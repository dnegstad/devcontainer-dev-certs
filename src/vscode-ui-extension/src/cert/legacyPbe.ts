/**
 * Read-only legacy-PBE shim for round-tripping PKCS#12 PFXes that older
 * tooling (pre-OpenSSL 3.0 defaults, `openssl pkcs12 -legacy`) wrote with
 * the RFC 7292 PBE-with-SHA-and-RC2 algorithms.
 *
 * Scope is intentionally narrow — we deliberately do NOT support the
 * `pbeWithSHAAnd{2,3}-KeyTripleDES-CBC` variants. Most legacy PFXes that
 * carry a private key encrypt the key bag with 3DES, so in practice this
 * shim covers cert-bag decryption only (CA-only PFX migration). PFXes
 * with 3DES-encrypted key bags raise a clear error so the user can
 * re-export with a modern cipher.
 *
 *   - 128-bit RC2-CBC           (1.2.840.113549.1.12.1.5)
 *   - 40-bit RC2-CBC            (1.2.840.113549.1.12.1.6)
 *
 * RC2 isn't compiled into OpenSSL 3.x by default, so we ship a pure-JS
 * implementation per RFC 2268. We only ever decrypt — these algorithms
 * are never used by `buildPfx`.
 */

import { createHash } from "node:crypto";

export const LEGACY_PBE_OID_SHA_128_RC2 = "1.2.840.113549.1.12.1.5";
export const LEGACY_PBE_OID_SHA_40_RC2 = "1.2.840.113549.1.12.1.6";

const LEGACY_OIDS = new Set<string>([
  LEGACY_PBE_OID_SHA_128_RC2,
  LEGACY_PBE_OID_SHA_40_RC2,
]);

export function isLegacyPbeOid(oid: string): boolean {
  return LEGACY_OIDS.has(oid);
}

export interface LegacyPbeKdfParams {
  /** Salt bytes from the AlgorithmIdentifier parameters. */
  salt: Buffer;
  /** Iteration count from the AlgorithmIdentifier parameters. */
  iterations: number;
  /** Password as a JS string; we re-encode as BMPString for the KDF. */
  password: string;
}

/**
 * Decrypt the body of an EncryptedData (or EncryptedPrivateKeyInfo)
 * encrypted under one of the supported legacy PBE algorithms. Returns the
 * cleartext (PKCS#7-padded plaintext stripped of its padding).
 */
export function decryptLegacyPbe(
  oid: string,
  params: LegacyPbeKdfParams,
  ciphertext: Buffer
): Buffer {
  const config = pickConfig(oid);
  const key = pkcs12B2Kdf(params, config.keyBytes, /* purpose */ 1);
  const iv = pkcs12B2Kdf(params, 8, /* purpose */ 2);
  const raw = rc2CbcDecrypt(key, iv, ciphertext, config.effectiveKeyBits);
  return stripPkcs7(raw, /* blockSize */ 8);
}

interface CipherConfig {
  keyBytes: number;
  effectiveKeyBits: number;
}

function pickConfig(oid: string): CipherConfig {
  switch (oid) {
    case LEGACY_PBE_OID_SHA_128_RC2:
      return { keyBytes: 16, effectiveKeyBits: 128 };
    case LEGACY_PBE_OID_SHA_40_RC2:
      return { keyBytes: 5, effectiveKeyBits: 40 };
    default:
      throw new Error(`Not a supported legacy PBE OID: ${oid}`);
  }
}

function stripPkcs7(buf: Buffer, blockSize: number): Buffer {
  if (buf.length === 0 || buf.length % blockSize !== 0) {
    throw new Error("Legacy-PBE plaintext has invalid length.");
  }
  const pad = buf[buf.length - 1];
  if (pad === 0 || pad > blockSize) {
    throw new Error("Legacy-PBE plaintext has invalid PKCS#7 padding.");
  }
  for (let i = buf.length - pad; i < buf.length; i++) {
    if (buf[i] !== pad) {
      throw new Error("Legacy-PBE plaintext has invalid PKCS#7 padding.");
    }
  }
  return buf.subarray(0, buf.length - pad);
}

// ---------------------------------------------------------------------------
// PKCS#12 Appendix B.2 KDF (RFC 7292 §B.2). Produces a string of `outputBytes`
// bytes from (password BMPString, salt, iterationCount, purpose byte).
// purpose: 1 = encryption key, 2 = IV, 3 = MAC key.
// SHA-1 is hard-coded because every PKCS#12 PBE-with-SHA-* algorithm uses it.
// ---------------------------------------------------------------------------

function pkcs12B2Kdf(
  { salt, iterations, password }: LegacyPbeKdfParams,
  outputBytes: number,
  purpose: 1 | 2 | 3
): Buffer {
  const u = 20; // SHA-1 output size
  const v = 64; // SHA-1 block size
  const passwordBmp = encodePasswordBmpString(password);

  const D = Buffer.alloc(v, purpose);
  const S = repeatToMultipleOf(salt, v);
  const P = repeatToMultipleOf(passwordBmp, v);
  let I: Buffer = Buffer.concat([S, P]);

  const c = Math.ceil(outputBytes / u);
  const out = Buffer.alloc(c * u);

  for (let i = 0; i < c; i++) {
    let A = sha1(Buffer.concat([D, I]));
    for (let j = 1; j < iterations; j++) {
      A = sha1(A);
    }
    A.copy(out, i * u);

    if (i + 1 < c) {
      // I_j := (I_j + B + 1) mod 2^v, where B is A repeated to fill v bytes.
      const B = repeatToFill(A, v);
      I = addToBlocks(I, B, v);
    }
  }

  return out.subarray(0, outputBytes);
}

function encodePasswordBmpString(password: string): Buffer {
  // BMPString = UTF-16BE, then a trailing 0x0000 terminator.
  const buf = Buffer.alloc((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++) {
    buf.writeUInt16BE(password.charCodeAt(i), i * 2);
  }
  // Last 2 bytes are already zero from Buffer.alloc.
  return buf;
}

function repeatToMultipleOf(src: Buffer, blockSize: number): Buffer {
  if (src.length === 0) return Buffer.alloc(0);
  const len = blockSize * Math.ceil(src.length / blockSize);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = src[i % src.length];
  return out;
}

function repeatToFill(src: Buffer, length: number): Buffer {
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i++) out[i] = src[i % src.length];
  return out;
}

function sha1(input: Buffer): Buffer {
  return createHash("sha1").update(input).digest();
}

/**
 * Compute (chunk + B + 1) mod 2^(8*v) for each `v`-byte chunk of `I`,
 * with the carry chain running from the LSB (last byte) up through MSB.
 * This matches RFC 7292 §B.2 step 6c.
 */
function addToBlocks(I: Buffer, B: Buffer, v: number): Buffer {
  const out = Buffer.alloc(I.length);
  I.copy(out);
  for (let off = 0; off < out.length; off += v) {
    let carry = 1;
    for (let i = v - 1; i >= 0; i--) {
      const sum = out[off + i] + B[i] + carry;
      out[off + i] = sum & 0xff;
      carry = sum >> 8;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// RC2 (RFC 2268). We only need decryption in CBC mode, so the helper does
// the key schedule once, then runs reverse rounds for every ciphertext block.
// Roughly 100 LOC of cipher + 80 LOC of constants; only invoked on
// PFXes encrypted with `pbeWithSHAAndN-BitRC2-CBC`.
// ---------------------------------------------------------------------------

const RC2_PITABLE: readonly number[] = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

function rc2KeySchedule(key: Buffer, effectiveKeyBits: number): Uint16Array {
  // L holds the 128-byte expanded key as bytes, then we reinterpret as 64
  // little-endian 16-bit words for the rounds.
  const L = new Uint8Array(128);
  L.set(key, 0);

  const T = key.length;
  const T1 = effectiveKeyBits;
  const T8 = Math.floor((T1 + 7) / 8);
  const TM = 0xff >>> ((-T1) & 0x07) >>> 0;

  for (let i = T; i < 128; i++) {
    L[i] = RC2_PITABLE[(L[i - 1] + L[i - T]) & 0xff];
  }

  L[128 - T8] = RC2_PITABLE[L[128 - T8] & TM];
  for (let i = 127 - T8; i >= 0; i--) {
    L[i] = RC2_PITABLE[L[i + 1] ^ L[i + T8]];
  }

  const K = new Uint16Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = L[2 * i] | (L[2 * i + 1] << 8);
  }
  return K;
}

function rc2DecryptBlock(K: Uint16Array, block: Buffer, offset: number): void {
  // Read 4 little-endian 16-bit words.
  let R0 = block[offset] | (block[offset + 1] << 8);
  let R1 = block[offset + 2] | (block[offset + 3] << 8);
  let R2 = block[offset + 4] | (block[offset + 5] << 8);
  let R3 = block[offset + 6] | (block[offset + 7] << 8);

  // Decryption is the reverse of the encryption schedule:
  //   5 r-mix (j = 60,56,52,48,44), 1 r-mash, 6 r-mix (40..20), 1 r-mash,
  //   5 r-mix (16..0).
  for (let j = 60; j >= 44; j -= 4) {
    [R0, R1, R2, R3] = revMix(R0, R1, R2, R3, K, j);
  }
  [R0, R1, R2, R3] = revMash(R0, R1, R2, R3, K);
  for (let j = 40; j >= 20; j -= 4) {
    [R0, R1, R2, R3] = revMix(R0, R1, R2, R3, K, j);
  }
  [R0, R1, R2, R3] = revMash(R0, R1, R2, R3, K);
  for (let j = 16; j >= 0; j -= 4) {
    [R0, R1, R2, R3] = revMix(R0, R1, R2, R3, K, j);
  }

  block[offset + 0] = R0 & 0xff;
  block[offset + 1] = (R0 >>> 8) & 0xff;
  block[offset + 2] = R1 & 0xff;
  block[offset + 3] = (R1 >>> 8) & 0xff;
  block[offset + 4] = R2 & 0xff;
  block[offset + 5] = (R2 >>> 8) & 0xff;
  block[offset + 6] = R3 & 0xff;
  block[offset + 7] = (R3 >>> 8) & 0xff;
}

function revMix(
  R0: number,
  R1: number,
  R2: number,
  R3: number,
  K: Uint16Array,
  j: number
): [number, number, number, number] {
  R3 = ror16(R3, 5);
  R3 = (R3 - K[j + 3] - (R2 & R1) - (~R2 & R0)) & 0xffff;
  R2 = ror16(R2, 3);
  R2 = (R2 - K[j + 2] - (R1 & R0) - (~R1 & R3)) & 0xffff;
  R1 = ror16(R1, 2);
  R1 = (R1 - K[j + 1] - (R0 & R3) - (~R0 & R2)) & 0xffff;
  R0 = ror16(R0, 1);
  R0 = (R0 - K[j] - (R3 & R2) - (~R3 & R1)) & 0xffff;
  return [R0, R1, R2, R3];
}

function revMash(
  R0: number,
  R1: number,
  R2: number,
  R3: number,
  K: Uint16Array
): [number, number, number, number] {
  R3 = (R3 - K[R2 & 0x3f]) & 0xffff;
  R2 = (R2 - K[R1 & 0x3f]) & 0xffff;
  R1 = (R1 - K[R0 & 0x3f]) & 0xffff;
  R0 = (R0 - K[R3 & 0x3f]) & 0xffff;
  return [R0, R1, R2, R3];
}

function ror16(x: number, n: number): number {
  return ((x >>> n) | (x << (16 - n))) & 0xffff;
}

function rc2CbcDecrypt(
  key: Buffer,
  iv: Buffer,
  ciphertext: Buffer,
  effectiveKeyBits: number
): Buffer {
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new Error("RC2 ciphertext length must be a non-zero multiple of 8.");
  }
  const K = rc2KeySchedule(key, effectiveKeyBits);
  const out = Buffer.alloc(ciphertext.length);

  let prev = iv;
  for (let off = 0; off < ciphertext.length; off += 8) {
    const block = Buffer.from(ciphertext.subarray(off, off + 8));
    rc2DecryptBlock(K, block, 0);
    for (let i = 0; i < 8; i++) {
      out[off + i] = block[i] ^ prev[i];
    }
    prev = ciphertext.subarray(off, off + 8);
  }
  return out;
}
