import { createDecipheriv, createHash, pbkdf2Sync } from "node:crypto";

/**
 * Scan a PKCS#12 (PFX) file for the ASP.NET Core HTTPS dev cert custom-OID
 * extension `1.3.6.1.4.1.311.84.1.1` — works for cert bags that are
 *
 *   a) plaintext (`id-data` ContentInfo, rare),
 *   b) PBES2-encrypted (PBKDF2-SHA-{1,256,384,512} + AES-{128,192,256}-CBC)
 *      — what this extension's host emits, and what modern `dotnet
 *      dev-certs https --export-path` emits on .NET 9+,
 *   c) PBE-SHA1-3DES or PBE-SHA1-2DES encrypted (the historical
 *      `dotnet dev-certs https` / `Pkcs12Builder` default on .NET ≤8).
 *
 * The scan tries each layer with the supplied password (empty by default,
 * which matches every dev cert PFX we care about) and is fail-closed: any
 * parse, decrypt, or unsupported-algorithm error returns `false`, so we
 * never delete a file we couldn't positively identify.
 *
 * RC2-40 (OID 1.2.840.113549.1.12.1.6) is intentionally NOT supported —
 * Node's `crypto` doesn't expose RC2, and we'd rather report "not a dev
 * cert" for an ancient export than ship a hand-rolled cipher.
 */

export const ASPNET_HTTPS_OID_DER = Buffer.from([
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x54, 0x01, 0x01,
]);

const OID = {
  data: "1.2.840.113549.1.7.1",
  encryptedData: "1.2.840.113549.1.7.6",
  pbes2: "1.2.840.113549.1.5.13",
  pbkdf2: "1.2.840.113549.1.5.12",
  pbeSha1_3Des: "1.2.840.113549.1.12.1.3",
  pbeSha1_2Des: "1.2.840.113549.1.12.1.4",
  aes128Cbc: "2.16.840.1.101.3.4.1.2",
  aes192Cbc: "2.16.840.1.101.3.4.1.22",
  aes256Cbc: "2.16.840.1.101.3.4.1.42",
  hmacSha1: "1.2.840.113549.2.7",
  hmacSha256: "1.2.840.113549.2.9",
  hmacSha384: "1.2.840.113549.2.10",
  hmacSha512: "1.2.840.113549.2.11",
} as const;

const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
// Context [0] with constructed bit set — used for EXPLICIT tagged content
// like `[0] EXPLICIT OCTET STRING` (the AuthenticatedSafe wrapper) and the
// inner ContentInfo content.
const TAG_CONTEXT_0_EXPLICIT = 0xa0;
// Context [0] primitive — used for IMPLICIT OCTET STRING (encryptedContent
// in EncryptedContentInfo). DER always uses primitive form for OCTET STRING.
const TAG_CONTEXT_0_IMPLICIT_PRIMITIVE = 0x80;

// ---------------------------------------------------------------------------
// ASN.1 reading — minimal DER walker. Indefinite-length (`length = 0x80`)
// is BER-only and not supported; encountering it returns `null` and the
// caller treats the whole file as unidentifiable.
// ---------------------------------------------------------------------------

interface Tlv {
  tag: number;
  contentStart: number;
  contentLength: number;
  /** tag byte + length bytes + content. Use to advance past this TLV. */
  totalLength: number;
}

function readTlv(buf: Buffer, offset: number): Tlv | null {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset];
  const first = buf[offset + 1];
  let length: number;
  let lengthLen: number;
  if (first < 0x80) {
    length = first;
    lengthLen = 1;
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) return null;
    if (offset + 2 + numBytes > buf.length) return null;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length * 256 + buf[offset + 2 + i];
    }
    lengthLen = 1 + numBytes;
  }
  const contentStart = offset + 1 + lengthLen;
  if (contentStart + length > buf.length) return null;
  return { tag, contentStart, contentLength: length, totalLength: 1 + lengthLen + length };
}

function expectTag(buf: Buffer, offset: number, tag: number): Tlv | null {
  const t = readTlv(buf, offset);
  return t && t.tag === tag ? t : null;
}

function readIntegerSmall(buf: Buffer, offset: number): { value: number; totalLength: number } | null {
  const t = expectTag(buf, offset, TAG_INTEGER);
  if (!t || t.contentLength === 0 || t.contentLength > 6) return null;
  let v = 0;
  for (let i = 0; i < t.contentLength; i++) {
    v = v * 256 + buf[t.contentStart + i];
  }
  return { value: v, totalLength: t.totalLength };
}

function readOctetString(buf: Buffer, offset: number): { content: Buffer; totalLength: number } | null {
  const t = expectTag(buf, offset, TAG_OCTET_STRING);
  if (!t) return null;
  return {
    content: buf.subarray(t.contentStart, t.contentStart + t.contentLength),
    totalLength: t.totalLength,
  };
}

function readOid(buf: Buffer, offset: number): { oid: string; totalLength: number } | null {
  const t = expectTag(buf, offset, TAG_OID);
  if (!t || t.contentLength === 0) return null;
  return {
    oid: decodeOid(buf, t.contentStart, t.contentLength),
    totalLength: t.totalLength,
  };
}

function decodeOid(buf: Buffer, start: number, len: number): string {
  const first = buf[start];
  const arcs: string[] = [`${Math.floor(first / 40)}`, `${first % 40}`];
  let acc = 0;
  for (let i = 1; i < len; i++) {
    const b = buf[start + i];
    acc = (acc << 7) | (b & 0x7f);
    if (!(b & 0x80)) {
      arcs.push(`${acc}`);
      acc = 0;
    }
  }
  return arcs.join(".");
}

// ---------------------------------------------------------------------------
// PKCS#12 B.2 KDF (RFC 7292 §B.2) — the legacy KDF used by PBE-SHA1-*.
// Ported from the host extension's identical implementation in
// `src/vscode-ui-extension/src/cert/pfx.ts`, parameterized over SHA-1 vs
// SHA-256 so callers can derive keys for either PBE-SHA1-* or PKCS#12 MAC
// SHA-256 if we ever need that here.
// ---------------------------------------------------------------------------

function pkcs12B2Kdf(
  password: string,
  salt: Buffer,
  purpose: 1 | 2 | 3,
  iterations: number,
  outputLength: number,
  hashAlg: "sha1" | "sha256"
): Buffer {
  const u = hashAlg === "sha1" ? 20 : 32;
  const v = 64;

  const passwordBmp = bmpStringWithNullTerminator(password);
  const D = Buffer.alloc(v, purpose);
  const S = repeatToBlock(salt, v);
  const P = repeatToBlock(passwordBmp, v);
  const I = Buffer.concat([S, P]);

  const c = Math.ceil(outputLength / u);
  const A = Buffer.alloc(c * u);
  for (let i = 0; i < c; i++) {
    let Ai = createHash(hashAlg).update(D).update(I).digest();
    for (let j = 1; j < iterations; j++) {
      Ai = createHash(hashAlg).update(Ai).digest();
    }
    Ai.copy(A, i * u);

    if (i < c - 1) {
      const B = repeatToBlock(Ai, v);
      for (let off = 0; off < I.length; off += v) {
        let carry = 1;
        for (let pos = v - 1; pos >= 0; pos--) {
          const sum = I[off + pos] + B[pos] + carry;
          I[off + pos] = sum & 0xff;
          carry = sum >>> 8;
        }
      }
    }
  }
  return A.subarray(0, outputLength);
}

function bmpStringWithNullTerminator(s: string): Buffer {
  const buf = Buffer.alloc((s.length + 1) * 2);
  for (let i = 0; i < s.length; i++) {
    buf.writeUInt16BE(s.charCodeAt(i), i * 2);
  }
  return buf;
}

function repeatToBlock(src: Buffer, blockSize: number): Buffer {
  if (src.length === 0) return Buffer.alloc(0);
  const len = blockSize * Math.ceil(src.length / blockSize);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = src[i % src.length];
  return out;
}

// ---------------------------------------------------------------------------
// Decryptors — each takes the ciphertext and the params SEQUENCE bytes
// (starting at the SEQUENCE tag itself) and returns plaintext, or null on
// any failure.
// ---------------------------------------------------------------------------

function decryptPbes2(encrypted: Buffer, params: Buffer, password: string): Buffer | null {
  // PBES2-params SEQUENCE { keyDerivationFunc, encryptionScheme }
  const outer = expectTag(params, 0, TAG_SEQUENCE);
  if (!outer) return null;
  const end = outer.contentStart + outer.contentLength;

  // keyDerivationFunc AlgorithmIdentifier
  const kdf = expectTag(params, outer.contentStart, TAG_SEQUENCE);
  if (!kdf) return null;
  const kdfOid = readOid(params, kdf.contentStart);
  if (!kdfOid || kdfOid.oid !== OID.pbkdf2) return null;

  // PBKDF2-params SEQUENCE
  const pbkdf2Params = expectTag(params, kdf.contentStart + kdfOid.totalLength, TAG_SEQUENCE);
  if (!pbkdf2Params) return null;
  let pp = pbkdf2Params.contentStart;
  const ppEnd = pbkdf2Params.contentStart + pbkdf2Params.contentLength;

  const saltTlv = readOctetString(params, pp);
  if (!saltTlv) return null;
  pp += saltTlv.totalLength;

  const iterTlv = readIntegerSmall(params, pp);
  if (!iterTlv || iterTlv.value <= 0) return null;
  pp += iterTlv.totalLength;

  let explicitKeyLength = 0;
  let prf: "sha1" | "sha256" | "sha384" | "sha512" = "sha1";
  while (pp < ppEnd) {
    const peek = readTlv(params, pp);
    if (!peek) return null;
    if (peek.tag === TAG_INTEGER) {
      const kl = readIntegerSmall(params, pp);
      if (!kl) return null;
      explicitKeyLength = kl.value;
      pp += kl.totalLength;
    } else if (peek.tag === TAG_SEQUENCE) {
      const prfAlg = expectTag(params, pp, TAG_SEQUENCE);
      if (!prfAlg) return null;
      const prfOid = readOid(params, prfAlg.contentStart);
      if (prfOid) {
        if (prfOid.oid === OID.hmacSha256) prf = "sha256";
        else if (prfOid.oid === OID.hmacSha384) prf = "sha384";
        else if (prfOid.oid === OID.hmacSha512) prf = "sha512";
        else if (prfOid.oid === OID.hmacSha1) prf = "sha1";
        else return null;
      }
      pp += prfAlg.totalLength;
    } else {
      return null;
    }
  }

  // encryptionScheme AlgorithmIdentifier — sits immediately after kdf in
  // the PBES2-params SEQUENCE.
  const encStart = outer.contentStart + kdf.totalLength;
  if (encStart >= end) return null;
  const enc = expectTag(params, encStart, TAG_SEQUENCE);
  if (!enc) return null;
  const algOid = readOid(params, enc.contentStart);
  if (!algOid) return null;

  let cipher: "aes-128-cbc" | "aes-192-cbc" | "aes-256-cbc";
  let cipherKeyLen: number;
  switch (algOid.oid) {
    case OID.aes128Cbc: cipher = "aes-128-cbc"; cipherKeyLen = 16; break;
    case OID.aes192Cbc: cipher = "aes-192-cbc"; cipherKeyLen = 24; break;
    case OID.aes256Cbc: cipher = "aes-256-cbc"; cipherKeyLen = 32; break;
    default: return null;
  }

  const iv = readOctetString(params, enc.contentStart + algOid.totalLength);
  if (!iv || iv.content.length !== 16) return null;

  const keyLen = explicitKeyLength > 0 ? explicitKeyLength : cipherKeyLen;
  const key = pbkdf2Sync(Buffer.from(password, "utf-8"), saltTlv.content, iterTlv.value, keyLen, prf);

  try {
    const decipher = createDecipheriv(cipher, key, iv.content);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch {
    return null;
  }
}

function decryptPkcs12Pbe3Des(
  encrypted: Buffer,
  params: Buffer,
  password: string,
  keyBytes: 16 | 24
): Buffer | null {
  // pkcs-12PbeParams SEQUENCE { salt OCTET STRING, iterations INTEGER }
  const outer = expectTag(params, 0, TAG_SEQUENCE);
  if (!outer) return null;
  const saltTlv = readOctetString(params, outer.contentStart);
  if (!saltTlv) return null;
  const iterTlv = readIntegerSmall(params, outer.contentStart + saltTlv.totalLength);
  if (!iterTlv || iterTlv.value <= 0) return null;

  const rawKey = pkcs12B2Kdf(password, saltTlv.content, 1, iterTlv.value, keyBytes, "sha1");
  // 2-key 3DES: K = K1 || K2 || K1 (24 bytes total for des-ede3-cbc).
  const key = keyBytes === 16 ? Buffer.concat([rawKey, rawKey.subarray(0, 8)]) : rawKey;
  const iv = pkcs12B2Kdf(password, saltTlv.content, 2, iterTlv.value, 8, "sha1");

  try {
    const decipher = createDecipheriv("des-ede3-cbc", key, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// PKCS#12 walker
// ---------------------------------------------------------------------------

function decryptAuthSafeEntry(
  buf: Buffer,
  ciContentOffset: number,
  password: string
): Buffer | null {
  // ContentInfo content has already been unwrapped — `ciContentOffset` points
  // at an EncryptedData SEQUENCE.
  const ed = expectTag(buf, ciContentOffset, TAG_SEQUENCE);
  if (!ed) return null;
  const versionTlv = readIntegerSmall(buf, ed.contentStart);
  if (!versionTlv) return null;

  // EncryptedContentInfo SEQUENCE { contentType, contentEncryptionAlgorithm, [0] IMPLICIT OCTET STRING }
  const eci = expectTag(buf, ed.contentStart + versionTlv.totalLength, TAG_SEQUENCE);
  if (!eci) return null;
  const contentType = readOid(buf, eci.contentStart);
  if (!contentType) return null;
  const algSeq = expectTag(buf, eci.contentStart + contentType.totalLength, TAG_SEQUENCE);
  if (!algSeq) return null;
  const algOid = readOid(buf, algSeq.contentStart);
  if (!algOid) return null;
  const paramsStart = algSeq.contentStart + algOid.totalLength;
  const paramsLen = algSeq.contentStart + algSeq.contentLength - paramsStart;
  const paramsBuf = buf.subarray(paramsStart, paramsStart + paramsLen);

  const encStart = eci.contentStart + contentType.totalLength + algSeq.totalLength;
  if (encStart >= eci.contentStart + eci.contentLength) return null;
  // The encryptedContent is `[0] IMPLICIT OCTET STRING` — primitive in DER.
  const encTlv = readTlv(buf, encStart);
  if (!encTlv) return null;
  if (encTlv.tag !== TAG_CONTEXT_0_IMPLICIT_PRIMITIVE) return null;
  const encrypted = buf.subarray(encTlv.contentStart, encTlv.contentStart + encTlv.contentLength);

  switch (algOid.oid) {
    case OID.pbes2:
      return decryptPbes2(encrypted, paramsBuf, password);
    case OID.pbeSha1_3Des:
      return decryptPkcs12Pbe3Des(encrypted, paramsBuf, password, 24);
    case OID.pbeSha1_2Des:
      return decryptPkcs12Pbe3Des(encrypted, paramsBuf, password, 16);
    default:
      return null;
  }
}

/**
 * Walk the PKCS#12 structure, decrypt every cert-bag-capable SafeContents
 * with `password`, and return true if any plaintext contains the ASP.NET
 * dev cert OID. Fail-closed on every error.
 */
export function scanPfxForDevCertOid(pfxBytes: Buffer, password = ""): boolean {
  // Fast path — handles plaintext-cert-bag PFXes (rare but possible) and
  // also any future producer that elides cert-bag encryption.
  if (pfxBytes.includes(ASPNET_HTTPS_OID_DER)) return true;

  try {
    // PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData OPTIONAL }
    const pfx = expectTag(pfxBytes, 0, TAG_SEQUENCE);
    if (!pfx) return false;
    const version = readIntegerSmall(pfxBytes, pfx.contentStart);
    if (!version || version.value !== 3) return false;

    // authSafe ContentInfo
    const ci = expectTag(pfxBytes, pfx.contentStart + version.totalLength, TAG_SEQUENCE);
    if (!ci) return false;
    const ciType = readOid(pfxBytes, ci.contentStart);
    if (!ciType || ciType.oid !== OID.data) return false;
    const ciCtx = expectTag(pfxBytes, ci.contentStart + ciType.totalLength, TAG_CONTEXT_0_EXPLICIT);
    if (!ciCtx) return false;
    const authSafeOctet = readOctetString(pfxBytes, ciCtx.contentStart);
    if (!authSafeOctet) return false;

    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    const authSafeBuf = authSafeOctet.content;
    const authSafeSeq = expectTag(authSafeBuf, 0, TAG_SEQUENCE);
    if (!authSafeSeq) return false;

    let p = authSafeSeq.contentStart;
    const end = authSafeSeq.contentStart + authSafeSeq.contentLength;
    while (p < end) {
      const entry = expectTag(authSafeBuf, p, TAG_SEQUENCE);
      if (!entry) return false;
      const entryType = readOid(authSafeBuf, entry.contentStart);
      if (!entryType) return false;
      const ctx = expectTag(authSafeBuf, entry.contentStart + entryType.totalLength, TAG_CONTEXT_0_EXPLICIT);
      if (!ctx) return false;

      let plaintext: Buffer | null = null;
      if (entryType.oid === OID.data) {
        // SafeContents wrapped in an OCTET STRING.
        const octet = readOctetString(authSafeBuf, ctx.contentStart);
        if (octet) plaintext = octet.content;
      } else if (entryType.oid === OID.encryptedData) {
        plaintext = decryptAuthSafeEntry(authSafeBuf, ctx.contentStart, password);
      }
      // Unknown ContentInfo types are ignored — keep scanning subsequent
      // entries rather than bailing out, so an unrecognised key-bag wrapper
      // never blocks identification of a recognised cert bag.

      if (plaintext && plaintext.includes(ASPNET_HTTPS_OID_DER)) return true;

      p += entry.totalLength;
    }
  } catch {
    // Fail closed.
  }

  return false;
}
