/**
 * PKCS#12 / PFX writer + reader.
 *
 * The writer emits DER directly using small TLV helpers + Node crypto for
 * AES/HMAC/PBKDF2/B.2-KDF. We previously used pkijs, but it has multiple
 * incompatibilities with Windows CryptoAPI's PFXImportCertStore — it emits
 * indefinite-length BER inside encrypted content, hardcodes a 64-byte MAC
 * salt, and offers no public toggles for either. Hand-rolling the writer
 * lets us match what `dotnet dev-certs` produces (modern PBES2/AES-256-CBC
 * + HMAC-SHA-256 with parameters CryptoAPI accepts) without depending on
 * pkijs's undocumented encoding choices.
 *
 * The reader stays on pkijs since parsing PBES2/AES PFXes works fine — only
 * the writer had to change to satisfy CryptoAPI.
 */

import type * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
  createCipheriv,
  createHash,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  webcrypto,
} from "node:crypto";
import { DevCert } from "./types";
import { DevKey } from "./types";

let engineConfigured = false;
function ensureEngine(): void {
  if (engineConfigured) return;
  const engine = new pkijs.CryptoEngine({
    name: "node-webcrypto",
    crypto: webcrypto as unknown as Crypto,
  });
  pkijs.setEngine(
    engine.name,
    engine as unknown as Parameters<typeof pkijs.setEngine>[1]
  );
  engineConfigured = true;
}

const OID_CONTENT_DATA = "1.2.840.113549.1.7.1";
const OID_CONTENT_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";
const OID_BAG_PKCS8_SHROUDED = "1.2.840.113549.1.12.10.1.2";
const OID_BAG_CERT = "1.2.840.113549.1.12.10.1.3";
const OID_X509 = "1.2.840.113549.1.9.22.1";
const OID_FRIENDLY_NAME = "1.2.840.113549.1.9.20";
const OID_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";
const OID_PBES2 = "1.2.840.113549.1.5.13";
const OID_PBKDF2 = "1.2.840.113549.1.5.12";
const OID_AES_256_CBC = "2.16.840.1.101.3.4.1.42";
const OID_HMAC_SHA256 = "1.2.840.113549.2.9";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

// Parameters chosen so the resulting PFX round-trips through Windows
// CryptoAPI's PFXImportCertStore. Empirically verified against what
// `Export-PfxCertificate -CryptoAlgorithmOption AES256_SHA256` emits.
const PBKDF2_ITERATIONS = 2048;
const MAC_SALT_LENGTH = 20; // CryptoAPI rejects 64-byte MAC salts.
const PBES2_SALT_LENGTH = 16;
const AES_KEY_LENGTH = 32; // AES-256
const AES_IV_LENGTH = 16;

/**
 * Well-known PKCS#12 PBE-with-SHA OIDs that we deliberately don't accept on
 * the read path. Used purely to render an actionable error message — the
 * actual rejection is "anything that isn't PBES2".
 */
const REJECTED_LEGACY_PBE_NAMES: Record<string, string> = {
  "1.2.840.113549.1.12.1.1": "pbeWithSHAAnd128BitRC4",
  "1.2.840.113549.1.12.1.2": "pbeWithSHAAnd40BitRC4",
  "1.2.840.113549.1.12.1.3": "pbeWithSHAAnd3-KeyTripleDES-CBC",
  "1.2.840.113549.1.12.1.4": "pbeWithSHAAnd2-KeyTripleDES-CBC",
  "1.2.840.113549.1.12.1.5": "pbeWithSHAAnd128BitRC2-CBC",
  "1.2.840.113549.1.12.1.6": "pbeWithSHAAnd40BitRC2-CBC",
};

function unsupportedAlgorithmError(what: string, oid: string): Error {
  const legacyName = REJECTED_LEGACY_PBE_NAMES[oid];
  if (legacyName) {
    return new Error(
      `PFX ${what} is encrypted with the legacy PKCS#12 algorithm ` +
        `${legacyName} (OID ${oid}), which is not supported. Re-export ` +
        `the PFX with the modern PBES2/AES default — i.e. ` +
        `\`openssl pkcs12 -in legacy.pfx -nodes\` piped into ` +
        `\`openssl pkcs12 -export -out modern.pfx\` (without \`-legacy\`).`
    );
  }
  return new Error(
    `PFX ${what} uses an unsupported encryption algorithm: ${oid} ` +
      `(only PBES2/AES-CBC is accepted).`
  );
}

export interface BuildPfxOptions {
  cert: DevCert;
  key?: DevKey | null;
  password?: string;
  /** Optional human-readable label written into the cert / key SafeBags. */
  friendlyName?: string;
}

/**
 * Build a DER-encoded PFX containing one certificate and (optionally) its
 * matching private key. Encryption uses PBES2/AES-256-CBC + PBKDF2-SHA-256;
 * outer integrity uses HMAC-SHA-256 with the PKCS#12 B.2 KDF.
 */
// Kept `async` purely so existing `await buildPfx(...)` callers stay
// type-correct after dropping the pkijs-based async path; the body itself
// is fully synchronous now.
// eslint-disable-next-line @typescript-eslint/require-await
export async function buildPfx(opts: BuildPfxOptions): Promise<Buffer> {
  const password = opts.password ?? "";
  // Cert ↔ key linkage attribute. dotnet dev-certs and Windows both use the
  // SHA-1 thumbprint here; matching that lets .NET pair the two bags.
  const localKeyId = Buffer.from(opts.cert.thumbprintSha1, "hex");

  const certSafeContents = encodeSequence([
    encodeCertSafeBag(opts.cert, opts.friendlyName, localKeyId),
  ]);
  const encryptedCertCi = encryptSafeContentsPbes2(certSafeContents, password);

  let keyCi: Buffer | null = null;
  if (opts.key) {
    const shroudedKey = encryptPkcs8ShroudedKeyBag(opts.key, password);
    const keySafeBag = encodeKeySafeBag(
      shroudedKey,
      opts.friendlyName,
      localKeyId
    );
    const keySafeContents = encodeSequence([keySafeBag]);
    keyCi = encodeDataContentInfo(keySafeContents);
  }

  // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
  const authSafe = encodeSequence(
    keyCi ? [encryptedCertCi, keyCi] : [encryptedCertCi]
  );

  const outerCi = encodeDataContentInfo(authSafe);

  const macSalt = randomBytes(MAC_SALT_LENGTH);
  // Purpose 3 = MAC-key derivation per RFC 7292 §B.3.
  const macKey = pkcs12B2Kdf(password, macSalt, 3, PBKDF2_ITERATIONS, 32);
  const mac = createHmac("sha256", macKey).update(authSafe).digest();
  const macData = encodeMacData(mac, macSalt, PBKDF2_ITERATIONS);

  return encodeSequence([encodeInteger(3), outerCi, macData]);
}

// ---------------------------------------------------------------------------
// TLV helpers — minimal DER emission. Every constructed value is built from
// children that already carry their own definite-length headers, so the
// output is DER by construction.
// ---------------------------------------------------------------------------

function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = n >>> 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, contents: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([tag]),
    encodeLength(contents.length),
    contents,
  ]);
}

function encodeSequence(children: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(children));
}

function encodeSet(children: Buffer[]): Buffer {
  return tlv(0x31, Buffer.concat(children));
}

function encodeOctetString(buf: Buffer): Buffer {
  return tlv(0x04, buf);
}

function encodeInteger(n: number): Buffer {
  if (n < 0) throw new Error("negative integers not supported");
  if (n === 0) return Buffer.from([0x02, 0x01, 0x00]);
  const bytes: number[] = [];
  let val = n;
  while (val > 0) {
    bytes.unshift(val & 0xff);
    val = Math.floor(val / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0); // ensure positive (unsigned-leading-zero)
  return tlv(0x02, Buffer.from(bytes));
}

function encodeNull(): Buffer {
  return Buffer.from([0x05, 0x00]);
}

function encodeOID(oid: string): Buffer {
  const parts = oid.split(".").map((p) => Number(p));
  const out: number[] = [];
  out.push(parts[0] * 40 + parts[1]);
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack: number[] = [];
    do {
      stack.unshift(v & 0x7f);
      v = v >>> 7;
    } while (v > 0);
    for (let j = 0; j < stack.length; j++) {
      out.push(stack[j] | (j < stack.length - 1 ? 0x80 : 0));
    }
  }
  return tlv(0x06, Buffer.from(out));
}

function encodeBmpString(s: string): Buffer {
  // BMPString = UTF-16BE; PKCS#12 attribute friendlyName uses this.
  const buf = Buffer.alloc(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    buf.writeUInt16BE(s.charCodeAt(i), i * 2);
  }
  return tlv(0x1e, buf);
}

function encodeContextTagged(
  tagNumber: number,
  body: Buffer,
  constructed: boolean
): Buffer {
  // Class 2 (context-specific). Set/clear bit 5 for constructed/primitive.
  const tag = (constructed ? 0xa0 : 0x80) | (tagNumber & 0x1f);
  return tlv(tag, body);
}

// ---------------------------------------------------------------------------
// PKCS#12 structural emission
// ---------------------------------------------------------------------------

function encodeAlgorithmIdentifier(oid: string, params: Buffer | null): Buffer {
  return encodeSequence(params ? [encodeOID(oid), params] : [encodeOID(oid)]);
}

function encodeCertSafeBag(
  cert: DevCert,
  friendlyName: string | undefined,
  localKeyId: Buffer
): Buffer {
  // SafeBag {
  //   bagId        OID id-certBag,
  //   bagValue     [0] EXPLICIT CertBag {
  //     certId    OID x509Certificate,
  //     certValue [0] EXPLICIT OCTET STRING (cert DER),
  //   },
  //   bagAttributes SET OF Attribute,
  // }
  const certBag = encodeSequence([
    encodeOID(OID_X509),
    encodeContextTagged(0, encodeOctetString(cert.der), true),
  ]);
  return encodeSequence([
    encodeOID(OID_BAG_CERT),
    encodeContextTagged(0, certBag, true),
    encodeBagAttributes(friendlyName, localKeyId),
  ]);
}

function encodeKeySafeBag(
  shroudedKey: Buffer,
  friendlyName: string | undefined,
  localKeyId: Buffer
): Buffer {
  return encodeSequence([
    encodeOID(OID_BAG_PKCS8_SHROUDED),
    encodeContextTagged(0, shroudedKey, true),
    encodeBagAttributes(friendlyName, localKeyId),
  ]);
}

function encodeBagAttributes(
  friendlyName: string | undefined,
  localKeyId: Buffer
): Buffer {
  // friendlyName OID (...01.09.14) sorts before localKeyId (...01.09.15) in
  // DER, so emit friendlyName first when present — matching strict SET OF
  // ordering rules.
  const attrs: Buffer[] = [];
  if (friendlyName !== undefined) {
    attrs.push(
      encodeSequence([
        encodeOID(OID_FRIENDLY_NAME),
        encodeSet([encodeBmpString(friendlyName)]),
      ])
    );
  }
  attrs.push(
    encodeSequence([
      encodeOID(OID_LOCAL_KEY_ID),
      encodeSet([encodeOctetString(localKeyId)]),
    ])
  );
  return encodeSet(attrs);
}

function encodeDataContentInfo(content: Buffer): Buffer {
  // ContentInfo {
  //   contentType OID id-data,
  //   content     [0] EXPLICIT OCTET STRING,
  // }
  return encodeSequence([
    encodeOID(OID_CONTENT_DATA),
    encodeContextTagged(0, encodeOctetString(content), true),
  ]);
}

function encryptSafeContentsPbes2(plaintext: Buffer, password: string): Buffer {
  const salt = randomBytes(PBES2_SALT_LENGTH);
  const iv = randomBytes(AES_IV_LENGTH);
  const key = pbkdf2Sync(
    Buffer.from(password, "utf-8"),
    salt,
    PBKDF2_ITERATIONS,
    AES_KEY_LENGTH,
    "sha256"
  );
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  // EncryptedContentInfo {
  //   contentType                ContentType,
  //   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
  //   encryptedContent           [0] IMPLICIT OCTET STRING OPTIONAL,
  // }
  // The IMPLICIT [0] is primitive (not constructed) — bit 5 of the tag byte
  // stays 0; just the value bytes follow.
  const encryptedContentInfo = encodeSequence([
    encodeOID(OID_CONTENT_DATA),
    encodePbes2AlgorithmId(salt, iv),
    encodeContextTagged(0, encrypted, false),
  ]);

  // EncryptedData ::= SEQUENCE { version INTEGER, encryptedContentInfo ... }
  const encryptedData = encodeSequence([
    encodeInteger(0),
    encryptedContentInfo,
  ]);

  // ContentInfo wrapping EncryptedData
  return encodeSequence([
    encodeOID(OID_CONTENT_ENCRYPTED_DATA),
    encodeContextTagged(0, encryptedData, true),
  ]);
}

function encryptPkcs8ShroudedKeyBag(key: DevKey, password: string): Buffer {
  // EncryptedPrivateKeyInfo ::= SEQUENCE {
  //   encryptionAlgorithm AlgorithmIdentifier,
  //   encryptedData       OCTET STRING,
  // }
  const salt = randomBytes(PBES2_SALT_LENGTH);
  const iv = randomBytes(AES_IV_LENGTH);
  const aesKey = pbkdf2Sync(
    Buffer.from(password, "utf-8"),
    salt,
    PBKDF2_ITERATIONS,
    AES_KEY_LENGTH,
    "sha256"
  );
  const cipher = createCipheriv("aes-256-cbc", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(key.der), cipher.final()]);

  return encodeSequence([
    encodePbes2AlgorithmId(salt, iv),
    encodeOctetString(encrypted),
  ]);
}

function encodePbes2AlgorithmId(salt: Buffer, iv: Buffer): Buffer {
  // PBES2-params ::= SEQUENCE {
  //   keyDerivationFunc AlgorithmIdentifier (PBKDF2),
  //   encryptionScheme  AlgorithmIdentifier (AES-256-CBC, params=IV),
  // }
  // PBKDF2-params ::= SEQUENCE {
  //   salt           OCTET STRING,
  //   iterationCount INTEGER,
  //   prf            AlgorithmIdentifier DEFAULT hmacWithSHA1,
  // }
  const pbkdf2Params = encodeSequence([
    encodeOctetString(salt),
    encodeInteger(PBKDF2_ITERATIONS),
    encodeAlgorithmIdentifier(OID_HMAC_SHA256, encodeNull()),
  ]);
  const pbkdf2Algo = encodeAlgorithmIdentifier(OID_PBKDF2, pbkdf2Params);
  const aesAlgo = encodeAlgorithmIdentifier(
    OID_AES_256_CBC,
    encodeOctetString(iv)
  );
  const pbes2Params = encodeSequence([pbkdf2Algo, aesAlgo]);
  return encodeAlgorithmIdentifier(OID_PBES2, pbes2Params);
}

function encodeMacData(mac: Buffer, salt: Buffer, iterations: number): Buffer {
  // MacData ::= SEQUENCE {
  //   mac        DigestInfo,
  //   macSalt    OCTET STRING,
  //   iterations INTEGER DEFAULT 1,
  // }
  const digestInfo = encodeSequence([
    encodeAlgorithmIdentifier(OID_SHA256, encodeNull()),
    encodeOctetString(mac),
  ]);
  return encodeSequence([
    digestInfo,
    encodeOctetString(salt),
    encodeInteger(iterations),
  ]);
}

// ---------------------------------------------------------------------------
// PKCS#12 B.2 KDF (RFC 7292 §B.2). Used here only to derive the outer-MAC
// key. PBKDF2-SHA-256 covers all the PBES2 paths above.
// ---------------------------------------------------------------------------

function pkcs12B2Kdf(
  password: string,
  salt: Buffer,
  purpose: 1 | 2 | 3,
  iterations: number,
  outputLength: number
): Buffer {
  const u = 32; // SHA-256 digest length
  const v = 64; // SHA-256 block size

  const passwordBmp = bmpStringWithNullTerminator(password);
  const D = Buffer.alloc(v, purpose);
  const S = repeatToBlock(salt, v);
  const P = repeatToBlock(passwordBmp, v);
  const I = Buffer.concat([S, P]);

  const c = Math.ceil(outputLength / u);
  const A = Buffer.alloc(c * u);
  for (let i = 0; i < c; i++) {
    let A_i = createHash("sha256").update(D).update(I).digest();
    for (let j = 1; j < iterations; j++) {
      A_i = createHash("sha256").update(A_i).digest();
    }
    A_i.copy(A, i * u);

    if (i < c - 1) {
      const B = repeatToBlock(A_i, v);
      // Each v-byte block of I gets I_j := (I_j + B + 1) mod 2^(8*v).
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
  // Per RFC 7292 §B.1: a supplied password (even the empty string) is
  // encoded as UTF-16BE with a 2-byte null terminator. Returning Buffer(0)
  // here would diverge from every other PKCS#12 implementation when the
  // password is the empty string — the MAC wouldn't verify on read-back.
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
// Read path — pkijs handles parsing PBES2/AES PFXes correctly. Only the write
// path needed to be lifted out of pkijs.
// ---------------------------------------------------------------------------

export interface ParsedPfx {
  cert: DevCert;
  key: DevKey | null;
}

/**
 * Parse a PFX, returning the first certificate bag and (when present)
 * its matching private key.
 */
export async function parsePfx(
  pfxBytes: Buffer | Uint8Array,
  password?: string
): Promise<ParsedPfx> {
  ensureEngine();
  const passwordBuf = passwordToArrayBuffer(password ?? "");
  const ab = bufferToArrayBuffer(pfxBytes);
  const pfx = pkijs.PFX.fromBER(ab);

  // Outer integrity check uses the PKCS#12 B.2 KDF, which pkijs supports
  // for both modern (SHA-2) and legacy (SHA-1) MACs, so this part works
  // regardless of how the inner SafeContents were encrypted.
  await pfx.parseInternalValues({ password: passwordBuf, checkIntegrity: true });

  const authSafe = pfx.parsedValue?.authenticatedSafe;
  if (!authSafe) throw new Error("PFX has no authenticated safe");

  // Walk the inner ContentInfos ourselves rather than calling pkijs's
  // `authSafe.parseInternalValues`, so that an unrecognized algorithm
  // produces a diagnostic that names the offending OID instead of the
  // generic "Unknown contentEncryptionAlgorithm" pkijs raises.
  const safeContentsList: pkijs.SafeContents[] = [];
  for (const contentInfo of authSafe.safeContents) {
    safeContentsList.push(await decryptSafeContents(contentInfo, passwordBuf));
  }

  let cert: DevCert | null = null;
  let key: DevKey | null = null;
  for (const safeContents of safeContentsList) {
    for (const bag of safeContents.safeBags) {
      if (bag.bagId === OID_BAG_CERT) {
        const certBag = bag.bagValue as pkijs.CertBag;
        const certParsed = certBag.parsedValue as pkijs.Certificate;
        const der = certParsed.toSchema(true).toBER(false);
        cert ??= new DevCert(Buffer.from(der));
      } else if (bag.bagId === OID_BAG_PKCS8_SHROUDED) {
        key ??= await decryptShroudedKeyBag(
          bag.bagValue as pkijs.PKCS8ShroudedKeyBag,
          passwordBuf
        );
      }
    }
  }

  if (!cert) {
    throw new Error("PFX contains no certificate.");
  }

  return { cert, key };
}

async function decryptSafeContents(
  contentInfo: pkijs.ContentInfo,
  passwordBuf: ArrayBuffer
): Promise<pkijs.SafeContents> {
  if (contentInfo.contentType === OID_CONTENT_DATA) {
    const octet = contentInfo.content as asn1js.OctetString;
    return pkijs.SafeContents.fromBER(octet.getValue());
  }

  if (contentInfo.contentType === OID_CONTENT_ENCRYPTED_DATA) {
    const encryptedData = new pkijs.EncryptedData({
      schema: contentInfo.content,
    });
    const algoOid =
      encryptedData.encryptedContentInfo.contentEncryptionAlgorithm
        .algorithmId;
    if (algoOid !== OID_PBES2) {
      throw unsupportedAlgorithmError("cert bag", algoOid);
    }
    const decrypted = await encryptedData.decrypt({ password: passwordBuf });
    return pkijs.SafeContents.fromBER(decrypted);
  }

  throw new Error(
    `PFX contains an unsupported AuthenticatedSafe content type: ${contentInfo.contentType}`
  );
}

async function decryptShroudedKeyBag(
  bag: pkijs.PKCS8ShroudedKeyBag,
  passwordBuf: ArrayBuffer
): Promise<DevKey> {
  const algoOid = bag.encryptionAlgorithm.algorithmId;
  if (algoOid !== OID_PBES2) {
    throw unsupportedAlgorithmError("private key", algoOid);
  }
  await (
    bag as unknown as {
      parseInternalValues: (p: { password: ArrayBuffer }) => Promise<void>;
    }
  ).parseInternalValues({ password: passwordBuf });
  const pki = bag.parsedValue;
  if (!pki) throw new Error("PKCS#8 shrouded key bag has no key.");
  const der = pki.toSchema().toBER(false);
  return DevKey.fromPkcs8Der(Buffer.from(der));
}

function passwordToArrayBuffer(password: string): ArrayBuffer {
  // pkijs accepts the raw UTF-8 bytes here:
  // - For the PKCS#12 B.2 KDF (used to MAC the PFX), it auto-detects whether
  //   the bytes round-trip as UTF-8 and re-encodes to BMPString internally.
  // - For PBES2/PBKDF2 on inner SafeContents and the shrouded key bag, it
  //   passes the bytes through unchanged, which matches the encoding used by
  //   .NET (Core 6+) and OpenSSL ≥ 1.1.0 when reading the PFX back.
  return bufferToArrayBuffer(Buffer.from(password, "utf-8"));
}

function bufferToArrayBuffer(buf: Buffer | Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(buf.byteLength);
  new Uint8Array(ab).set(buf);
  return ab;
}
