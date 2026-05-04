/**
 * PKCS#12 / PFX read + write built on `pkijs` (which handles the RFC 7292 KDF
 * and PBES2 encryption directly via webcrypto), replacing the RSA-only
 * `node-forge` PFX path.
 *
 * Uses PBES2/AES-256-CBC + PBKDF2-SHA-256 for both the SafeBag content
 * encryption and the PKCS#8 ShroudedKeyBag — modern .NET (Core 6+) accepts
 * these on every platform we target.
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { webcrypto } from "node:crypto";
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

/**
 * Well-known PKCS#12 PBE-with-SHA OIDs that we deliberately don't accept.
 * Used purely to render an actionable error message — the actual rejection
 * is just "anything that isn't PBES2" — so any future additions to this
 * map only improve diagnostics, not policy.
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

const PBKDF2_ITERATIONS = 2048;

export interface BuildPfxOptions {
  cert: DevCert;
  key?: DevKey | null;
  password?: string;
  /** Optional human-readable label written into the cert / key SafeBags. */
  friendlyName?: string;
}

/**
 * Build a PFX containing one certificate and (optionally) its matching
 * private key. Returns the raw PFX bytes.
 */
export async function buildPfx(opts: BuildPfxOptions): Promise<Buffer> {
  ensureEngine();
  const passwordBuf = passwordToArrayBuffer(opts.password ?? "");
  const localKeyId = computeLocalKeyId(opts.cert);

  const certBag = buildCertSafeBag(opts.cert, opts.friendlyName, localKeyId);

  const certSafeContents = new pkijs.SafeContents({ safeBags: [certBag] });
  const keyBags: pkijs.SafeBag[] = [];
  if (opts.key) {
    keyBags.push(
      await buildKeySafeBag(opts.key, passwordBuf, opts.friendlyName, localKeyId)
    );
  }

  // Build AuthenticatedSafe parsedValue with our SafeContents.
  // privacyMode 1 = password-encrypted, 0 = unencrypted (the key bag is
  // encrypted at the SafeBag layer, so the surrounding SafeContents may be
  // plain to mirror common PFX tooling output).
  const parsedSafeContents: Array<{
    privacyMode: number;
    value: pkijs.SafeContents;
  }> = [{ privacyMode: 1, value: certSafeContents }];
  if (keyBags.length > 0) {
    parsedSafeContents.push({
      privacyMode: 0,
      value: new pkijs.SafeContents({ safeBags: keyBags }),
    });
  }

  const authenticatedSafe = new pkijs.AuthenticatedSafe();
  // pkijs reads parsedValue from the constructor or from parseInternalValues;
  // we set it directly so makeInternalValues has something to encode.
  (authenticatedSafe as unknown as { parsedValue: unknown }).parsedValue = {
    safeContents: parsedSafeContents,
  };

  const safeContentParams = parsedSafeContents.map((sc) =>
    sc.privacyMode === 1
      ? {
          password: passwordBuf,
          contentEncryptionAlgorithm: aesCbc256(),
          hmacHashAlgorithm: "SHA-256",
          iterationCount: PBKDF2_ITERATIONS,
        }
      : {}
  );

  await authenticatedSafe.makeInternalValues({
    safeContents: safeContentParams,
  });

  // Build outer PFX with HMAC-SHA-256 integrity.
  const pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0,
      authenticatedSafe,
    },
  });
  await pfx.makeInternalValues({
    iterations: PBKDF2_ITERATIONS,
    pbkdf2HashAlgorithm: { name: "SHA-256" },
    hmacHashAlgorithm: "SHA-256",
    password: passwordBuf,
  });

  const der = pfx.toSchema().toBER(false);
  return Buffer.from(der);
}

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
    // Cleartext SafeContents wrapped in an OCTET STRING.
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

function buildCertSafeBag(
  cert: DevCert,
  friendlyName: string | undefined,
  localKeyId: ArrayBuffer
): pkijs.SafeBag {
  const certificate = pkijs.Certificate.fromBER(bufferToArrayBuffer(cert.der));
  const safeBag = new pkijs.SafeBag({
    bagId: OID_BAG_CERT,
    bagValue: new pkijs.CertBag({
      parsedValue: certificate,
      certId: OID_X509,
    }),
    bagAttributes: buildBagAttributes(friendlyName, localKeyId),
  });
  return safeBag;
}

async function buildKeySafeBag(
  key: DevKey,
  password: ArrayBuffer,
  friendlyName: string | undefined,
  localKeyId: ArrayBuffer
): Promise<pkijs.SafeBag> {
  const pkcs8Ab = bufferToArrayBuffer(key.der);
  const pki = pkijs.PrivateKeyInfo.fromBER(pkcs8Ab);

  const shroudedBag = new pkijs.PKCS8ShroudedKeyBag({
    parsedValue: pki,
  });

  await shroudedBag.makeInternalValues({
    password,
    contentEncryptionAlgorithm: aesCbc256(),
    hmacHashAlgorithm: "SHA-256",
    iterationCount: PBKDF2_ITERATIONS,
  });

  return new pkijs.SafeBag({
    bagId: OID_BAG_PKCS8_SHROUDED,
    bagValue: shroudedBag,
    bagAttributes: buildBagAttributes(friendlyName, localKeyId),
  });
}

function buildBagAttributes(
  friendlyName: string | undefined,
  localKeyId: ArrayBuffer
): pkijs.Attribute[] {
  const attrs: pkijs.Attribute[] = [];
  if (friendlyName) {
    attrs.push(
      new pkijs.Attribute({
        type: OID_FRIENDLY_NAME,
        values: [new asn1js.BmpString({ value: friendlyName })],
      })
    );
  }
  attrs.push(
    new pkijs.Attribute({
      type: OID_LOCAL_KEY_ID,
      values: [new asn1js.OctetString({ valueHex: localKeyId })],
    })
  );
  return attrs;
}

/**
 * The PKCS#12 `localKeyId` attribute that links a cert bag to the matching
 * key bag. We use the cert's SHA-1 thumbprint, which is what `dotnet
 * dev-certs` produces.
 */
function computeLocalKeyId(cert: DevCert): ArrayBuffer {
  const hex = cert.thumbprintSha1;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out.buffer;
}

/**
 * pkijs's `ContentEncryptionAlgorithm` type unions AES-CBC and AES-GCM
 * variants, both of which require an `iv` field in their declared shape.
 * In practice pkijs generates a random IV inside `EncryptedData.encrypt`
 * and the runtime only consumes `name` + `length`; the cast tells the
 * typechecker what the function actually accepts.
 */
function aesCbc256(): NonNullable<
  Parameters<pkijs.PKCS8ShroudedKeyBag["makeInternalValues"]>[0]
>["contentEncryptionAlgorithm"] {
  return {
    name: "AES-CBC",
    length: 256,
  } as unknown as NonNullable<
    Parameters<pkijs.PKCS8ShroudedKeyBag["makeInternalValues"]>[0]
  >["contentEncryptionAlgorithm"];
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
