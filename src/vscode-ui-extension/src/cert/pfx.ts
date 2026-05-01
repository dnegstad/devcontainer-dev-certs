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
  pkijs.setEngine(engine.name, engine);
  engineConfigured = true;
}

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_BAG_CERT = "1.2.840.113549.1.12.10.1.3";
const OID_BAG_PKCS8_SHROUDED = "1.2.840.113549.1.12.10.1.2";
const OID_X509 = "1.2.840.113549.1.9.22.1";
const OID_FRIENDLY_NAME = "1.2.840.113549.1.9.20";
const OID_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";

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
          contentEncryptionAlgorithm: { name: "AES-CBC", length: 256 },
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

  await pfx.parseInternalValues({ password: passwordBuf, checkIntegrity: true });

  const authSafe = pfx.parsedValue?.authenticatedSafe;
  if (!authSafe) throw new Error("PFX has no authenticated safe");

  // We need to decrypt the inner SafeContents. pkijs expects a parameter
  // shape per content type; we pass password for any encrypted contents.
  const innerParams = authSafe.safeContents.map(() => ({ password: passwordBuf }));
  await authSafe.parseInternalValues({ safeContents: innerParams });

  const allBags: pkijs.SafeBag[] = [];
  for (const inner of authSafe.parsedValue.safeContents) {
    const safeContents = inner.value as pkijs.SafeContents;
    for (const bag of safeContents.safeBags) {
      allBags.push(bag);
    }
  }

  let cert: DevCert | null = null;
  let key: DevKey | null = null;
  for (const bag of allBags) {
    if (bag.bagId === OID_BAG_CERT) {
      const certBag = bag.bagValue as pkijs.CertBag;
      const certParsed = certBag.parsedValue as pkijs.Certificate;
      const der = certParsed.toSchema(true).toBER(false);
      if (!cert) cert = new DevCert(Buffer.from(der));
    } else if (bag.bagId === OID_BAG_PKCS8_SHROUDED) {
      const keyBag = bag.bagValue as pkijs.PKCS8ShroudedKeyBag;
      // Decrypt the shrouded key bag.
      await (keyBag as unknown as {
        parseInternalValues: (
          p: { password: ArrayBuffer }
        ) => Promise<void>;
      }).parseInternalValues({ password: passwordBuf });
      const pki = keyBag.parsedValue;
      if (!pki) throw new Error("PKCS#8 shrouded key bag has no key");
      const der = pki.toSchema().toBER(false);
      key = DevKey.fromPkcs8Der(Buffer.from(der));
    }
  }

  if (!cert) {
    throw new Error("PFX contains no certificate.");
  }

  return { cert, key };
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
    contentEncryptionAlgorithm: { name: "AES-CBC", length: 256 },
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
  const hex = cert.thumbprint;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out.buffer;
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
