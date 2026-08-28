import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";
import { randomBytes, webcrypto } from "node:crypto";
import { DevCert, DevKey } from "./types";
import {
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  RSA_KEY_SIZE,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
} from "./properties";

let cryptoProviderConfigured = false;
function ensureCryptoProvider(): void {
  if (cryptoProviderConfigured) return;
  cryptoProvider.set(webcrypto as unknown as Crypto);
  cryptoProviderConfigured = true;
}

export interface GeneratedCert {
  cert: DevCert;
  key: DevKey;
  /**
   * SHA-1 thumbprint, uppercase hex. This is the .NET-compatible
   * `X509Certificate2.Thumbprint` value used as the X509Store filename
   * (`{thumbprint}.pfx`). For a stronger cert identifier, use
   * `cert.thumbprint` (SHA-256).
   */
  thumbprint: string;
}

/**
 * Algorithm choices for `generateCertificate`. Defaults to RSA-2048 to match
 * the historical ASP.NET dev cert format, but the same code path supports
 * ECDSA P-256/P-384/P-521 and Ed25519 for user-managed flows.
 */
export type GenerateAlgorithm =
  | { kind: "rsa"; modulusLength?: number }
  | { kind: "ec"; namedCurve: "P-256" | "P-384" | "P-521" }
  | { kind: "ed25519" }
  | { kind: "ed448" };

/**
 * Generate a self-signed certificate matching the ASP.NET Core HTTPS dev
 * cert format (subject, validity, SANs, custom OID, SKI/AKI).
 *
 * The default algorithm is RSA-2048 with SHA-256 signing — a byte-for-byte
 * compatible replacement for the previous `node-forge` path. Pass an
 * `algorithm` to opt into ECDSA / Ed25519 (used by user-managed cert flows
 * that need to round-trip non-RSA keys).
 */
export async function generateCertificate(
  notBefore: Date,
  notAfter: Date,
  algorithm: GenerateAlgorithm = { kind: "rsa" }
): Promise<GeneratedCert> {
  ensureCryptoProvider();

  const { keyPair, signingAlgorithm } = await generateKeyPair(algorithm);

  const serialNumber = generateSerialNumber();
  const subject = "CN=localhost";
  const issuer = subject;

  const sanEntries = [
    ...SAN_DNS_NAMES.map(
      (dns) => ({ type: "dns" as const, value: dns })
    ),
    ...SAN_IP_ADDRESSES.map(
      (ip) => ({ type: "ip" as const, value: ip })
    ),
  ];

  const extensions: Extension[] = [
    new BasicConstraintsExtension(false, undefined, true),
    new KeyUsagesExtension(
      KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment,
      true
    ),
    new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth], true),
    new SubjectAlternativeNameExtension(sanEntries, true),
    new Extension(
      ASPNET_HTTPS_OID,
      false,
      new Uint8Array([CURRENT_CERTIFICATE_VERSION]).buffer
    ),
    await SubjectKeyIdentifierExtension.create(keyPair.publicKey),
    await AuthorityKeyIdentifierExtension.create(keyPair.publicKey),
  ];

  const cert = await X509CertificateGenerator.create({
    serialNumber,
    subject,
    issuer,
    notBefore,
    notAfter,
    signingAlgorithm,
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    extensions,
  });

  const devCert = new DevCert(cert);
  const devKey = await DevKey.fromCryptoKey(keyPair.privateKey);

  return {
    cert: devCert,
    key: devKey,
    thumbprint: devCert.thumbprintSha1,
  };
}

async function generateKeyPair(
  algorithm: GenerateAlgorithm
): Promise<{
  keyPair: CryptoKeyPair;
  signingAlgorithm: Algorithm | RsaHashedKeyGenParams | EcdsaParams;
}> {
  const subtle = webcrypto.subtle;

  if (algorithm.kind === "rsa") {
    const modulusLength = algorithm.modulusLength ?? RSA_KEY_SIZE;
    const params: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    };
    const keyPair = (await subtle.generateKey(params, true, [
      "sign",
      "verify",
    ]));
    return {
      keyPair,
      signingAlgorithm: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      } as RsaHashedKeyGenParams,
    };
  }

  if (algorithm.kind === "ec") {
    const params: EcKeyGenParams = {
      name: "ECDSA",
      namedCurve: algorithm.namedCurve,
    };
    const keyPair = (await subtle.generateKey(params, true, [
      "sign",
      "verify",
    ]));
    return {
      keyPair,
      signingAlgorithm: {
        name: "ECDSA",
        hash: defaultEcHash(algorithm.namedCurve),
      } as EcdsaParams,
    };
  }

  if (algorithm.kind === "ed25519") {
    const keyPair = (await subtle.generateKey(
      "Ed25519",
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    return {
      keyPair,
      signingAlgorithm: { name: "Ed25519" },
    };
  }

  if (algorithm.kind === "ed448") {
    const keyPair = (await subtle.generateKey(
      { name: "Ed448" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    return {
      keyPair,
      signingAlgorithm: { name: "Ed448" },
    };
  }

  throw new Error(
    `Unsupported algorithm: ${(algorithm as { kind: string }).kind}`
  );
}

function defaultEcHash(curve: string): string {
  switch (curve) {
    case "P-256":
      return "SHA-256";
    case "P-384":
      return "SHA-384";
    case "P-521":
      return "SHA-512";
    default:
      return "SHA-256";
  }
}

/**
 * 16-byte positive serial number, hex-encoded.
 *
 * Exported for testing: the guarantee below is probabilistic (a bad leading
 * byte turns up about once in 128), so pinning it needs thousands of samples,
 * and routing those through `generateCertificate` would mean thousands of RSA
 * keygens. The production caller is `generateCertificate`, just below.
 */
export function generateSerialNumber(): string {
  const maxAttempts = 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const bytes = randomBytes(16);
    bytes[0] &= 0x7f; // ensure non-negative
    // Reject a zero leading byte, not just an all-zero serial. Clearing the
    // high bit keeps the DER INTEGER positive, but a resulting 0x00 leading
    // byte is retained on the wire as sign padding (`02 10 00 b5 ...`) —
    // correct, yet every textual readback drops it, so the serial then looks
    // like a 15-byte value starting at or above 0x80. Requiring 0x01..0x7f
    // yields a serial that is positive, non-zero, and minimally encoded, with
    // no padding byte for downstream code to reason about. Rejection (rather
    // than masking a 1 in) keeps the remaining bits uniform; five attempts
    // leaves a (1/128)^5 failure chance.
    if (bytes[0] !== 0) {
      return bytes.toString("hex");
    }
  }
  throw new Error("Failed to generate a non-zero certificate serial number.");
}
