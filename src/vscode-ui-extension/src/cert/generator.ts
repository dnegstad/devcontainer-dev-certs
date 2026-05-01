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
  ASPNET_HTTPS_OID_FRIENDLY_NAME,
  CURRENT_CERTIFICATE_VERSION,
  MINIMUM_CERTIFICATE_VERSION,
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
    thumbprint: devCert.thumbprint,
  };
}

/**
 * Check whether a parsed certificate looks like a valid ASP.NET Core HTTPS
 * dev cert: CN=localhost, currently within its validity window, and tagged
 * with the dev-cert custom OID at an acceptable version.
 */
export function isValidDevCert(
  cert: DevCert,
  minimumVersion: number = MINIMUM_CERTIFICATE_VERSION
): boolean {
  if (cert.subjectCN !== "localhost") return false;

  const now = new Date();
  if (cert.notBefore > now || cert.notAfter < now) return false;

  const version = getCertificateVersion(cert);
  if (version < 0 || version < minimumVersion) return false;

  return true;
}

/**
 * Extract the version byte from the ASP.NET dev cert custom-OID extension.
 * Returns -1 if the extension is absent.
 */
export function getCertificateVersion(cert: DevCert): number {
  const ext = cert.getExtension(ASPNET_HTTPS_OID);
  if (!ext) return -1;

  // The extension's extnValue is itself a DER OCTET STRING wrapping the
  // version byte (matching how `dotnet dev-certs` and node-forge serialise
  // the value). Peel back one layer of OCTET STRING if present, otherwise
  // treat the bytes directly.
  const raw = unwrapOctetString(ext.value);

  if (raw.length === 0) return 0;

  // Legacy v0 cert: raw bytes spell out the friendly name.
  if (
    raw.length === ASPNET_HTTPS_OID_FRIENDLY_NAME.length &&
    raw[0] === 0x41 // 'A'
  ) {
    return 0;
  }

  return raw[0];
}

/**
 * Compute the SHA-1 thumbprint of a PEM-encoded certificate string.
 * Uppercase hex, matching .NET's `X509Certificate2.Thumbprint`.
 */
export function computeThumbprint(pemCert: string): string {
  return new DevCert(pemCert).thumbprint;
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

function generateSerialNumber(): string {
  const maxAttempts = 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const bytes = randomBytes(16);
    bytes[0] &= 0x7f; // ensure non-negative
    if (bytes.some((value) => value !== 0)) {
      return bytes.toString("hex");
    }
  }
  throw new Error("Failed to generate a non-zero certificate serial number.");
}

function unwrapOctetString(value: Buffer): Buffer {
  if (value.length >= 2 && value[0] === 0x04) {
    // OCTET STRING tag is 0x04. Decode short-form length.
    if ((value[1] & 0x80) === 0) {
      const len = value[1];
      if (value.length === 2 + len) {
        return value.subarray(2);
      }
    } else {
      const numLenBytes = value[1] & 0x7f;
      if (numLenBytes <= 4 && value.length >= 2 + numLenBytes) {
        let len = 0;
        for (let i = 0; i < numLenBytes; i++) {
          len = (len << 8) | value[2 + i];
        }
        if (value.length === 2 + numLenBytes + len) {
          return value.subarray(2 + numLenBytes);
        }
      }
    }
  }
  return value;
}
