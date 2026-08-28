import { describe, it, expect } from "vitest";
import { X509Certificate } from "node:crypto";
import { generateSerialNumber } from "@devcontainer-dev-certs/shared/src/cert/generator";
import {
  generateCertificate,
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
  DevCert,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  MINIMUM_CERTIFICATE_VERSION,
  RSA_KEY_SIZE,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
  VALIDITY_DAYS,
} from "@devcontainer-dev-certs/shared";
import { Extension, X509CertificateGenerator } from "@peculiar/x509";
import { webcrypto } from "node:crypto";

const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_SAN = "2.5.29.17";
const OID_SKI = "2.5.29.14";
const OID_AKI = "2.5.29.35";

async function makeTestCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

describe("generateCertificate", () => {
  it("sets subject CN=localhost", async () => {
    const { cert } = await makeTestCert();
    expect(cert.subjectCN).toBe("localhost");
  });

  it("sets issuer CN=localhost (self-signed)", async () => {
    const { cert } = await makeTestCert();
    expect(cert.issuerCN).toBe("localhost");
  });

  it("uses a 2048-bit RSA key by default", async () => {
    const { cert, key } = await makeTestCert();
    expect(key.algorithm).toBe("rsa");
    // Modulus length is exposed via the underlying KeyObject.
    const detail = (
      key.keyObject as unknown as {
        asymmetricKeyDetails?: { modulusLength?: number };
      }
    ).asymmetricKeyDetails;
    expect(detail?.modulusLength).toBe(RSA_KEY_SIZE);
    // The cert's public key info encodes RSA.
    const node = new X509Certificate(cert.der);
    expect(node.publicKey.asymmetricKeyType).toBe("rsa");
  });

  it("supports ECDSA (P-256) generation", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key } = await generateCertificate(now, expiry, {
      kind: "ec",
      namedCurve: "P-256",
    });
    expect(key.algorithm).toBe("ec");
    const node = new X509Certificate(cert.der);
    expect(node.publicKey.asymmetricKeyType).toBe("ec");
  });

  it("supports Ed25519 generation", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key } = await generateCertificate(now, expiry, {
      kind: "ed25519",
    });
    expect(key.algorithm).toBe("ed25519");
    const node = new X509Certificate(cert.der);
    expect(node.publicKey.asymmetricKeyType).toBe("ed25519");
  });

  it("sets validity dates matching the provided range", async () => {
    const notBefore = new Date("2025-01-01T00:00:00Z");
    const notAfter = new Date("2026-01-01T00:00:00Z");
    const { cert } = await generateCertificate(notBefore, notAfter);
    expect(cert.notBefore.getTime()).toBe(notBefore.getTime());
    expect(cert.notAfter.getTime()).toBe(notAfter.getTime());
  });

  it("generates a positive serial number", async () => {
    const { cert } = await makeTestCert();
    const serial = cert.serialNumber;
    expect(serial).toMatch(/^[0-9a-f]+$/);
    const firstNibble = parseInt(serial[0], 16);
    expect(firstNibble).toBeLessThanOrEqual(7);
    // Full 16 bytes: a leading 0x00 would be dropped from this readback (DER
    // keeps it as sign padding, `cert.serialNumber` does not), which is
    // exactly the case `generateSerialNumber` now rejects.
    expect(serial).toHaveLength(32);
  });

  it("never emits a serial needing DER sign padding (10k samples)", async () => {
    // This used to fail about one run in 256: `bytes[0] &= 0x7f` can leave
    // 0x00, DER retains that byte as sign padding, and the textual readback
    // drops it — so the serial appeared to start at or above 0x80 and the
    // assertion above flaked. Sampled directly rather than through
    // generateCertificate, which would mean 10k RSA keygens.
    for (let i = 0; i < 10_000; i++) {
      const serial = generateSerialNumber();
      expect(serial).toHaveLength(32);
      const leading = parseInt(serial.slice(0, 2), 16);
      expect(leading).toBeGreaterThanOrEqual(0x01);
      expect(leading).toBeLessThanOrEqual(0x7f);
    }
  });

  it("produces an uppercase hex SHA-1 thumbprint on GeneratedCert", async () => {
    // The GeneratedCert.thumbprint field is the SHA-1 thumbprint that
    // matches .NET's `X509Certificate2.Thumbprint` and is used as the
    // X509Store filename stem.
    const { thumbprint } = await makeTestCert();
    expect(thumbprint).toMatch(/^[0-9A-F]{40}$/);
  });

  it("DevCert.thumbprint is SHA-256 by default", async () => {
    const { cert } = await makeTestCert();
    expect(cert.thumbprint).toMatch(/^[0-9A-F]{64}$/);
  });

  it("DevCert.thumbprintSha1 matches GeneratedCert.thumbprint", async () => {
    const { cert, thumbprint } = await makeTestCert();
    expect(cert.thumbprintSha1).toMatch(/^[0-9A-F]{40}$/);
    expect(cert.thumbprintSha1).toBe(thumbprint);
  });

  it("DevCert.thumbprint and thumbprintSha1 differ", async () => {
    const { cert } = await makeTestCert();
    expect(cert.thumbprint).not.toBe(cert.thumbprintSha1);
  });

  it("computeThumbprint returns the SHA-1 thumbprint (matching .NET's convention)", async () => {
    const { cert, thumbprint } = await makeTestCert();
    expect(computeThumbprint(cert.pem)).toBe(thumbprint);
    expect(computeThumbprint(cert.pem)).toBe(cert.thumbprintSha1);
    expect(computeThumbprint(cert.pem)).toMatch(/^[0-9A-F]{40}$/);
  });

  describe("extensions", () => {
    it("includes Basic Constraints (critical, not a CA)", async () => {
      const { cert } = await makeTestCert();
      const ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
      expect(ext).not.toBeNull();
      expect(ext!.critical).toBe(true);
    });

    it("includes Key Usage (critical)", async () => {
      const { cert } = await makeTestCert();
      const ext = cert.getExtension(OID_KEY_USAGE);
      expect(ext).not.toBeNull();
      expect(ext!.critical).toBe(true);
    });

    it("includes Extended Key Usage (critical)", async () => {
      const { cert } = await makeTestCert();
      const ext = cert.getExtension(OID_EXT_KEY_USAGE);
      expect(ext).not.toBeNull();
      expect(ext!.critical).toBe(true);
    });

    it("includes SAN with all expected DNS names and IPs (critical)", async () => {
      const { cert } = await makeTestCert();
      const ext = cert.getExtension(OID_SAN);
      expect(ext).not.toBeNull();
      expect(ext!.critical).toBe(true);

      // Parse SAN entries via Node's X509Certificate which exposes them as text.
      const node = new X509Certificate(cert.der);
      const sanText = node.subjectAltName ?? "";
      for (const expected of SAN_DNS_NAMES) {
        expect(sanText).toContain(`DNS:${expected}`);
      }
      for (const expected of SAN_IP_ADDRESSES) {
        // Node renders IPv6 in expanded form; check for textual presence of
        // either a key part or the full address.
        expect(sanText).toContain("IP");
        if (expected.includes(":")) {
          expect(sanText).toMatch(/IP[^:]*:[0-9a-fA-F:]+/);
        } else {
          expect(sanText).toContain(`IP Address:${expected}`);
        }
      }
    });

    it("includes ASP.NET HTTPS OID with current version byte", async () => {
      const { cert } = await makeTestCert();
      const ext = cert.getExtension(ASPNET_HTTPS_OID);
      expect(ext).not.toBeNull();
      expect(ext!.critical).toBe(false);
      expect(getCertificateVersion(cert)).toBe(CURRENT_CERTIFICATE_VERSION);
    });

    it("includes Subject Key Identifier", async () => {
      const { cert } = await makeTestCert();
      expect(cert.getExtension(OID_SKI)).not.toBeNull();
    });

    it("includes Authority Key Identifier", async () => {
      const { cert } = await makeTestCert();
      expect(cert.getExtension(OID_AKI)).not.toBeNull();
    });
  });

  it("generates unique certificates on each call", async () => {
    const a = await makeTestCert();
    const b = await makeTestCert();
    expect(a.thumbprint).not.toBe(b.thumbprint);
    expect(a.cert.serialNumber).not.toBe(b.cert.serialNumber);
  });
});

describe("isValidDevCert", () => {
  it("returns true for a freshly generated cert", async () => {
    const { cert } = await makeTestCert();
    expect(isValidDevCert(cert)).toBe(true);
  });

  it("returns false for an expired cert", async () => {
    const notBefore = new Date("2020-01-01T00:00:00Z");
    const notAfter = new Date("2020-06-01T00:00:00Z");
    const { cert } = await generateCertificate(notBefore, notAfter);
    expect(isValidDevCert(cert)).toBe(false);
  });

  it("returns false for a not-yet-valid cert", async () => {
    const notBefore = new Date("2099-01-01T00:00:00Z");
    const notAfter = new Date("2100-01-01T00:00:00Z");
    const { cert } = await generateCertificate(notBefore, notAfter);
    expect(isValidDevCert(cert)).toBe(false);
  });

  it("returns false when minimum version is higher than current", async () => {
    const { cert } = await makeTestCert();
    expect(isValidDevCert(cert, CURRENT_CERTIFICATE_VERSION + 1)).toBe(false);
  });

  it("returns true with the default minimum version", async () => {
    const { cert } = await makeTestCert();
    expect(isValidDevCert(cert, MINIMUM_CERTIFICATE_VERSION)).toBe(true);
  });

  it("returns false for a cert with a wrong subject", async () => {
    const cert = await buildBareCert("CN=not-localhost", [
      new Extension(
        ASPNET_HTTPS_OID,
        false,
        new Uint8Array([CURRENT_CERTIFICATE_VERSION]).buffer
      ),
    ]);
    expect(isValidDevCert(cert)).toBe(false);
  });

  it("returns false for a cert without the ASP.NET OID", async () => {
    const cert = await buildBareCert("CN=localhost", []);
    expect(isValidDevCert(cert)).toBe(false);
  });
});

describe("getCertificateVersion", () => {
  it("returns current version for a generated cert", async () => {
    const { cert } = await makeTestCert();
    expect(getCertificateVersion(cert)).toBe(CURRENT_CERTIFICATE_VERSION);
  });

  it("returns -1 for a cert without the OID", async () => {
    const cert = await buildBareCert("CN=localhost", []);
    expect(getCertificateVersion(cert)).toBe(-1);
  });
});

describe("computeThumbprint", () => {
  it("returns a 40-character uppercase hex string", async () => {
    const { cert } = await makeTestCert();
    const thumbprint = computeThumbprint(cert.pem);
    expect(thumbprint).toMatch(/^[0-9A-F]{40}$/);
  });

  it("is deterministic for the same certificate", async () => {
    const { cert } = await makeTestCert();
    expect(computeThumbprint(cert.pem)).toBe(computeThumbprint(cert.pem));
  });

  it("differs for different certificates", async () => {
    const a = await makeTestCert();
    const b = await makeTestCert();
    expect(computeThumbprint(a.cert.pem)).not.toBe(
      computeThumbprint(b.cert.pem)
    );
  });
});

async function buildBareCert(subject: string, extensions: Extension[]): Promise<DevCert> {
  const keyPair = (await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  ));

  const cert = await X509CertificateGenerator.create({
    serialNumber: "01",
    subject,
    issuer: subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    extensions,
  });
  return new DevCert(cert);
}
