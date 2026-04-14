import { describe, it, expect } from "vitest";
import * as forge from "node-forge";
import {
  generateCertificate,
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
} from "../src/cert/generator";
import {
  ASPNET_HTTPS_OID,
  ASPNET_HTTPS_OID_FRIENDLY_NAME,
  CURRENT_CERTIFICATE_VERSION,
  MINIMUM_CERTIFICATE_VERSION,
  RSA_KEY_SIZE,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
  VALIDITY_DAYS,
} from "../src/cert/properties";

function makeTestCert() {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

describe("generateCertificate", () => {
  it("sets subject CN=localhost", () => {
    const { cert } = makeTestCert();
    const cn = cert.subject.getField("CN");
    expect(cn).not.toBeNull();
    expect(cn!.value).toBe("localhost");
  });

  it("sets issuer CN=localhost (self-signed)", () => {
    const { cert } = makeTestCert();
    const cn = cert.issuer.getField("CN");
    expect(cn).not.toBeNull();
    expect(cn!.value).toBe("localhost");
  });

  it("uses a 2048-bit RSA key", () => {
    const { cert } = makeTestCert();
    const pubKey = cert.publicKey as forge.pki.rsa.PublicKey;
    expect(pubKey.n.bitLength()).toBe(RSA_KEY_SIZE);
  });

  it("sets validity dates matching the provided range", () => {
    const notBefore = new Date("2025-01-01T00:00:00Z");
    const notAfter = new Date("2026-01-01T00:00:00Z");
    const { cert } = generateCertificate(notBefore, notAfter);
    expect(cert.validity.notBefore.getTime()).toBe(notBefore.getTime());
    expect(cert.validity.notAfter.getTime()).toBe(notAfter.getTime());
  });

  it("generates a positive serial number", () => {
    const { cert } = makeTestCert();
    // Serial should be a hex string. The leading nibble should be 0-7 (positive).
    const serial = cert.serialNumber;
    expect(serial).toMatch(/^[0-9a-f]+$/);
    const firstNibble = parseInt(serial[0], 16);
    expect(firstNibble).toBeLessThanOrEqual(7);
  });

  it("produces an uppercase hex thumbprint", () => {
    const { thumbprint } = makeTestCert();
    expect(thumbprint).toMatch(/^[0-9A-F]{40}$/);
  });

  it("produces consistent thumbprint via computeThumbprint", () => {
    const { cert, thumbprint } = makeTestCert();
    const pem = forge.pki.certificateToPem(cert);
    expect(computeThumbprint(pem)).toBe(thumbprint);
  });

  describe("extensions", () => {
    it("includes Basic Constraints (critical, not a CA)", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension("basicConstraints") as {
        critical: boolean;
        cA: boolean;
      };
      expect(ext).not.toBeNull();
      expect(ext.critical).toBe(true);
      expect(ext.cA).toBe(false);
    });

    it("includes Key Usage (critical, digitalSignature + keyEncipherment)", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension("keyUsage") as {
        critical: boolean;
        digitalSignature: boolean;
        keyEncipherment: boolean;
      };
      expect(ext).not.toBeNull();
      expect(ext.critical).toBe(true);
      expect(ext.digitalSignature).toBe(true);
      expect(ext.keyEncipherment).toBe(true);
    });

    it("includes Extended Key Usage (critical, serverAuth)", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension("extKeyUsage") as {
        critical: boolean;
        serverAuth: boolean;
      };
      expect(ext).not.toBeNull();
      expect(ext.critical).toBe(true);
      expect(ext.serverAuth).toBe(true);
    });

    it("includes SAN with all expected DNS names and IPs (critical)", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension("subjectAltName") as {
        critical: boolean;
        altNames: Array<{ type: number; value?: string; ip?: string }>;
      };
      expect(ext).not.toBeNull();
      expect(ext.critical).toBe(true);

      const dnsNames = ext.altNames
        .filter((a) => a.type === 2)
        .map((a) => a.value);
      for (const expected of SAN_DNS_NAMES) {
        expect(dnsNames).toContain(expected);
      }

      const ips = ext.altNames
        .filter((a) => a.type === 7)
        .map((a) => a.ip);
      for (const expected of SAN_IP_ADDRESSES) {
        expect(ips).toContain(expected);
      }
    });

    it("includes ASP.NET HTTPS OID with current version byte", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension({ id: ASPNET_HTTPS_OID }) as {
        critical: boolean;
        value: string;
      } | null;
      expect(ext).not.toBeNull();
      expect(ext!.critical).toBe(false);
      expect(ext!.value.charCodeAt(0)).toBe(CURRENT_CERTIFICATE_VERSION);
    });

    it("includes Subject Key Identifier", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension("subjectKeyIdentifier");
      expect(ext).not.toBeNull();
    });

    it("includes Authority Key Identifier", () => {
      const { cert } = makeTestCert();
      const ext = cert.getExtension("authorityKeyIdentifier");
      expect(ext).not.toBeNull();
    });
  });

  it("generates unique certificates on each call", () => {
    const a = makeTestCert();
    const b = makeTestCert();
    expect(a.thumbprint).not.toBe(b.thumbprint);
    expect(a.cert.serialNumber).not.toBe(b.cert.serialNumber);
  });
});

describe("isValidDevCert", () => {
  it("returns true for a freshly generated cert", () => {
    const { cert } = makeTestCert();
    expect(isValidDevCert(cert)).toBe(true);
  });

  it("returns false for an expired cert", () => {
    const notBefore = new Date("2020-01-01T00:00:00Z");
    const notAfter = new Date("2020-06-01T00:00:00Z");
    const { cert } = generateCertificate(notBefore, notAfter);
    expect(isValidDevCert(cert)).toBe(false);
  });

  it("returns false for a not-yet-valid cert", () => {
    const notBefore = new Date("2099-01-01T00:00:00Z");
    const notAfter = new Date("2100-01-01T00:00:00Z");
    const { cert } = generateCertificate(notBefore, notAfter);
    expect(isValidDevCert(cert)).toBe(false);
  });

  it("returns false when minimum version is higher than current", () => {
    const { cert } = makeTestCert();
    expect(isValidDevCert(cert, CURRENT_CERTIFICATE_VERSION + 1)).toBe(false);
  });

  it("returns true with the default minimum version", () => {
    const { cert } = makeTestCert();
    expect(isValidDevCert(cert, MINIMUM_CERTIFICATE_VERSION)).toBe(true);
  });

  it("returns false for a cert with wrong subject", () => {
    // Create a cert manually with a different CN
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    );
    cert.setSubject([{ name: "commonName", value: "not-localhost" }]);
    cert.setIssuer([{ name: "commonName", value: "not-localhost" }]);
    cert.setExtensions([
      {
        id: ASPNET_HTTPS_OID,
        critical: false,
        value: String.fromCharCode(CURRENT_CERTIFICATE_VERSION),
      },
    ]);
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    expect(isValidDevCert(cert)).toBe(false);
  });

  it("returns false for a cert without the ASP.NET OID", () => {
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    );
    cert.setSubject([{ name: "commonName", value: "localhost" }]);
    cert.setIssuer([{ name: "commonName", value: "localhost" }]);
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    expect(isValidDevCert(cert)).toBe(false);
  });
});

describe("getCertificateVersion", () => {
  it("returns current version for a generated cert", () => {
    const { cert } = makeTestCert();
    expect(getCertificateVersion(cert)).toBe(CURRENT_CERTIFICATE_VERSION);
  });

  it("returns -1 for a cert without the OID", () => {
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    );
    cert.setSubject([{ name: "commonName", value: "localhost" }]);
    cert.setIssuer([{ name: "commonName", value: "localhost" }]);
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    expect(getCertificateVersion(cert)).toBe(-1);
  });

  it("returns 0 for a legacy cert with empty value", () => {
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    );
    cert.setSubject([{ name: "commonName", value: "localhost" }]);
    cert.setIssuer([{ name: "commonName", value: "localhost" }]);
    cert.setExtensions([
      { id: ASPNET_HTTPS_OID, critical: false, value: "" },
    ]);
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    expect(getCertificateVersion(cert)).toBe(0);
  });

  it("returns 0 for a legacy cert with friendly-name-length value starting with 'A'", () => {
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    );
    cert.setSubject([{ name: "commonName", value: "localhost" }]);
    cert.setIssuer([{ name: "commonName", value: "localhost" }]);
    cert.setExtensions([
      {
        id: ASPNET_HTTPS_OID,
        critical: false,
        value: ASPNET_HTTPS_OID_FRIENDLY_NAME,
      },
    ]);
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    expect(getCertificateVersion(cert)).toBe(0);
  });
});

describe("computeThumbprint", () => {
  it("returns a 40-character uppercase hex string", () => {
    const { cert } = makeTestCert();
    const pem = forge.pki.certificateToPem(cert);
    const thumbprint = computeThumbprint(pem);
    expect(thumbprint).toMatch(/^[0-9A-F]{40}$/);
  });

  it("is deterministic for the same certificate", () => {
    const { cert } = makeTestCert();
    const pem = forge.pki.certificateToPem(cert);
    expect(computeThumbprint(pem)).toBe(computeThumbprint(pem));
  });

  it("differs for different certificates", () => {
    const a = makeTestCert();
    const b = makeTestCert();
    const pemA = forge.pki.certificateToPem(a.cert);
    const pemB = forge.pki.certificateToPem(b.cert);
    expect(computeThumbprint(pemA)).not.toBe(computeThumbprint(pemB));
  });
});
