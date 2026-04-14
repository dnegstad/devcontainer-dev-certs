import { describe, it, expect, afterEach } from "vitest";
import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  exportPfx,
  exportPem,
  certToPem,
  keyToPem,
  certToDer,
} from "../src/cert/exporter";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

function makeTestCert() {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-test-"));
}

const cleanupDirs: string[] = [];
afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

describe("exportPfx", () => {
  it("writes a PFX file to the output directory", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const outPath = exportPfx(cert, key, dir);
    expect(outPath).toBe(path.join(dir, "aspnetcore-dev.pfx"));
    expect(fs.existsSync(outPath)).toBe(true);
  });

  it("produces a PFX that can be parsed back", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    exportPfx(cert, key, dir);
    const pfxBytes = fs.readFileSync(path.join(dir, "aspnetcore-dev.pfx"));
    const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, "");

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBag = certBags[forge.pki.oids.certBag];
    expect(certBag).toBeDefined();
    expect(certBag!.length).toBeGreaterThan(0);

    const parsedCert = certBag![0].cert!;
    expect(parsedCert.subject.getField("CN")!.value).toBe("localhost");
  });

  it("produces a password-protected PFX when password is provided", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    exportPfx(cert, key, dir, "test-password");
    const pfxBytes = fs.readFileSync(path.join(dir, "aspnetcore-dev.pfx"));
    const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);

    // Should parse with the correct password
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, "test-password");
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    expect(certBags[forge.pki.oids.certBag]!.length).toBeGreaterThan(0);
  });

  it("creates the output directory if it does not exist", () => {
    const { cert, key } = makeTestCert();
    const dir = path.join(tmpDir(), "nested", "subdir");
    cleanupDirs.push(path.resolve(dir, "..", ".."));

    exportPfx(cert, key, dir);
    expect(fs.existsSync(path.join(dir, "aspnetcore-dev.pfx"))).toBe(true);
  });
});

describe("exportPem", () => {
  it("writes cert and key PEM files", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath, keyPath } = exportPem(cert, key, dir);
    expect(certPath).toBe(path.join(dir, "aspnetcore-dev.pem"));
    expect(keyPath).toBe(path.join(dir, "aspnetcore-dev.key"));
    expect(fs.existsSync(certPath)).toBe(true);
    expect(fs.existsSync(keyPath)).toBe(true);
  });

  it("writes a valid PEM certificate that can be parsed back", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath } = exportPem(cert, key, dir);
    const pemContent = fs.readFileSync(certPath, "utf-8");
    expect(pemContent).toContain("-----BEGIN CERTIFICATE-----");
    expect(pemContent).toContain("-----END CERTIFICATE-----");

    const parsed = forge.pki.certificateFromPem(pemContent);
    expect(parsed.subject.getField("CN")!.value).toBe("localhost");
  });

  it("writes a valid PEM private key that can be parsed back", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { keyPath } = exportPem(cert, key, dir);
    const pemContent = fs.readFileSync(keyPath, "utf-8");
    expect(pemContent).toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(pemContent).toContain("-----END RSA PRIVATE KEY-----");

    const parsed = forge.pki.privateKeyFromPem(pemContent);
    expect(parsed).toBeDefined();
  });

  it("creates the output directory if it does not exist", () => {
    const { cert, key } = makeTestCert();
    const dir = path.join(tmpDir(), "nested", "subdir");
    cleanupDirs.push(path.resolve(dir, "..", ".."));

    exportPem(cert, key, dir);
    expect(fs.existsSync(path.join(dir, "aspnetcore-dev.pem"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "aspnetcore-dev.key"))).toBe(true);
  });
});

describe("certToPem", () => {
  it("returns a PEM-encoded certificate string", () => {
    const { cert } = makeTestCert();
    const pem = certToPem(cert);
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(pem).toContain("-----END CERTIFICATE-----");
  });
});

describe("keyToPem", () => {
  it("returns a PEM-encoded private key string", () => {
    const { key } = makeTestCert();
    const pem = keyToPem(key);
    expect(pem).toContain("PRIVATE KEY");
  });
});

describe("certToDer", () => {
  it("returns a Buffer of DER bytes", () => {
    const { cert } = makeTestCert();
    const der = certToDer(cert);
    expect(Buffer.isBuffer(der)).toBe(true);
    expect(der.length).toBeGreaterThan(0);
  });

  it("produces DER that can be round-tripped through forge", () => {
    const { cert } = makeTestCert();
    const der = certToDer(cert);
    const asn1 = forge.asn1.fromDer(
      forge.util.createBuffer(der.toString("binary"))
    );
    const parsed = forge.pki.certificateFromAsn1(asn1);
    expect(parsed.subject.getField("CN")!.value).toBe("localhost");
  });
});
