import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { X509Certificate } from "node:crypto";
import {
  exportPfx,
  exportPem,
  certToPem,
  keyToPem,
  certToDer,
} from "../src/cert/exporter";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";
import { parsePfx } from "../src/cert/pfx";

async function makeTestCert(): ReturnType<typeof generateCertificate> {
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
  it("writes a PFX file to the output directory", async () => {
    const { cert, key } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const outPath = await exportPfx(cert, key, dir);
    expect(outPath).toBe(path.join(dir, "aspnetcore-dev.pfx"));
    expect(fs.existsSync(outPath)).toBe(true);
  });

  it("produces a PFX that can be parsed back", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    await exportPfx(cert, key, dir);
    const pfxBytes = fs.readFileSync(path.join(dir, "aspnetcore-dev.pfx"));
    const parsed = await parsePfx(pfxBytes);
    expect(parsed.cert.subjectCN).toBe("localhost");
    expect(parsed.cert.thumbprint).toBe(thumbprint);
    expect(parsed.key).not.toBeNull();
  });

  it("produces a password-protected PFX when password is provided", async () => {
    const { cert, key } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    await exportPfx(cert, key, dir, "test-password");
    const pfxBytes = fs.readFileSync(path.join(dir, "aspnetcore-dev.pfx"));
    const parsed = await parsePfx(pfxBytes, "test-password");
    expect(parsed.cert.subjectCN).toBe("localhost");
  });

  it("creates the output directory if it does not exist", async () => {
    const { cert, key } = await makeTestCert();
    const root = tmpDir();
    cleanupDirs.push(root);
    const dir = path.join(root, "nested", "subdir");

    await exportPfx(cert, key, dir);
    expect(fs.existsSync(path.join(dir, "aspnetcore-dev.pfx"))).toBe(true);
  });
});

describe("exportPem", () => {
  it("writes cert and key PEM files", async () => {
    const { cert, key } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath, keyPath } = exportPem(cert, key, dir);
    expect(certPath).toBe(path.join(dir, "aspnetcore-dev.pem"));
    expect(keyPath).toBe(path.join(dir, "aspnetcore-dev.key"));
    expect(fs.existsSync(certPath)).toBe(true);
    expect(fs.existsSync(keyPath)).toBe(true);
  });

  it("writes a valid PEM certificate that can be parsed back", async () => {
    const { cert, key } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath } = exportPem(cert, key, dir);
    const pemContent = fs.readFileSync(certPath, "utf-8");
    expect(pemContent).toContain("-----BEGIN CERTIFICATE-----");
    expect(pemContent).toContain("-----END CERTIFICATE-----");

    const parsed = new X509Certificate(pemContent);
    expect(parsed.subject).toContain("CN=localhost");
  });

  it("writes a PKCS#8 PEM private key that Node can parse back", async () => {
    const { cert, key } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { keyPath } = exportPem(cert, key, dir);
    const pemContent = fs.readFileSync(keyPath, "utf-8");
    expect(pemContent).toContain("-----BEGIN PRIVATE KEY-----");
    expect(pemContent).toContain("-----END PRIVATE KEY-----");

    // Node round-trips it without error (createPrivateKey is implicit via DevKey).
    const { createPrivateKey } = await import("node:crypto");
    const obj = createPrivateKey({ key: pemContent, format: "pem" });
    expect(obj.asymmetricKeyType).toBe("rsa");
  });

  it("creates the output directory if it does not exist", async () => {
    const { cert, key } = await makeTestCert();
    const root = tmpDir();
    cleanupDirs.push(root);
    const dir = path.join(root, "nested", "subdir");

    exportPem(cert, key, dir);
    expect(fs.existsSync(path.join(dir, "aspnetcore-dev.pem"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "aspnetcore-dev.key"))).toBe(true);
  });
});

describe("certToPem", () => {
  it("returns a PEM-encoded certificate string", async () => {
    const { cert } = await makeTestCert();
    const pem = certToPem(cert);
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(pem).toContain("-----END CERTIFICATE-----");
  });
});

describe("keyToPem", () => {
  it("returns a PEM-encoded private key string", async () => {
    const { key } = await makeTestCert();
    const pem = keyToPem(key);
    expect(pem).toContain("PRIVATE KEY");
  });
});

describe("certToDer", () => {
  it("returns a Buffer of DER bytes", async () => {
    const { cert } = await makeTestCert();
    const der = certToDer(cert);
    expect(Buffer.isBuffer(der)).toBe(true);
    expect(der.length).toBeGreaterThan(0);
  });

  it("produces DER that Node's X509Certificate can parse", async () => {
    const { cert } = await makeTestCert();
    const der = certToDer(cert);
    const parsed = new X509Certificate(der);
    expect(parsed.subject).toContain("CN=localhost");
  });
});
