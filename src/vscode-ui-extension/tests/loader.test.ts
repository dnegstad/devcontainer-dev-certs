import { describe, it, expect, afterEach } from "vitest";
import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadPfx, loadPemPair } from "../src/cert/loader";
import { exportPfx, exportPem } from "../src/cert/exporter";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

function makeTestCert() {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

function makeExpiredCert() {
  const notBefore = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const notAfter = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000);
  return generateCertificate(notBefore, notAfter);
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-loader-test-"));
}

const cleanupDirs: string[] = [];
afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

describe("loadPfx", () => {
  it("round-trips a PFX written by exportPfx and recovers the thumbprint", () => {
    const { cert, key, thumbprint } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    exportPfx(cert, key, dir);
    const loaded = loadPfx(path.join(dir, "aspnetcore-dev.pfx"));
    expect(loaded.thumbprint).toBe(thumbprint);
    expect(loaded.key).not.toBeNull();
    expect(loaded.isExpired).toBe(false);
    expect(loaded.cert.subject.getField("CN")!.value).toBe("localhost");
  });

  it("accepts a password-protected PFX", () => {
    const { cert, key, thumbprint } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    exportPfx(cert, key, dir, "hunter2");
    const loaded = loadPfx(path.join(dir, "aspnetcore-dev.pfx"), "hunter2");
    expect(loaded.thumbprint).toBe(thumbprint);
  });
});

describe("loadPemPair", () => {
  it("loads a cert + key pair", () => {
    const { cert, key, thumbprint } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath, keyPath } = exportPem(cert, key, dir);
    const loaded = loadPemPair(certPath, keyPath);
    expect(loaded.thumbprint).toBe(thumbprint);
    expect(loaded.key).not.toBeNull();
    expect(loaded.isExpired).toBe(false);
  });

  it("loads a CA-only PEM (no key path supplied)", () => {
    const { cert, key } = makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath } = exportPem(cert, key, dir);
    const loaded = loadPemPair(certPath);
    expect(loaded.key).toBeNull();
    expect(loaded.cert.subject.getField("CN")!.value).toBe("localhost");
  });

  it("flags expired certificates via isExpired", () => {
    const { cert, key } = makeExpiredCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    // exportPem's round-trip is fine even for expired certs.
    const certPath = path.join(dir, "expired.pem");
    const keyPath = path.join(dir, "expired.key");
    fs.writeFileSync(certPath, forge.pki.certificateToPem(cert));
    fs.writeFileSync(keyPath, forge.pki.privateKeyToPem(key));

    const loaded = loadPemPair(certPath, keyPath);
    expect(loaded.isExpired).toBe(true);
  });
});
