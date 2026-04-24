import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { exportLoadedCert } from "../src/cert/exporter";
import { loadPemPair } from "../src/cert/loader";
import { exportPem } from "../src/cert/exporter";
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
  return fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-export-test-"));
}

const cleanupDirs: string[] = [];
afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

describe("exportLoadedCert", () => {
  it("writes pem, key, pfx, and root pfx when includeRootPfx is true", () => {
    const { cert, key } = makeTestCert();
    const exportDir = tmpDir();
    cleanupDirs.push(exportDir);
    const { certPath, keyPath } = exportPem(cert, key, exportDir);
    const loaded = loadPemPair(certPath, keyPath);

    const outDir = tmpDir();
    cleanupDirs.push(outDir);
    const result = exportLoadedCert(loaded, "corp-ca", outDir, {
      includeRootPfx: true,
    });

    expect(result.pemCertPath).toBe(path.join(outDir, "corp-ca.pem"));
    expect(result.pemKeyPath).toBe(path.join(outDir, "corp-ca.key"));
    expect(result.pfxPath).toBe(path.join(outDir, "corp-ca.pfx"));
    expect(result.rootPfxPath).toBe(path.join(outDir, "corp-ca-root.pfx"));
    expect(fs.existsSync(result.pemCertPath)).toBe(true);
    expect(fs.existsSync(result.pemKeyPath!)).toBe(true);
    expect(fs.existsSync(result.pfxPath!)).toBe(true);
    expect(fs.existsSync(result.rootPfxPath!)).toBe(true);
  });

  it("skips PFX artifacts when the loaded cert has no private key", () => {
    const { cert, key } = makeTestCert();
    const exportDir = tmpDir();
    cleanupDirs.push(exportDir);
    const { certPath } = exportPem(cert, key, exportDir);
    const loaded = loadPemPair(certPath);

    const outDir = tmpDir();
    cleanupDirs.push(outDir);
    const result = exportLoadedCert(loaded, "ca-only", outDir);

    expect(result.pemCertPath).toBe(path.join(outDir, "ca-only.pem"));
    expect(result.pemKeyPath).toBeNull();
    expect(result.pfxPath).toBeNull();
    expect(result.rootPfxPath).toBeNull();
    expect(fs.existsSync(result.pemCertPath)).toBe(true);
  });
});
