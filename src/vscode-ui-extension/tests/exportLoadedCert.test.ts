import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { exportLoadedCert, exportPem } from "../src/cert/exporter";
import { loadPemPair } from "../src/cert/loader";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

async function makeTestCert(): ReturnType<typeof generateCertificate> {
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
  it("writes pem, key, pfx, and root pfx when includeRootPfx is true", async () => {
    const { cert, key } = await makeTestCert();
    const exportDir = tmpDir();
    cleanupDirs.push(exportDir);
    const { certPath, keyPath } = exportPem(cert, key, exportDir);
    const loaded = loadPemPair(certPath, keyPath);

    const outDir = tmpDir();
    cleanupDirs.push(outDir);
    const result = await exportLoadedCert(loaded, "corp-ca", outDir, {
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

  it("skips PFX artifacts when the loaded cert has no private key", async () => {
    const { cert, key } = await makeTestCert();
    const exportDir = tmpDir();
    cleanupDirs.push(exportDir);
    const { certPath } = exportPem(cert, key, exportDir);
    const loaded = loadPemPair(certPath);

    const outDir = tmpDir();
    cleanupDirs.push(outDir);
    const result = await exportLoadedCert(loaded, "ca-only", outDir);

    expect(result.pemCertPath).toBe(path.join(outDir, "ca-only.pem"));
    expect(result.pemKeyPath).toBeNull();
    expect(result.pfxPath).toBeNull();
    expect(result.rootPfxPath).toBeNull();
    expect(fs.existsSync(result.pemCertPath)).toBe(true);
  });

  it("round-trips an EC-keyed user cert", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key } = await generateCertificate(now, expiry, {
      kind: "ec",
      namedCurve: "P-256",
    });

    const exportDir = tmpDir();
    cleanupDirs.push(exportDir);
    const { certPath, keyPath } = exportPem(cert, key, exportDir);
    const loaded = loadPemPair(certPath, keyPath);

    const outDir = tmpDir();
    cleanupDirs.push(outDir);
    const result = await exportLoadedCert(loaded, "ec-cert", outDir);

    expect(fs.existsSync(result.pfxPath!)).toBe(true);
  });
});
