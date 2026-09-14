import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  exportLoadedCert,
  exportPem,
  loadPemPair,
  generateCertificate,
  VALIDITY_DAYS,
} from "@devcontainer-dev-certs/shared";

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
  it("writes pem, key, and root pfx when includeRootPfx is true", async () => {
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
    expect(result.rootPfxPath).toBe(path.join(outDir, "corp-ca-root.pfx"));
    expect(fs.existsSync(result.pemCertPath)).toBe(true);
    expect(fs.existsSync(result.pemKeyPath!)).toBe(true);
    expect(fs.existsSync(result.rootPfxPath!)).toBe(true);
    // PFX-with-key synthesis intentionally moved out of exportLoadedCert
    // so the password decision lives next to pfxPassword in certProvider.
    expect(fs.existsSync(path.join(outDir, "corp-ca.pfx"))).toBe(false);
  });

  it("skips PEM key when the loaded cert has no private key", async () => {
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
    expect(result.rootPfxPath).toBeNull();
    expect(fs.existsSync(result.pemCertPath)).toBe(true);
  });

  it("writes the PEM artifacts for an EC-keyed cert", async () => {
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

    expect(fs.existsSync(result.pemCertPath)).toBe(true);
    expect(fs.existsSync(result.pemKeyPath!)).toBe(true);
  });
});
