import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  loadPfx,
  loadPemPair,
  exportPfx,
  exportPem,
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

async function makeExpiredCert(): ReturnType<typeof generateCertificate> {
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
  it("round-trips a PFX written by exportPfx and recovers the thumbprint", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    await exportPfx(cert, key, dir);
    const loaded = await loadPfx(path.join(dir, "aspnetcore-dev.pfx"));
    // LoadedCert.thumbprint is the SHA-1 (.NET-compatible) form; both that
    // and the SHA-256 `cert.thumbprint` should round-trip through the PFX.
    expect(loaded.thumbprint).toBe(thumbprint);
    expect(loaded.cert.thumbprintSha1).toBe(thumbprint);
    expect(loaded.cert.thumbprint).toBe(cert.thumbprint);
    expect(loaded.key).not.toBeNull();
    expect(loaded.isExpired).toBe(false);
    expect(loaded.cert.subjectCN).toBe("localhost");
  });

  it("accepts a password-protected PFX", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    await exportPfx(cert, key, dir, "hunter2");
    const loaded = await loadPfx(
      path.join(dir, "aspnetcore-dev.pfx"),
      "hunter2"
    );
    expect(loaded.thumbprint).toBe(thumbprint);
  });

  it("round-trips an ECDSA P-256 cert+key", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key, thumbprint } = await generateCertificate(now, expiry, {
      kind: "ec",
      namedCurve: "P-256",
    });
    const dir = tmpDir();
    cleanupDirs.push(dir);

    await exportPfx(cert, key, dir);
    const loaded = await loadPfx(path.join(dir, "aspnetcore-dev.pfx"));
    expect(loaded.thumbprint).toBe(thumbprint);
    expect(loaded.key).not.toBeNull();
    expect(loaded.key!.algorithm).toBe("ec");
  });

  it("round-trips an Ed25519 cert+key", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key, thumbprint } = await generateCertificate(now, expiry, {
      kind: "ed25519",
    });
    const dir = tmpDir();
    cleanupDirs.push(dir);

    await exportPfx(cert, key, dir);
    const loaded = await loadPfx(path.join(dir, "aspnetcore-dev.pfx"));
    expect(loaded.thumbprint).toBe(thumbprint);
    expect(loaded.key).not.toBeNull();
    expect(loaded.key!.algorithm).toBe("ed25519");
  });
});

describe("loadPemPair", () => {
  it("loads a cert + key pair", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath, keyPath } = exportPem(cert, key, dir);
    const loaded = loadPemPair(certPath, keyPath);
    expect(loaded.thumbprint).toBe(thumbprint);
    expect(loaded.key).not.toBeNull();
    expect(loaded.isExpired).toBe(false);
  });

  it("loads an EC cert + key pair", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key } = await generateCertificate(now, expiry, {
      kind: "ec",
      namedCurve: "P-256",
    });
    const dir = tmpDir();
    cleanupDirs.push(dir);
    const { certPath, keyPath } = exportPem(cert, key, dir);

    const loaded = loadPemPair(certPath, keyPath);
    expect(loaded.key).not.toBeNull();
    expect(loaded.key!.algorithm).toBe("ec");
  });

  it("loads a CA-only PEM (no key path supplied)", async () => {
    const { cert, key } = await makeTestCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { certPath } = exportPem(cert, key, dir);
    const loaded = loadPemPair(certPath);
    expect(loaded.key).toBeNull();
    expect(loaded.cert.subjectCN).toBe("localhost");
  });

  it("flags expired certificates via isExpired", async () => {
    const { cert, key } = await makeExpiredCert();
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const certPath = path.join(dir, "expired.pem");
    const keyPath = path.join(dir, "expired.key");
    fs.writeFileSync(certPath, cert.pem);
    fs.writeFileSync(keyPath, key.pem);

    const loaded = loadPemPair(certPath, keyPath);
    expect(loaded.isExpired).toBe(true);
  });
});
