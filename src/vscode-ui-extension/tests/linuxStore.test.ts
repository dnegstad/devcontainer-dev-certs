import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type * as Shared from "@devcontainer-dev-certs/shared";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";
import { parsePfx } from "../src/cert/pfx";

// Mock runProcess so tests don't need an actual openssl binary.
vi.mock("../src/platform/processUtil", () => ({
  runProcess: vi.fn().mockResolvedValue({
    exitCode: 0,
    stdout: "abcd1234\n",
    stderr: "",
  }),
}));

// Override the shared paths to point at temp directories.
let testStoreDir: string;
let testRootStoreDir: string;
let testTrustDir: string;

vi.mock("@devcontainer-dev-certs/shared", async (importOriginal) => {
  const original = await importOriginal<typeof Shared>();
  return {
    ...original,
    getDotNetStorePath: () => testStoreDir,
    getDotNetRootStorePath: () => testRootStoreDir,
    getOpenSslTrustDir: () => testTrustDir,
  };
});

import { LinuxCertificateStore } from "../src/platform/linuxStore";
import { runProcess } from "../src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

async function makeTestCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

describe("LinuxCertificateStore", () => {
  let store: LinuxCertificateStore;
  let tmpDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-test-"));
    testStoreDir = path.join(tmpDir, "x509stores", "my");
    testRootStoreDir = path.join(tmpDir, "x509stores", "root");
    testTrustDir = path.join(tmpDir, "trust");
    store = new LinuxCertificateStore();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("saveCertificate", () => {
    it("writes a PFX to the .NET store directory", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);

      const pfxPath = path.join(testStoreDir, `${thumbprint}.pfx`);
      expect(fs.existsSync(pfxPath)).toBe(true);

      const pfxBytes = fs.readFileSync(pfxPath);
      const parsed = await parsePfx(pfxBytes);
      expect(parsed.cert.thumbprint).toBe(thumbprint);
      expect(parsed.key).not.toBeNull();
    });

    it("creates the store directory if it does not exist", async () => {
      expect(fs.existsSync(testStoreDir)).toBe(false);
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      expect(fs.existsSync(testStoreDir)).toBe(true);
    });
  });

  describe("trustCertificate", () => {
    it("writes a PFX to the .NET Root store", async () => {
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);

      const pfxPath = path.join(testRootStoreDir, `${thumbprint}.pfx`);
      expect(fs.existsSync(pfxPath)).toBe(true);
    });

    it("writes a PEM to the OpenSSL trust directory", async () => {
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);

      const pemPath = path.join(
        testTrustDir,
        `aspnetcore-localhost-${thumbprint}.pem`
      );
      expect(fs.existsSync(pemPath)).toBe(true);

      const content = fs.readFileSync(pemPath, "utf-8");
      expect(content).toContain("-----BEGIN CERTIFICATE-----");
    });

    it("creates hash symlinks via openssl", async () => {
      mockedRunProcess.mockResolvedValue({
        exitCode: 0,
        stdout: "a1b2c3d4\n",
        stderr: "",
      });

      const { cert } = await makeTestCert();
      await store.trustCertificate(cert);

      const symlinkPath = path.join(testTrustDir, "a1b2c3d4.0");
      expect(fs.existsSync(symlinkPath)).toBe(true);
      expect(fs.lstatSync(symlinkPath).isSymbolicLink()).toBe(true);
    });

    it("calls openssl x509 -hash to compute the subject hash", async () => {
      const { cert } = await makeTestCert();
      await store.trustCertificate(cert);

      expect(mockedRunProcess).toHaveBeenCalledWith(
        "openssl",
        expect.arrayContaining(["x509", "-hash", "-noout", "-in"])
      );
    });

    it("root store PFX contains only the public cert (no private key)", async () => {
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);

      const pfxPath = path.join(testRootStoreDir, `${thumbprint}.pfx`);
      const pfxBytes = fs.readFileSync(pfxPath);
      const parsed = await parsePfx(pfxBytes);
      expect(parsed.cert.thumbprint).toBe(thumbprint);
      expect(parsed.key).toBeNull();
    });
  });

  describe("isTrusted", () => {
    it("returns true when PEM exists in trust directory", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      const status = await store.checkStatus();
      expect(status.isTrusted).toBe(true);
    });

    it("returns false when PEM does not exist", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);

      const status = await store.checkStatus();
      expect(status.isTrusted).toBe(false);
    });
  });

  describe("findExistingDevCert", () => {
    it("finds a previously saved certificate", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);

      const found = await store.findExistingDevCert();
      expect(found).not.toBeNull();
      expect(found!.thumbprint).toBe(thumbprint);
    });

    it("returns null when store directory is empty", async () => {
      const found = await store.findExistingDevCert();
      expect(found).toBeNull();
    });
  });

  describe("removeCertificates", () => {
    it("removes PFX from .NET store", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);

      const pfxPath = path.join(testStoreDir, `${thumbprint}.pfx`);
      expect(fs.existsSync(pfxPath)).toBe(true);

      await store.removeCertificates();
      expect(fs.existsSync(pfxPath)).toBe(false);
    });

    it("removes PEM and hash symlinks from trust directory", async () => {
      mockedRunProcess.mockResolvedValue({
        exitCode: 0,
        stdout: "a1b2c3d4\n",
        stderr: "",
      });

      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      const pemPath = path.join(
        testTrustDir,
        `aspnetcore-localhost-${thumbprint}.pem`
      );
      const symlinkPath = path.join(testTrustDir, "a1b2c3d4.0");
      expect(fs.existsSync(pemPath)).toBe(true);
      expect(fs.existsSync(symlinkPath)).toBe(true);

      await store.removeCertificates();
      expect(fs.existsSync(pemPath)).toBe(false);
      expect(fs.existsSync(symlinkPath)).toBe(false);
    });

    it("handles non-existent directories gracefully", async () => {
      await expect(store.removeCertificates()).resolves.toBeUndefined();
    });
  });

  describe("checkStatus", () => {
    it("returns full status for a saved and trusted cert", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      const status = await store.checkStatus();
      expect(status.exists).toBe(true);
      expect(status.isTrusted).toBe(true);
      expect(status.thumbprint).toBe(thumbprint);
      expect(status.notBefore).toBeDefined();
      expect(status.notAfter).toBeDefined();
      expect(status.version).toBeGreaterThanOrEqual(0);
    });

    it("returns not-exists when store is empty", async () => {
      const status = await store.checkStatus();
      expect(status.exists).toBe(false);
      expect(status.isTrusted).toBe(false);
      expect(status.thumbprint).toBeNull();
    });
  });
});
