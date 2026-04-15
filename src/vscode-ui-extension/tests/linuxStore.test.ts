import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as forge from "node-forge";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

// Mock runProcess so tests don't need actual openssl binary
vi.mock("../src/platform/processUtil", () => ({
  runProcess: vi.fn().mockResolvedValue({
    exitCode: 0,
    stdout: "abcd1234\n",
    stderr: "",
  }),
}));

// Mock shared paths to use temp directories
let testStoreDir: string;
let testTrustDir: string;

vi.mock("@devcontainer-dev-certs/shared", async (importOriginal) => {
  const original =
    (await importOriginal()) as typeof import("@devcontainer-dev-certs/shared");
  return {
    ...original,
    getDotNetStorePath: () => testStoreDir,
    getOpenSslTrustDir: () => testTrustDir,
  };
});

import { LinuxCertificateStore } from "../src/platform/linuxStore";
import { runProcess } from "../src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

function makeTestCert() {
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
    testTrustDir = path.join(tmpDir, "trust");
    store = new LinuxCertificateStore();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("saveCertificate", () => {
    it("writes a PFX to the .NET store directory", async () => {
      const { cert, key, thumbprint } = makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);

      const pfxPath = path.join(testStoreDir, `${thumbprint}.pfx`);
      expect(fs.existsSync(pfxPath)).toBe(true);

      // Verify it's a valid PFX that can be parsed back
      const pfxBytes = fs.readFileSync(pfxPath);
      const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
      const p12Asn1 = forge.asn1.fromDer(p12Der);
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, "");
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
      expect(certBags[forge.pki.oids.certBag]?.length).toBeGreaterThan(0);
    });

    it("creates the store directory if it does not exist", async () => {
      expect(fs.existsSync(testStoreDir)).toBe(false);
      const { cert, key, thumbprint } = makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      expect(fs.existsSync(testStoreDir)).toBe(true);
    });
  });

  describe("trustCertificate", () => {
    it("writes a PFX to the .NET Root store", async () => {
      const { cert, thumbprint } = makeTestCert();
      await store.trustCertificate(cert);

      const rootDir = path.resolve(testStoreDir, "..", "root");
      const pfxPath = path.join(rootDir, `${thumbprint}.pfx`);
      expect(fs.existsSync(pfxPath)).toBe(true);
    });

    it("writes a PEM to the OpenSSL trust directory", async () => {
      const { cert, thumbprint } = makeTestCert();
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

      const { cert } = makeTestCert();
      await store.trustCertificate(cert);

      const symlinkPath = path.join(testTrustDir, "a1b2c3d4.0");
      expect(fs.existsSync(symlinkPath)).toBe(true);
      expect(fs.lstatSync(symlinkPath).isSymbolicLink()).toBe(true);
    });

    it("calls openssl x509 -hash to compute the subject hash", async () => {
      const { cert } = makeTestCert();
      await store.trustCertificate(cert);

      expect(mockedRunProcess).toHaveBeenCalledWith(
        "openssl",
        expect.arrayContaining(["x509", "-hash", "-noout", "-in"]),
      );
    });

    it("root store PFX contains only the public cert (no private key)", async () => {
      const { cert, thumbprint } = makeTestCert();
      await store.trustCertificate(cert);

      const rootDir = path.resolve(testStoreDir, "..", "root");
      const pfxPath = path.join(rootDir, `${thumbprint}.pfx`);
      const pfxBytes = fs.readFileSync(pfxPath);
      const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
      const p12Asn1 = forge.asn1.fromDer(p12Der);
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, "");

      // Should have a cert bag
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
      expect(certBags[forge.pki.oids.certBag]?.length).toBeGreaterThan(0);

      // Should NOT have a private key bag
      const keyBags = p12.getBags({
        bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
      });
      const keys = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [];
      expect(keys.length).toBe(0);
    });
  });

  describe("isTrusted", () => {
    it("returns true when PEM exists in trust directory", async () => {
      const { cert, key, thumbprint } = makeTestCert();
      // Save and trust the cert first
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      const status = await store.checkStatus();
      expect(status.isTrusted).toBe(true);
    });

    it("returns false when PEM does not exist", async () => {
      const { cert, key, thumbprint } = makeTestCert();
      // Save but don't trust
      await store.saveCertificate(cert, key, thumbprint);

      const status = await store.checkStatus();
      expect(status.isTrusted).toBe(false);
    });
  });

  describe("findExistingDevCert", () => {
    it("finds a previously saved certificate", async () => {
      const { cert, key, thumbprint } = makeTestCert();
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
      const { cert, key, thumbprint } = makeTestCert();
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

      const { cert, key, thumbprint } = makeTestCert();
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

    it("does not remove root store PFX (public-cert-only PFX lacks private key for parsing)", async () => {
      const { cert, key, thumbprint } = makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      const rootDir = path.resolve(testStoreDir, "..", "root");
      const pfxPath = path.join(rootDir, `${thumbprint}.pfx`);
      expect(fs.existsSync(pfxPath)).toBe(true);

      await store.removeCertificates();
      // Root store PFX contains no private key, so loadPfx returns null
      // and removeDevCertsFromDir skips it. This is a known limitation.
      expect(fs.existsSync(pfxPath)).toBe(true);
    });

    it("handles non-existent directories gracefully", async () => {
      // Should not throw when directories don't exist
      await expect(store.removeCertificates()).resolves.toBeUndefined();
    });
  });

  describe("checkStatus", () => {
    it("returns full status for a saved and trusted cert", async () => {
      const { cert, key, thumbprint } = makeTestCert();
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
