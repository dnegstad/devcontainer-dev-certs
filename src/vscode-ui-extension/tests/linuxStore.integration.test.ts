import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { execFileSync } from "child_process";
import {
  LinuxCertificateStore,
  generateCertificate,
  VALIDITY_DAYS,
  buildPfx,
  getPemFileName,
} from "@devcontainer-dev-certs/shared";

let opensslAvailable = false;
try {
  execFileSync("openssl", ["version"], { timeout: 5000 });
  opensslAvailable = true;
} catch {
  // openssl not available
}

let testStoreDir: string;
let testTrustDir: string;
let tmpDir: string;

async function makeTestCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

describe.skipIf(!opensslAvailable)(
  "LinuxCertificateStore (integration)",
  () => {
    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-integ-"));
      testStoreDir = path.join(tmpDir, "x509stores", "my");
      testTrustDir = path.join(tmpDir, "trust");

      // Read at call time by `getOpenSslTrustDir`, so setting it here is
      // enough — the store module can be imported statically.
      process.env["DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY"] =
        testTrustDir;
    });

    afterEach(() => {
      delete process.env["DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY"];
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("full lifecycle: save → trust → PEM + canonical hash symlink on disk", async () => {
      const store = new LinuxCertificateStore();
      const { cert, key, thumbprint } = await makeTestCert();

      // Save the PFX directly to the store dir using our PFX builder.
      fs.mkdirSync(testStoreDir, { recursive: true });
      const pfxPath = path.join(testStoreDir, `${thumbprint}.pfx`);
      const pfxBytes = await buildPfx({ cert, key });
      fs.writeFileSync(pfxPath, pfxBytes, { mode: 0o600 });

      // Trust — the subject hash is computed in-process; the assertion
      // below cross-checks it against the real openssl binary.
      await store.trustCertificate(cert);

      const pemPath = path.join(testTrustDir, getPemFileName(thumbprint));
      expect(fs.existsSync(pemPath)).toBe(true);
      const pemContent = fs.readFileSync(pemPath, "utf-8");
      expect(pemContent).toContain("-----BEGIN CERTIFICATE-----");

      const entries = fs.readdirSync(testTrustDir);
      const symlinks = entries.filter((e) => /^[0-9a-f]{8}\.\d+$/.test(e));
      expect(symlinks.length).toBeGreaterThan(0);

      const symlinkTarget = fs.readlinkSync(
        path.join(testTrustDir, symlinks[0])
      );
      expect(symlinkTarget).toBe(getPemFileName(thumbprint));

      const expectedHash = execFileSync("openssl", [
        "x509",
        "-hash",
        "-noout",
        "-in",
        pemPath,
      ])
        .toString()
        .trim();
      expect(symlinks[0]).toBe(`${expectedHash}.0`);
    });

    it("trustCertificate creates valid OpenSSL hash symlinks", async () => {
      const store = new LinuxCertificateStore();
      const { cert, thumbprint } = await makeTestCert();

      await store.trustCertificate(cert);

      const pemPath = path.join(testTrustDir, getPemFileName(thumbprint));
      const result = execFileSync("openssl", [
        "verify",
        "-CApath",
        testTrustDir,
        "-partial_chain",
        pemPath,
      ])
        .toString()
        .trim();

      expect(result).toContain("OK");
    });

    it("trustCertificate is idempotent — re-trust replaces symlinks cleanly", async () => {
      const store = new LinuxCertificateStore();
      const { cert } = await makeTestCert();

      await store.trustCertificate(cert);
      await store.trustCertificate(cert);

      const entries = fs.readdirSync(testTrustDir);
      const pems = entries.filter((e) => e.endsWith(".pem"));
      const symlinks = entries.filter((e) => /^[0-9a-f]{8}\.\d+$/.test(e));
      expect(pems.length).toBe(1);
      expect(symlinks.length).toBe(1);
    });

    it("PFX containing the cert is parseable by openssl", async () => {
      const store = new LinuxCertificateStore();
      const { cert, thumbprint } = await makeTestCert();

      await store.trustCertificate(cert);

      const pemPath = path.join(testTrustDir, getPemFileName(thumbprint));
      expect(fs.existsSync(pemPath)).toBe(true);

      const certInfo = execFileSync("openssl", [
        "x509",
        "-in",
        pemPath,
        "-noout",
        "-subject",
        "-issuer",
      ]).toString();
      expect(certInfo).toContain("localhost");
    });

    it("PEM certificate has correct subject and SAN entries", async () => {
      const store = new LinuxCertificateStore();
      const { cert } = await makeTestCert();

      await store.trustCertificate(cert);

      const entries = fs.readdirSync(testTrustDir);
      const pemFile = entries.find((e) => e.endsWith(".pem"));
      expect(pemFile).toBeDefined();
      const pemPath = path.join(testTrustDir, pemFile!);

      const textOutput = execFileSync("openssl", [
        "x509",
        "-in",
        pemPath,
        "-noout",
        "-text",
      ]).toString();

      expect(textOutput).toContain("DNS:localhost");
      expect(textOutput).toContain("IP Address:127.0.0.1");
      expect(textOutput).toContain("IP Address:0:0:0:0:0:0:0:1");
      expect(textOutput).toContain("CN = localhost");
    });

    it("ECDSA certificate is parseable by openssl", async () => {
      const store = new LinuxCertificateStore();
      const now = new Date();
      const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
      const { cert } = await generateCertificate(now, expiry, {
        kind: "ec",
        namedCurve: "P-256",
      });

      await store.trustCertificate(cert);

      const entries = fs.readdirSync(testTrustDir);
      const pemFile = entries.find((e) => e.endsWith(".pem"));
      expect(pemFile).toBeDefined();
      const pemPath = path.join(testTrustDir, pemFile!);

      const textOutput = execFileSync("openssl", [
        "x509",
        "-in",
        pemPath,
        "-noout",
        "-text",
      ]).toString();
      expect(textOutput).toContain("Public Key Algorithm: id-ecPublicKey");
    });
  }
);
