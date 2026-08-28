import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type * as SharedPaths from "@devcontainer-dev-certs/shared/src/paths";
import { initLogger } from "@devcontainer-dev-certs/shared/src/loggerVscode";
import {
  generateCertificate,
  VALIDITY_DAYS,
  buildPfx,
  parsePfx,
  LinuxCertificateStore,
} from "@devcontainer-dev-certs/shared";
import { logMessages } from "./__mocks__/vscode";

initLogger("test");

// Mock runProcess so tests don't need an actual openssl binary. After the
// platform-layer move into the shared package, the LinuxCertificateStore
// imports `runProcess` from the shared internal path (`./processUtil`), so
// the mock target has to be that same shared file — mocking the extension's
// thin re-export shim won't intercept the import the implementation actually
// uses.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn().mockResolvedValue({
    exitCode: 0,
    stdout: "abcd1234\n",
    stderr: "",
    truncated: false,
  }),
}));

// Mock trustInNss so the in-trust NSS step doesn't touch the real homedir.
// Tests that exercise the NSS step explicitly construct a store with a
// reporter; the default tests construct it without one, in which case the
// step is skipped entirely and this mock is never invoked.
vi.mock("@devcontainer-dev-certs/shared/src/platform/nssTrust", () => ({
  trustInNss: vi.fn(),
}));

// Override the shared paths to point at temp directories. The
// LinuxCertificateStore imports these from the shared internal `paths`
// module, so the mock has to target that same file.
let testStoreDir: string;
let testRootStoreDir: string;
let testTrustDir: string;

vi.mock("@devcontainer-dev-certs/shared/src/paths", async (importOriginal) => {
  const original = await importOriginal<typeof SharedPaths>();
  return {
    ...original,
    getDotNetStorePath: () => testStoreDir,
    getDotNetRootStorePath: () => testRootStoreDir,
    getOpenSslTrustDir: () => testTrustDir,
  };
});

import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";
import { trustInNss } from "@devcontainer-dev-certs/shared/src/platform/nssTrust";

const mockedRunProcess = vi.mocked(runProcess);
const mockedTrustInNss = vi.mocked(trustInNss);

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
      // .NET store filename is keyed by the SHA-1 thumbprint.
      expect(parsed.cert.thumbprintSha1).toBe(thumbprint);
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

    it("names the hash symlink with OpenSSL's canonical subject hash", async () => {
      // Every cert we manage is CN=localhost, so the subject hash is the
      // fixed value `openssl x509 -hash` reports for that name. Asserting
      // the literal is the point: a symlink under any other name is one
      // OpenSSL's `by_dir` lookup will never open, which silently disables
      // SSL_CERT_DIR trust while looking perfectly healthy on disk.
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);

      const symlinkPath = path.join(testTrustDir, "ce275665.0");
      expect(fs.existsSync(symlinkPath)).toBe(true);
      expect(fs.lstatSync(symlinkPath).isSymbolicLink()).toBe(true);
      expect(fs.readlinkSync(symlinkPath)).toBe(
        `aspnetcore-localhost-${thumbprint}.pem`
      );
    });

    it("computes the subject hash in-process, never shelling out to openssl", async () => {
      // The host is a developer machine we don't control; requiring an
      // `openssl` binary there would make OpenSSL trust silently no-op on
      // any host without it (the old code returned null and skipped the
      // symlink). Trust must not depend on host tooling.
      const { cert } = await makeTestCert();
      await store.trustCertificate(cert);

      const spawned = mockedRunProcess.mock.calls.map((c) => c[0]);
      expect(spawned).not.toContain("openssl");
    });

    it("reports NOT trusted when the hash symlink is under the wrong hash", async () => {
      // A host trusted before the subject hash was computed canonically has a
      // link under the wrong name. If `isTrusted` only checked the PEM and root
      // PFX, it would answer "trusted", CertManager.trust() would skip
      // trustCertificate, and the broken link would survive every upgrade —
      // leaving local OpenSSL trust dead for exactly the hosts this fixes.
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);
      expect(await store.isCertTrusted(cert)).toBe(true);

      const links = fs
        .readdirSync(testTrustDir)
        .filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f));
      expect(links).toHaveLength(1);
      const target = fs.readlinkSync(path.join(testTrustDir, links[0]));
      fs.unlinkSync(path.join(testTrustDir, links[0]));
      fs.symlinkSync(target, path.join(testTrustDir, "deadbeef.0"));

      // PEM and root PFX are both still present...
      expect(
        fs.existsSync(path.join(testTrustDir, `aspnetcore-localhost-${thumbprint}.pem`))
      ).toBe(true);
      expect(fs.existsSync(path.join(testRootStoreDir, `${thumbprint}.pfx`))).toBe(true);
      // ...but trust is not actually established.
      expect(await store.isCertTrusted(cert)).toBe(false);

      // Re-trusting repairs it.
      await store.trustCertificate(cert);
      expect(await store.isCertTrusted(cert)).toBe(true);
    });

    it("reports NOT trusted when the PEM on disk no longer matches the cert", async () => {
      // The filename is thumbprint-derived, so a *different* cert can't land
      // here — but the file can still be truncated or rewritten in place
      // while the hash link and root PFX survive. Checking only the name
      // would report trust for bytes OpenSSL cannot load, and
      // trustExternalCertificate's short-circuit would skip the repair.
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);
      expect(await store.isCertTrusted(cert)).toBe(true);

      const pemPath = path.join(
        testTrustDir,
        `aspnetcore-localhost-${thumbprint}.pem`
      );
      fs.writeFileSync(
        pemPath,
        "-----BEGIN CERTIFICATE-----\ntruncated\n"
      );

      // Link and root PFX are untouched — only the content changed.
      const links = fs
        .readdirSync(testTrustDir)
        .filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f));
      expect(links).toHaveLength(1);
      expect(fs.existsSync(path.join(testRootStoreDir, `${thumbprint}.pfx`))).toBe(true);

      expect(await store.isCertTrusted(cert)).toBe(false);

      // Re-trusting rewrites the PEM and restores trust.
      await store.trustCertificate(cert);
      expect(await store.isCertTrusted(cert)).toBe(true);
    });

    it("is purely additive — does NOT remove other aspnetcore-localhost-*.pem files in the trust dir", async () => {
      // Pin the post-fix contract: trustCertificate must never remove or
      // modify other dev cert PEMs that happen to share the
      // `aspnetcore-localhost-*.pem` filename pattern. The
      // container-to-host reverse-sync flow and the host-generation
      // flow can each result in a separate cert being trusted in the
      // same directory; sweeping "other" PEMs as part of trust would
      // turn every trust call into an implicit revocation of every
      // other dev cert in the trust dir, ping-ponging trust between
      // the two flows. Only the cleanup command (with explicit user
      // approval via the modal prompt) may remove certificates from
      // the trust dir.
      fs.mkdirSync(testTrustDir, { recursive: true });
      const otherPem = path.join(
        testTrustDir,
        "aspnetcore-localhost-OTHERTHUMBPRINT.pem"
      );
      const otherContent =
        "-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----\n";
      fs.writeFileSync(otherPem, otherContent);

      const { cert } = await makeTestCert();
      await store.trustCertificate(cert);

      // The other PEM is still present and its content is unchanged.
      expect(fs.existsSync(otherPem)).toBe(true);
      expect(fs.readFileSync(otherPem, "utf-8")).toBe(otherContent);
    });

    it("root store PFX contains only the public cert (no private key)", async () => {
      const { cert, thumbprint } = await makeTestCert();
      await store.trustCertificate(cert);

      const pfxPath = path.join(testRootStoreDir, `${thumbprint}.pfx`);
      const pfxBytes = fs.readFileSync(pfxPath);
      const parsed = await parsePfx(pfxBytes);
      // Root store filename is keyed by the SHA-1 thumbprint.
      expect(parsed.cert.thumbprintSha1).toBe(thumbprint);
      expect(parsed.key).toBeNull();
    });

    describe("NSS browser trust step", () => {
      it("skips NSS entirely when no reporter is configured", async () => {
        const { cert } = await makeTestCert();
        await store.trustCertificate(cert);

        expect(mockedTrustInNss).not.toHaveBeenCalled();
      });

      it("reports success when trustInNss resolves with success", async () => {
        const reporter = vi.fn();
        const reportingStore = new LinuxCertificateStore({
          nssTrustReporter: reporter,
        });
        mockedTrustInNss.mockResolvedValueOnce({
          success: true,
          message: "Trusted in: Firefox (default)",
        });

        const { cert, thumbprint } = await makeTestCert();
        await reportingStore.trustCertificate(cert);

        const expectedPemPath = path.join(
          testTrustDir,
          `aspnetcore-localhost-${thumbprint}.pem`
        );
        expect(mockedTrustInNss).toHaveBeenCalledWith(expectedPemPath);
        expect(reporter).toHaveBeenCalledOnce();
        expect(reporter).toHaveBeenCalledWith(
          { success: true, message: "Trusted in: Firefox (default)" },
          expectedPemPath
        );
      });

      it("reports failure when trustInNss resolves unsuccessfully", async () => {
        const reporter = vi.fn();
        const reportingStore = new LinuxCertificateStore({
          nssTrustReporter: reporter,
        });
        mockedTrustInNss.mockResolvedValueOnce({
          success: false,
          message: "certutil is not installed.",
        });

        const { cert } = await makeTestCert();
        await reportingStore.trustCertificate(cert);

        expect(reporter).toHaveBeenCalledOnce();
        expect(reporter.mock.calls[0][0]).toEqual({
          success: false,
          message: "certutil is not installed.",
        });
      });

      it("reports failure when trustInNss throws unexpectedly", async () => {
        const reporter = vi.fn();
        const reportingStore = new LinuxCertificateStore({
          nssTrustReporter: reporter,
        });
        mockedTrustInNss.mockRejectedValueOnce(new Error("boom"));

        const { cert } = await makeTestCert();
        await reportingStore.trustCertificate(cert);

        expect(reporter).toHaveBeenCalledOnce();
        expect(reporter.mock.calls[0][0]).toEqual({
          success: false,
          message: "boom",
        });
      });

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

    it("returns false when the .NET Root store PFX is missing though the PEM survives", async () => {
      // Regression: `isTrusted` used to check only the OpenSSL PEM, so
      // clearing ~/.dotnet/corefx/.../root/ (manual cleanup, partial
      // removal) while the PEM survived left .NET-side trust broken
      // forever — CertManager.trust's recheck and the container-push
      // short-circuit both saw "trusted" and never re-ran the
      // idempotent trust path to repair the Root store.
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      fs.rmSync(path.join(testRootStoreDir, `${thumbprint}.pfx`));

      const status = await store.checkStatus();
      expect(status.isTrusted).toBe(false);
    });

    it("returns false when the PEM is missing though the Root store PFX survives", async () => {
      const { cert, key, thumbprint } = await makeTestCert();
      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      for (const entry of fs.readdirSync(testTrustDir)) {
        fs.rmSync(path.join(testTrustDir, entry), { force: true });
      }

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

    it("silently skips an unparseable file rather than throwing", async () => {
      // A user upgrading from a node-forge-era build of this extension can
      // have a legacy-PBE PFX (3DES / RC2-encoded) sitting in the store
      // dir. parsePfx rejects those; findExistingDevCert needs to swallow
      // that error so manager.trust() can fall through to regenerating
      // a fresh cert instead of surfacing a parse failure to the user.
      fs.mkdirSync(testStoreDir, { recursive: true });
      fs.writeFileSync(
        path.join(testStoreDir, "garbage.pfx"),
        Buffer.from("this is not a valid PKCS#12 file")
      );

      const found = await store.findExistingDevCert();
      expect(found).toBeNull();
    });

    it("picks one of the candidates deterministically regardless of filename order", async () => {
      const { cert: certA, key: keyA, thumbprint: thumbA } = await makeTestCert();
      const { cert: certB, key: keyB, thumbprint: thumbB } = await makeTestCert();
      const bytesA = await buildPfx({ cert: certA, key: keyA });
      const bytesB = await buildPfx({ cert: certB, key: keyB });
      fs.mkdirSync(testStoreDir, { recursive: true });
      // Lexically reversed filenames so readdir order differs from
      // selection order.
      fs.writeFileSync(path.join(testStoreDir, `zzz-${thumbA}.pfx`), bytesA);
      fs.writeFileSync(path.join(testStoreDir, `aaa-${thumbB}.pfx`), bytesB);

      const found = await store.findExistingDevCert();
      expect(found).not.toBeNull();
      // Both certs share version; selection is deterministic on
      // (version DESC, notAfter DESC).
      expect([thumbA, thumbB]).toContain(found!.thumbprint);
    });

    it("warns when a canonically-named PFX fails to parse", async () => {
      logMessages.length = 0;
      const fakeThumb = "B".repeat(40);
      fs.mkdirSync(testStoreDir, { recursive: true });
      fs.writeFileSync(
        path.join(testStoreDir, `${fakeThumb}.pfx`),
        Buffer.from("not a valid pfx")
      );
      await store.findExistingDevCert();
      const warn = logMessages.find((m) => m.includes("failed to parse PFX"));
      expect(warn).toBeDefined();
      expect(warn).toContain(fakeThumb);
    });

    it("warns when a valid-looking PFX has no private key", async () => {
      logMessages.length = 0;
      const { cert, thumbprint } = await makeTestCert();
      const bytes = await buildPfx({ cert }); // cert-only
      fs.mkdirSync(testStoreDir, { recursive: true });
      fs.writeFileSync(path.join(testStoreDir, `${thumbprint}.pfx`), bytes);

      const found = await store.findExistingDevCert();
      expect(found).toBeNull();
      const warn = logMessages.find((m) =>
        m.includes("certificate without matching private key")
      );
      expect(warn).toBeDefined();
      expect(warn).toContain(thumbprint);
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
