import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { initLogger } from "@devcontainer-dev-certs/shared/src/loggerVscode";
import { logMessages } from "./__mocks__/vscode";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";
import { buildPfx } from "../src/cert/pfx";

// Mock os.homedir so the macStore points at a writable temp dir.
let testHomeDir = "";
vi.mock("os", async (importOriginal) => {
  const actual = await importOriginal<typeof os>();
  return { ...actual, ...{ homedir: () => testHomeDir } };
});

// Mock runProcess so tests don't shell out to the real `security` CLI.
// Target the shared internal module since MacCertificateStore lives there
// and imports its runProcess via the local `./processUtil`.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

import { MacCertificateStore } from "../src/platform/macStore";
import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

initLogger("test");

async function makeTestCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const exp = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
  return generateCertificate(now, exp);
}

function devCertsDir(): string {
  return path.join(testHomeDir, ".aspnet", "dev-certs", "https");
}

/**
 * Build a security-CLI mock that:
 *  - `find-certificate -Z <thumb>` succeeds for thumbprints in `keychainThumbs`
 *  - `find-certificate -a -p -Z` returns a synthetic PEM block listing every
 *    `extraKeychainPems` entry
 *  - any other call resolves to a benign success
 *  - tracks every command for assertions
 */
function setupSecurityMock(opts: {
  keychainThumbs?: Set<string>;
  extraKeychainPems?: string[];
} = {}) {
  const calls: Array<{ cmd: string; args: readonly string[] }> = [];
  mockedRunProcess.mockImplementation(async (cmd: string, args: readonly string[]) => {
    calls.push({ cmd, args: [...args] });
    if (cmd !== "security") {
      return { exitCode: 0, stdout: "", stderr: "" };
    }
    const sub = args[0];
    if (sub === "find-certificate") {
      // single-thumb lookup
      if (args.includes("-Z") && !args.includes("-a")) {
        const zIdx = args.indexOf("-Z");
        const thumb = args[zIdx + 1];
        const present = opts.keychainThumbs?.has(thumb) ?? false;
        return {
          exitCode: present ? 0 : 1,
          stdout: present ? `SHA-1 hash: ${thumb}\n` : "",
          stderr: present ? "" : "SecKeychainSearchCopyNext: The specified item could not be found",
        };
      }
      // enumerate all
      if (args.includes("-a") && args.includes("-p")) {
        const pems = opts.extraKeychainPems ?? [];
        return {
          exitCode: 0,
          stdout: pems.join("\n"),
          stderr: "",
        };
      }
    }
    return { exitCode: 0, stdout: "", stderr: "" };
  });
  return {
    calls,
    securityExportCalled() {
      return calls.some(
        (c) => c.cmd === "security" && c.args[0] === "export"
      );
    },
  };
}

describe("MacCertificateStore.findExistingDevCert", () => {
  let store: MacCertificateStore;

  beforeEach(() => {
    vi.clearAllMocks();
    logMessages.length = 0;
    testHomeDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-mac-"));
    fs.mkdirSync(devCertsDir(), { recursive: true });
    store = new MacCertificateStore();
  });

  afterEach(() => {
    fs.rmSync(testHomeDir, { recursive: true, force: true });
  });

  it("returns the cert when its thumbprint is present in the keychain", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    const sec = setupSecurityMock({ keychainThumbs: new Set([thumbprint]) });

    const found = await store.findExistingDevCert();
    expect(found?.thumbprint).toBe(thumbprint);
    expect(sec.securityExportCalled()).toBe(false);
  });

  it("excludes a PFX whose cert is NOT in the keychain and logs the orphan warning", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    // Empty keychain — orphaned cache file.
    const sec = setupSecurityMock({ keychainThumbs: new Set() });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();
    expect(sec.securityExportCalled()).toBe(false);

    const orphan = logMessages.find((m) => m.includes("orphaned cache file"));
    expect(orphan).toBeDefined();
    expect(orphan).toContain(thumbprint);
  });

  it("fires the keychain-only warning when a dev cert is in the keychain but not on disk", async () => {
    const { cert } = await makeTestCert();
    const pem = cert.pem;
    const sec = setupSecurityMock({
      keychainThumbs: new Set(),
      extraKeychainPems: [pem],
    });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();
    expect(sec.securityExportCalled()).toBe(false);

    const keychainOnly = logMessages.find((m) =>
      m.includes("present in keychain but no matching PFX")
    );
    expect(keychainOnly).toBeDefined();
    expect(keychainOnly).toContain(cert.thumbprintSha1);
  });

  it("does not warn about keychain certs that ARE represented on disk", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    const sec = setupSecurityMock({
      keychainThumbs: new Set([thumbprint]),
      extraKeychainPems: [cert.pem],
    });

    const found = await store.findExistingDevCert();
    expect(found?.thumbprint).toBe(thumbprint);
    expect(sec.securityExportCalled()).toBe(false);

    const keychainOnly = logMessages.find((m) =>
      m.includes("present in keychain but no matching PFX")
    );
    expect(keychainOnly).toBeUndefined();
  });

  it("never invokes `security export` (compliance regression)", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );
    const sec = setupSecurityMock({
      keychainThumbs: new Set([thumbprint]),
      extraKeychainPems: [cert.pem],
    });

    await store.findExistingDevCert();
    expect(sec.securityExportCalled()).toBe(false);
  });

  it("warns and skips a cert-only PFX (no private key)", async () => {
    const { cert, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert }); // no key
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );
    setupSecurityMock({ keychainThumbs: new Set([thumbprint]) });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();
    const warn = logMessages.find((m) =>
      m.includes("certificate without matching private key")
    );
    expect(warn).toBeDefined();
  });

  it("warns and skips an unparseable canonically-named PFX", async () => {
    const fakeThumb = "A".repeat(40);
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${fakeThumb}.pfx`),
      Buffer.from("not a real PFX")
    );
    setupSecurityMock({ keychainThumbs: new Set() });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();
    const warn = logMessages.find((m) => m.includes("failed to parse PFX"));
    expect(warn).toBeDefined();
  });
});

describe("MacCertificateStore.removeCertificates", () => {
  let store: MacCertificateStore;

  beforeEach(() => {
    vi.clearAllMocks();
    logMessages.length = 0;
    testHomeDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-mac-rm-"));
    fs.mkdirSync(devCertsDir(), { recursive: true });
    store = new MacCertificateStore();
  });

  afterEach(() => {
    fs.rmSync(testHomeDir, { recursive: true, force: true });
  });

  it("calls `security remove-trusted-cert <cert-file>` for each dev cert (no `-d`, no keychain positional)", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    const sec = setupSecurityMock();
    await store.removeCertificates();

    const untrust = sec.calls.filter(
      (c) => c.cmd === "security" && c.args[0] === "remove-trusted-cert"
    );
    expect(untrust).toHaveLength(1);
    // No `-d` (we trusted to user domain, not admin) — using -d here
    // would look in the wrong trust-settings file and silently miss
    // our entry.
    expect(untrust[0].args).not.toContain("-d");
    // The positional must be a cert file path under os.tmpdir() — NOT
    // the keychain path. Past bug: we were passing the keychain path
    // here, which made the command a no-op (or worse, errored).
    const tmpDir = os.tmpdir();
    const positional = untrust[0].args[untrust[0].args.length - 1];
    expect(positional.startsWith(tmpDir)).toBe(true);
    expect(positional).toMatch(/devcert-untrust-.*\.cer$/);
  });

  it("calls untrust BEFORE delete-certificate (so trust-settings entries aren't orphaned)", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    const sec = setupSecurityMock();
    await store.removeCertificates();

    const untrustIdx = sec.calls.findIndex(
      (c) => c.cmd === "security" && c.args[0] === "remove-trusted-cert"
    );
    const deleteIdx = sec.calls.findIndex(
      (c) => c.cmd === "security" && c.args[0] === "delete-certificate"
    );
    expect(untrustIdx).toBeGreaterThanOrEqual(0);
    expect(deleteIdx).toBeGreaterThan(untrustIdx);
  });

  it("unlinks the PFX from disk after the keychain teardown", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    const pfxPath = path.join(
      devCertsDir(),
      `aspnetcore-localhost-${thumbprint}.pfx`
    );
    fs.writeFileSync(pfxPath, pfxBytes);

    setupSecurityMock();
    await store.removeCertificates();

    expect(fs.existsSync(pfxPath)).toBe(false);
  });

  it("regression: never calls `security remove-trusted-cert -d <keychain-path>`", async () => {
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    const sec = setupSecurityMock();
    await store.removeCertificates();

    const bad = sec.calls.find(
      (c) =>
        c.cmd === "security" &&
        c.args[0] === "remove-trusted-cert" &&
        c.args.includes("-d")
    );
    expect(bad).toBeUndefined();
  });

  it("processes multiple dev cert PFXes independently", async () => {
    const a = await makeTestCert();
    const b = await makeTestCert();
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${a.thumbprint}.pfx`),
      await buildPfx({ cert: a.cert, key: a.key })
    );
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${b.thumbprint}.pfx`),
      await buildPfx({ cert: b.cert, key: b.key })
    );

    const sec = setupSecurityMock();
    await store.removeCertificates();

    const untrustCount = sec.calls.filter(
      (c) => c.cmd === "security" && c.args[0] === "remove-trusted-cert"
    ).length;
    expect(untrustCount).toBe(2);
  });

  it("no-ops cleanly when the devCertsDir doesn't exist", async () => {
    fs.rmSync(devCertsDir(), { recursive: true, force: true });
    const sec = setupSecurityMock();
    await store.removeCertificates();
    expect(sec.calls).toHaveLength(0);
  });
});
