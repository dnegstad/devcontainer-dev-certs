import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { initLogger } from "@devcontainer-dev-certs/shared";
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
