import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { initLogger } from "@devcontainer-dev-certs/shared/src/loggerVscode";
import { logMessages } from "./__mocks__/vscode";
import {
  generateCertificate,
  VALIDITY_DAYS,
  buildPfx,
  MacCertificateStore,
} from "@devcontainer-dev-certs/shared";

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
 * Build a security-CLI mock that models the real find-certificate
 * semantics — `-Z` is an output modifier (prints hash lines), NOT a
 * filter, so presence checks enumerate with `-a -Z` and match on the
 * `SHA-1 hash:` lines:
 *  - `find-certificate -a -Z <keychain>` (no `-p`) emits one
 *    `SHA-1 hash: <thumb>` line per entry in `keychainThumbs`, mirroring
 *    modern macOS by also emitting a `SHA-256 hash:` line per cert
 *  - `find-certificate -a -p -Z` returns a synthetic PEM block listing
 *    every `extraKeychainPems` entry
 *  - any other call resolves to a benign success
 *  - tracks every command for assertions
 */
function setupSecurityMock(opts: {
  keychainThumbs?: Set<string>;
  extraKeychainPems?: string[];
  /**
   * Simulate `runProcess` killing `security` for exceeding the output cap:
   * exitCode 1, empty stderr, a truncated stdout prefix. That is exactly the
   * shape Node produces (`error.code` is the string
   * ERR_CHILD_PROCESS_STDIO_MAXBUFFER, so it lands in the same exitCode 1
   * bucket as a real failure).
   */
  truncateHashEnumeration?: boolean;
} = {}) {
  const calls: Array<{ cmd: string; args: readonly string[] }> = [];
  mockedRunProcess.mockImplementation(async (cmd: string, args: readonly string[]) => {
    calls.push({ cmd, args: [...args] });
    if (cmd !== "security") {
      return { exitCode: 0, stdout: "", stderr: "", truncated: false };
    }
    const sub = args[0];
    if (sub === "find-certificate") {
      // hash enumeration (presence checks)
      if (args.includes("-a") && args.includes("-Z") && !args.includes("-p")) {
        const thumbs = [...(opts.keychainThumbs ?? [])];
        const stdout = thumbs
          .map(
            (t) =>
              `SHA-256 hash: ${"AB".repeat(32)}\nSHA-1 hash: ${t}\nkeychain: "/Users/test/Library/Keychains/login.keychain-db"\n`
          )
          .join("");
        if (opts.truncateHashEnumeration) {
          return {
            exitCode: 1,
            stdout: stdout.slice(0, 32),
            stderr: "",
            truncated: true,
          };
        }
        return { exitCode: 0, stdout, stderr: "", truncated: false };
      }
      // enumerate all as PEM
      if (args.includes("-a") && args.includes("-p")) {
        const pems = opts.extraKeychainPems ?? [];
        return {
          exitCode: 0,
          stdout: pems.join("\n"),
          stderr: "",
          truncated: false,
        };
      }
    }
    return { exitCode: 0, stdout: "", stderr: "", truncated: false };
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

  it("keeps the cert when keychain enumeration is truncated, instead of regenerating", async () => {
    // `security find-certificate -a` dumps the whole login keychain, which on
    // a large one blows past the output cap. Node reports that with a STRING
    // error.code, so it arrives as exitCode 1 with empty stderr —
    // indistinguishable from a real failure without the `truncated` flag.
    //
    // Reading it as "not in the keychain" is the destructive answer: the PFX
    // gets force-skipped as an orphan, findExistingDevCert comes back empty,
    // checkStatus reports exists:false, and CertManager.trust() generates a
    // fresh cert plus an add-trusted-cert password prompt. That cert then
    // lands in the same keychain, so the next call truncates sooner — a loop
    // that feeds itself. So we deliberately fail OPEN here.
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    setupSecurityMock({
      keychainThumbs: new Set([thumbprint]),
      truncateHashEnumeration: true,
    });

    const found = await store.findExistingDevCert();
    expect(found?.thumbprint).toBe(thumbprint);
    // Specifically NOT classified as an orphaned cache file.
    expect(
      logMessages.find((m) => m.includes("orphaned cache file"))
    ).toBeUndefined();
    expect(
      logMessages.find((m) => m.includes("exceeded the output cap"))
    ).toBeDefined();
  });

  it("still reports a genuinely absent cert as an orphan when output is complete", async () => {
    // The fail-open above must be scoped to truncation only — an untruncated
    // enumeration that simply doesn't list the thumbprint still means the PFX
    // is orphaned, and that classification has to survive.
    const { cert, key, thumbprint } = await makeTestCert();
    const pfxBytes = await buildPfx({ cert, key });
    fs.writeFileSync(
      path.join(devCertsDir(), `aspnetcore-localhost-${thumbprint}.pfx`),
      pfxBytes
    );

    setupSecurityMock({
      keychainThumbs: new Set(),
      truncateHashEnumeration: false,
    });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();
    expect(
      logMessages.find((m) => m.includes("orphaned cache file"))
    ).toBeDefined();
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

