import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Mock runProcess to simulate certutil and which commands. Target the
// shared internal module that `trustInNss` actually imports from — mocking
// the extension's re-export shim would leave the implementation calling
// the real runProcess.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

// Mock os.homedir to use a temp directory for browser profile discovery
let mockHomeDir: string;
vi.mock("os", async (importOriginal) => {
  const original = await importOriginal<typeof os>();
  return {
    ...original,
    homedir: () => mockHomeDir,
  };
});

import { trustInNss } from "../src/platform/nssTrust";
import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

function makeNssDb(...segs: string[]): string {
  const dir = path.join(mockHomeDir, ...segs);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "cert9.db"), "");
  return dir;
}

function whichOk(): void {
  mockedRunProcess.mockResolvedValueOnce({
    exitCode: 0,
    stdout: "/usr/bin/certutil\n",
    stderr: "",
  });
}

function certutilOk(times: number): void {
  for (let i = 0; i < times; i++) {
    mockedRunProcess.mockResolvedValueOnce({
      exitCode: 0,
      stdout: "",
      stderr: "",
    });
  }
}

describe("trustInNss", () => {
  let tmpDir: string;
  let pemPath: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-nss-test-"));
    mockHomeDir = tmpDir;
    pemPath = path.join(tmpDir, "test-cert.pem");
    fs.writeFileSync(
      pemPath,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns failure when certutil is not installed", async () => {
    mockedRunProcess.mockResolvedValue({
      exitCode: 1,
      stdout: "",
      stderr: "which: no certutil in PATH",
    });

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("certutil is not installed");
  });

  it("returns failure when no NSS databases are found", async () => {
    // certutil exists but no browser profiles in mockHomeDir
    mockedRunProcess.mockResolvedValue({
      exitCode: 0,
      stdout: "/usr/bin/certutil\n",
      stderr: "",
    });

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("No browser NSS databases found");
  });

  it("trusts in native Chromium NSS database when present", async () => {
    const nssDir = makeNssDb(".pki", "nssdb");
    whichOk();
    certutilOk(2); // -D then -A

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Chromium");

    const addCall = mockedRunProcess.mock.calls.find(
      (call) => call[0] === "certutil" && call[1].includes("-A")
    );
    expect(addCall).toBeDefined();
    expect(addCall![1]).toContain("CT,,");
    expect(addCall![1]).toContain(pemPath);
    expect(addCall![1]).toContain(`sql:${nssDir}`);
  });

  it("trusts in native Firefox profile NSS databases when present", async () => {
    makeNssDb(".mozilla", "firefox", "abc123.default");
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Firefox (abc123.default)");
  });

  it("trusts in Snap Firefox profile NSS databases when present", async () => {
    makeNssDb("snap", "firefox", "common", ".mozilla", "firefox", "snap.default");
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Firefox (Snap) (snap.default)");
  });

  it("trusts in Flatpak Firefox profile NSS databases when present", async () => {
    makeNssDb(
      ".var",
      "app",
      "org.mozilla.firefox",
      ".mozilla",
      "firefox",
      "fp.default"
    );
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Firefox (Flatpak) (fp.default)");
  });

  it("trusts in Snap Chromium NSS database when present", async () => {
    makeNssDb("snap", "chromium", "common", ".pki", "nssdb");
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Chromium (Snap)");
  });

  it("trusts in Flatpak Chromium-family NSS databases when present", async () => {
    makeNssDb(".var", "app", "com.google.Chrome", ".pki", "nssdb");
    makeNssDb(".var", "app", "com.brave.Browser", ".pki", "nssdb");
    whichOk();
    certutilOk(4); // 2 dbs × (-D, -A)

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Chrome (Flatpak)");
    expect(result.message).toContain("Brave (Flatpak)");
  });

  it("trusts in Firefox forks (LibreWolf, Waterfox, Floorp, ESR) when present", async () => {
    makeNssDb(".mozilla", "firefox-esr", "esr.default");
    makeNssDb(".librewolf", "lw.default");
    makeNssDb(".waterfox", "wf.default");
    makeNssDb(".floorp", "fl.default");
    whichOk();
    certutilOk(8);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Firefox ESR (esr.default)");
    expect(result.message).toContain("LibreWolf (lw.default)");
    expect(result.message).toContain("Waterfox (wf.default)");
    expect(result.message).toContain("Floorp (fl.default)");
  });

  it("reports failure per-database when certutil -A fails", async () => {
    makeNssDb(".mozilla", "firefox", "test.profile");
    whichOk();
    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // -D
      .mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "SEC_ERROR_BAD_DATABASE",
      }); // -A fails

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("Firefox (test.profile): failed");
    expect(result.message).toContain("SEC_ERROR_BAD_DATABASE");
  });

  it("removes existing cert before adding for idempotency", async () => {
    makeNssDb(".mozilla", "firefox", "idempotent.profile");
    whichOk();
    certutilOk(2);

    await trustInNss(pemPath);

    const deleteCall = mockedRunProcess.mock.calls[1];
    expect(deleteCall[0]).toBe("certutil");
    expect(deleteCall[1]).toContain("-D");
    expect(deleteCall[1]).toContain("Dev Container Dev Cert");

    const addCall = mockedRunProcess.mock.calls[2];
    expect(addCall[0]).toBe("certutil");
    expect(addCall[1]).toContain("-A");
  });

  it("handles native Chromium and Firefox in a single call", async () => {
    makeNssDb(".pki", "nssdb");
    makeNssDb(".mozilla", "firefox", "multi.default");
    whichOk();
    certutilOk(4);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Chromium, Firefox (multi.default)");
  });

  it("skips Firefox roots silently when no profile has cert9.db", async () => {
    // Profile dir exists but no cert9.db inside — counts as not-yet-initialized
    const noCertProfile = path.join(
      mockHomeDir,
      ".mozilla",
      "firefox",
      "empty.profile"
    );
    fs.mkdirSync(noCertProfile, { recursive: true });
    whichOk();

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("No browser NSS databases found");
  });

  it("combines trusted databases into a single comma-separated entry", async () => {
    makeNssDb(".pki", "nssdb");
    makeNssDb("snap", "firefox", "common", ".mozilla", "firefox", "p.default");
    whichOk();
    certutilOk(4);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    // Exactly one "Trusted in:" prefix — failures (none here) would be appended
    // separately after a semicolon.
    expect(result.message.match(/Trusted in:/g)?.length).toBe(1);
    expect(result.message).toBe(
      "Trusted in: Chromium, Firefox (Snap) (p.default)"
    );
  });
});
