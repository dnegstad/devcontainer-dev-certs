import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Mock runProcess to simulate certutil and which commands
vi.mock("../src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

// Mock os.homedir to use a temp directory for browser profile discovery
let mockHomeDir: string;
vi.mock("os", async (importOriginal) => {
  const original = (await importOriginal()) as typeof import("os");
  return {
    ...original,
    homedir: () => mockHomeDir,
  };
});

import { trustInNss } from "../src/platform/nssTrust";
import { runProcess } from "../src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

describe("trustInNss", () => {
  let tmpDir: string;
  let pemPath: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-nss-test-"));
    mockHomeDir = tmpDir;
    pemPath = path.join(tmpDir, "test-cert.pem");
    fs.writeFileSync(pemPath, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
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

  it("trusts in Chromium NSS database when present", async () => {
    // Create fake Chromium NSS database
    const nssDir = path.join(tmpDir, ".pki", "nssdb");
    fs.mkdirSync(nssDir, { recursive: true });
    fs.writeFileSync(path.join(nssDir, "cert9.db"), "");

    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/certutil\n", stderr: "" }) // which
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -D (remove)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }); // certutil -A (add)

    const result = await trustInNss(pemPath);

    expect(result.message).toContain("Chromium: trusted");

    // Verify certutil -A was called with correct args
    const addCall = mockedRunProcess.mock.calls.find(
      (call) => call[0] === "certutil" && call[1].includes("-A")
    );
    expect(addCall).toBeDefined();
    expect(addCall![1]).toContain("CT,,");
    expect(addCall![1]).toContain(pemPath);
    expect(addCall![1]).toContain(`sql:${nssDir}`);
  });

  it("trusts in Firefox profile NSS databases when present", async () => {
    // Create fake Firefox profile
    const profileDir = path.join(tmpDir, ".mozilla", "firefox", "abc123.default");
    fs.mkdirSync(profileDir, { recursive: true });
    fs.writeFileSync(path.join(profileDir, "cert9.db"), "");

    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/certutil\n", stderr: "" }) // which
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -D
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }); // certutil -A

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Firefox (abc123.default): trusted");
  });

  it("reports failure per-database when certutil -A fails", async () => {
    const profileDir = path.join(tmpDir, ".mozilla", "firefox", "test.profile");
    fs.mkdirSync(profileDir, { recursive: true });
    fs.writeFileSync(path.join(profileDir, "cert9.db"), "");

    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/certutil\n", stderr: "" }) // which
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -D
      .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "SEC_ERROR_BAD_DATABASE" }); // certutil -A fails

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("Firefox (test.profile): failed");
    expect(result.message).toContain("SEC_ERROR_BAD_DATABASE");
  });

  it("removes existing cert before adding for idempotency", async () => {
    const profileDir = path.join(tmpDir, ".mozilla", "firefox", "idempotent.profile");
    fs.mkdirSync(profileDir, { recursive: true });
    fs.writeFileSync(path.join(profileDir, "cert9.db"), "");

    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/certutil\n", stderr: "" }) // which
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -D (remove)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }); // certutil -A (add)

    await trustInNss(pemPath);

    // First certutil call after `which` should be -D (delete)
    const deleteCall = mockedRunProcess.mock.calls[1];
    expect(deleteCall[0]).toBe("certutil");
    expect(deleteCall[1]).toContain("-D");
    expect(deleteCall[1]).toContain("Dev Container Dev Cert");

    // Second certutil call should be -A (add)
    const addCall = mockedRunProcess.mock.calls[2];
    expect(addCall[0]).toBe("certutil");
    expect(addCall[1]).toContain("-A");
  });

  it("handles both Chromium and Firefox databases in one call", async () => {
    // Create both
    const nssDir = path.join(tmpDir, ".pki", "nssdb");
    fs.mkdirSync(nssDir, { recursive: true });
    fs.writeFileSync(path.join(nssDir, "cert9.db"), "");

    const profileDir = path.join(tmpDir, ".mozilla", "firefox", "multi.default");
    fs.mkdirSync(profileDir, { recursive: true });
    fs.writeFileSync(path.join(profileDir, "cert9.db"), "");

    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/certutil\n", stderr: "" }) // which
      // Chromium
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -D
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -A
      // Firefox
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // certutil -D
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }); // certutil -A

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Chromium: trusted");
    expect(result.message).toContain("Firefox (multi.default): trusted");
  });
});
