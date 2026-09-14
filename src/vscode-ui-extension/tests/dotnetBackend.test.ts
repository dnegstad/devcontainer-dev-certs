import { describe, it, expect, beforeEach, afterEach, vi, } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type * as Shared from "@devcontainer-dev-certs/shared";
import type * as PlatformTypes from "@devcontainer-dev-certs/shared/src/platform/types";

// DotnetBackend shells out to the real `dotnet` CLI (which isn't on the
// test runner). Mock the shell-out chokepoint and the platform-store
// constructor so the test drives a synthetic outcome end-to-end.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn(),
  resolveSafeExecPath: vi.fn((c: string) => c),
}));

vi.mock("@devcontainer-dev-certs/shared/src/platform/types", async () => {
  const actual = await vi.importActual<typeof PlatformTypes>(
    "@devcontainer-dev-certs/shared/src/platform/types"
  );
  return { ...actual, createPlatformStore: vi.fn() };
});

vi.mock("@devcontainer-dev-certs/shared/src/platform/nssTrust", () => ({
  trustInNss: vi.fn(),
}));

import {
  DotnetBackend,
  generateCertificate,
  VALIDITY_DAYS,
} from "@devcontainer-dev-certs/shared";
import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";
import { createPlatformStore } from "@devcontainer-dev-certs/shared/src/platform/types";
import { trustInNss } from "@devcontainer-dev-certs/shared/src/platform/nssTrust";

const mockedRunProcess = vi.mocked(runProcess);
const mockedCreatePlatformStore = vi.mocked(createPlatformStore);
const mockedTrustInNss = vi.mocked(trustInNss);

import { stubPlatform } from "./_helpers";

const cleanupDirs: string[] = [];

async function makeCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400_000);
  return generateCertificate(now, expiry);
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  for (const dir of cleanupDirs) fs.rmSync(dir, { recursive: true, force: true });
  cleanupDirs.length = 0;
});

describe("DotnetBackend.generate", () => {
  it("invokes `dotnet dev-certs https --trust` (no --no-password, no --format)", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
    cleanupDirs.push(outDir);
    const generated = await makeCert();

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
    mockedCreatePlatformStore.mockResolvedValue({
      findExistingDevCert: vi.fn(async () => generated),
    } as unknown as Shared.PlatformCertificateStore);

    const result = await new DotnetBackend().generate({
      outDir,
      noTrust: false,
    });

    // Regression guard for the broken `--no-password` + `--format Pfx`
    // combo: we should never invoke dotnet with either flag.
    expect(mockedRunProcess).toHaveBeenCalledWith(
      "dotnet",
      ["dev-certs", "https", "--trust"],
      expect.any(Number)
    );
    for (const call of mockedRunProcess.mock.calls) {
      const args = call[1];
      expect(args).not.toContain("--no-password");
      expect(args).not.toContain("--format");
      expect(args).not.toContain("--export-path");
    }
    expect(result.thumbprint).toBe(generated.thumbprint);
  });

  it("omits --trust when noTrust is set", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
    cleanupDirs.push(outDir);
    const generated = await makeCert();

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
    mockedCreatePlatformStore.mockResolvedValue({
      findExistingDevCert: vi.fn(async () => generated),
    } as unknown as Shared.PlatformCertificateStore);

    await new DotnetBackend().generate({ outDir, noTrust: true });

    expect(mockedRunProcess).toHaveBeenCalledWith(
      "dotnet",
      ["dev-certs", "https"],
      expect.any(Number)
    );
  });

  it("writes PFX, PEM, and key into outDir using our naming (foo.key, not foo.pem.key)", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
    cleanupDirs.push(outDir);
    const generated = await makeCert();

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
    mockedCreatePlatformStore.mockResolvedValue({
      findExistingDevCert: vi.fn(async () => generated),
    } as unknown as Shared.PlatformCertificateStore);

    const result = await new DotnetBackend().generate({
      outDir,
      noTrust: false,
    });

    // Naming matches the native backend so bundle.ts and inspect.ts
    // sibling-discovery work uniformly. The dotnet-native convention
    // `aspnetcore-dev.pem.key` must NOT leak through here.
    expect(result.pfxPath).toBe(path.join(outDir, "aspnetcore-dev.pfx"));
    expect(result.pemPath).toBe(path.join(outDir, "aspnetcore-dev.pem"));
    expect(result.pemKeyPath).toBe(path.join(outDir, "aspnetcore-dev.key"));
    expect(fs.existsSync(result.pfxPath)).toBe(true);
    expect(fs.existsSync(result.pemPath)).toBe(true);
    expect(fs.existsSync(result.pemKeyPath!)).toBe(true);
    // Never write the dotnet-style naming as a byproduct.
    expect(fs.existsSync(path.join(outDir, "aspnetcore-dev.pem.key"))).toBe(false);
  });

  it("supplements the trust step with NSS on Linux, anchored on the persistent trust-dir PEM", async () => {
    const restore = stubPlatform("linux");
    const trustDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-trustdir-"));
    cleanupDirs.push(trustDir);
    vi.stubEnv("DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY", trustDir);
    try {
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
      mockedCreatePlatformStore.mockResolvedValue({
        findExistingDevCert: vi.fn(async () => generated),
      } as unknown as Shared.PlatformCertificateStore);
      mockedTrustInNss.mockResolvedValue({
        success: true,
        message: "ok",
      });

      const reporter = vi.fn();
      await new DotnetBackend().generate({
        outDir,
        noTrust: false,
        linuxNssTrustReporter: reporter,
      });

      // Verifies the gap-fill: dotnet --trust on Linux misses NSS
      // browser DBs, so the backend invokes trustInNss separately.
      // CRUCIALLY: with the persistent trust-dir path, NOT the exported
      // copy in outDir — callers delete outDir as soon as generate()
      // returns while the reporter's manual-import guidance (the
      // toast's "Copy Certificate Path" action) can outlive it.
      const persistentPem = path.join(
        trustDir,
        `aspnetcore-localhost-${generated.thumbprint}.pem`
      );
      expect(mockedTrustInNss).toHaveBeenCalledTimes(1);
      expect(mockedTrustInNss).toHaveBeenCalledWith(persistentPem);
      expect(reporter).toHaveBeenCalledTimes(1);
      expect(reporter).toHaveBeenCalledWith(
        { success: true, message: "ok" },
        persistentPem
      );
      // The trust dir started empty (older-SDK scenario where dotnet
      // --trust doesn't manage it) — the backend must have placed the
      // PEM there itself so the reported path actually exists.
      expect(fs.existsSync(persistentPem)).toBe(true);
    } finally {
      vi.unstubAllEnvs();
      restore();
    }
  });

  it("does not overwrite an existing trust-dir PEM (dotnet --trust already wrote it)", async () => {
    const restore = stubPlatform("linux");
    const trustDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-trustdir-"));
    cleanupDirs.push(trustDir);
    vi.stubEnv("DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY", trustDir);
    try {
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();
      const persistentPem = path.join(
        trustDir,
        `aspnetcore-localhost-${generated.thumbprint}.pem`
      );
      // Simulate an SDK that manages the trust dir: the PEM is already
      // there before the backend runs.
      fs.writeFileSync(persistentPem, "sentinel-existing-pem");

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
      mockedCreatePlatformStore.mockResolvedValue({
        findExistingDevCert: vi.fn(async () => generated),
      } as unknown as Shared.PlatformCertificateStore);
      mockedTrustInNss.mockResolvedValue({ success: true, message: "ok" });

      await new DotnetBackend().generate({
        outDir,
        noTrust: false,
        linuxNssTrustReporter: vi.fn(),
      });

      expect(mockedTrustInNss).toHaveBeenCalledWith(persistentPem);
      expect(fs.readFileSync(persistentPem, "utf-8")).toBe(
        "sentinel-existing-pem"
      );
    } finally {
      vi.unstubAllEnvs();
      restore();
    }
  });

  it("does NOT run the NSS step on macOS (keychain handles browser trust)", async () => {
    const restore = stubPlatform("darwin");
    try {
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
      mockedCreatePlatformStore.mockResolvedValue({
        findExistingDevCert: vi.fn(async () => generated),
      } as unknown as Shared.PlatformCertificateStore);

      await new DotnetBackend().generate({ outDir, noTrust: false });

      expect(mockedTrustInNss).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("does NOT run the NSS step on Linux when noTrust is set", async () => {
    const restore = stubPlatform("linux");
    try {
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
      mockedCreatePlatformStore.mockResolvedValue({
        findExistingDevCert: vi.fn(async () => generated),
      } as unknown as Shared.PlatformCertificateStore);

      await new DotnetBackend().generate({ outDir, noTrust: true });

      expect(mockedTrustInNss).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  it("throws when dotnet exits non-zero", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockResolvedValue({
      exitCode: 1,
      stdout: "",
      stderr: "Unrecognized command or argument 'whatever'",
      truncated: false,
    });

    await expect(
      new DotnetBackend().generate({ outDir, noTrust: false })
    ).rejects.toThrow(/dotnet dev-certs failed.*Unrecognized command/);
  });

  it("throws with a clear message when the store has no cert post-trust", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", truncated: false });
    mockedCreatePlatformStore.mockResolvedValue({
      findExistingDevCert: vi.fn(async () => null),
    } as unknown as Shared.PlatformCertificateStore);

    await expect(
      new DotnetBackend().generate({ outDir, noTrust: false })
    ).rejects.toThrow(/no dev cert was found in the platform store/);
  });
});
