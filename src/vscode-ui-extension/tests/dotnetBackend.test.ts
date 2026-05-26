import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
} from "vitest";
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

import { DotnetBackend } from "@devcontainer-dev-certs/shared";
import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";
import { createPlatformStore } from "@devcontainer-dev-certs/shared/src/platform/types";
import { trustInNss } from "@devcontainer-dev-certs/shared/src/platform/nssTrust";
import {
  generateCertificate,
  VALIDITY_DAYS,
} from "@devcontainer-dev-certs/shared";

const mockedRunProcess = vi.mocked(runProcess);
const mockedCreatePlatformStore = vi.mocked(createPlatformStore);
const mockedTrustInNss = vi.mocked(trustInNss);

const cleanupDirs: string[] = [];

function stubPlatform(value: NodeJS.Platform): () => void {
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value, configurable: true });
  return () => {
    if (original) Object.defineProperty(process, "platform", original);
  };
}

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
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
    cleanupDirs.push(outDir);
    const generated = await makeCert();

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
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
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
    cleanupDirs.push(outDir);
    const generated = await makeCert();

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
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
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
    cleanupDirs.push(outDir);
    const generated = await makeCert();

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
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

  it("supplements the trust step with NSS on Linux", async () => {
    const restore = stubPlatform("linux");
    try {
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
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
      expect(mockedTrustInNss).toHaveBeenCalledTimes(1);
      expect(mockedTrustInNss).toHaveBeenCalledWith(
        path.join(outDir, "aspnetcore-dev.pem")
      );
      expect(reporter).toHaveBeenCalledTimes(1);
      expect(reporter).toHaveBeenCalledWith(
        { success: true, message: "ok" },
        path.join(outDir, "aspnetcore-dev.pem")
      );
    } finally {
      restore();
    }
  });

  it("does NOT run the NSS step on macOS (keychain handles browser trust)", async () => {
    const restore = stubPlatform("darwin");
    try {
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
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
      const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
      cleanupDirs.push(outDir);
      const generated = await makeCert();

      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
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
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockResolvedValue({
      exitCode: 1,
      stdout: "",
      stderr: "Unrecognized command or argument 'whatever'",
    });

    await expect(
      new DotnetBackend().generate({ outDir, noTrust: false })
    ).rejects.toThrow(/dotnet dev-certs failed.*Unrecognized command/);
  });

  it("throws with a clear message when the store has no cert post-trust", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-dotnet-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
    mockedCreatePlatformStore.mockResolvedValue({
      findExistingDevCert: vi.fn(async () => null),
    } as unknown as Shared.PlatformCertificateStore);

    await expect(
      new DotnetBackend().generate({ outDir, noTrust: false })
    ).rejects.toThrow(/no dev cert was found in the platform store/);
  });
});
