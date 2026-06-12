import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  selectBackend,
  describeAutoBackend,
} from "@devcontainer-dev-certs/shared";
import { stubPlatform } from "./_helpers";

// `selectBackend('dotnet')` calls into the DotnetBackend's `isAvailable`
// which shells out via the shared runProcess. Stub that so the tests don't
// require an actual `dotnet` install.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

describe("selectBackend", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the native backend for --backend native regardless of platform", async () => {
    const restore = stubPlatform("linux");
    try {
      const backend = await selectBackend("native");
      expect(backend.kind).toBe("native");
    } finally {
      restore();
    }
  });

  it("returns the dotnet backend for --backend dotnet when dotnet is on PATH", async () => {
    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
    const backend = await selectBackend("dotnet");
    expect(backend.kind).toBe("dotnet");
  });

  it("throws when --backend dotnet is requested but dotnet is unavailable", async () => {
    mockedRunProcess.mockResolvedValue({ exitCode: 127, stdout: "", stderr: "not found" });
    await expect(selectBackend("dotnet")).rejects.toThrow(/not found on PATH/);
  });

  it("auto-picks dotnet on macOS when dotnet is available", async () => {
    const restore = stubPlatform("darwin");
    try {
      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
      const backend = await selectBackend("auto");
      expect(backend.kind).toBe("dotnet");
    } finally {
      restore();
    }
  });

  it("auto-falls-back to native on macOS when dotnet is unavailable", async () => {
    const restore = stubPlatform("darwin");
    try {
      mockedRunProcess.mockResolvedValue({ exitCode: 127, stdout: "", stderr: "not found" });
      const backend = await selectBackend("auto");
      expect(backend.kind).toBe("native");
    } finally {
      restore();
    }
  });

  it("auto-picks native on Linux regardless of dotnet availability", async () => {
    const restore = stubPlatform("linux");
    try {
      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
      const backend = await selectBackend("auto");
      expect(backend.kind).toBe("native");
    } finally {
      restore();
    }
  });

  it("auto-picks native on Windows", async () => {
    const restore = stubPlatform("win32");
    try {
      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
      const backend = await selectBackend("auto");
      expect(backend.kind).toBe("native");
    } finally {
      restore();
    }
  });
});

describe("describeAutoBackend", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reports 'dotnet' on macOS when dotnet is available", async () => {
    const restore = stubPlatform("darwin");
    try {
      mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
      expect(await describeAutoBackend()).toBe("dotnet");
    } finally {
      restore();
    }
  });

  it("reports 'native' everywhere else", async () => {
    const restoreLinux = stubPlatform("linux");
    try {
      expect(await describeAutoBackend()).toBe("native");
    } finally {
      restoreLinux();
    }
    const restoreWin = stubPlatform("win32");
    try {
      expect(await describeAutoBackend()).toBe("native");
    } finally {
      restoreWin();
    }
  });
});
