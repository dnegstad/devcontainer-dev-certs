import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  selectBackend,
  describeAutoBackend,
} from "@devcontainer-dev-certs/shared";

// `selectBackend('dotnet')` calls into the DotnetBackend's `isAvailable`
// which shells out via the shared runProcess. Stub that so the tests don't
// require an actual `dotnet` install.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

describe("selectBackend", () => {
  let originalPlatform: PropertyDescriptor | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  });

  afterEach(() => {
    if (originalPlatform) {
      Object.defineProperty(process, "platform", originalPlatform);
    }
  });

  function stubPlatform(value: NodeJS.Platform): void {
    Object.defineProperty(process, "platform", {
      value,
      configurable: true,
    });
  }

  it("returns the native backend for --backend native regardless of platform", async () => {
    stubPlatform("linux");
    const backend = await selectBackend("native");
    expect(backend.kind).toBe("native");
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
    stubPlatform("darwin");
    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
    const backend = await selectBackend("auto");
    expect(backend.kind).toBe("dotnet");
  });

  it("auto-falls-back to native on macOS when dotnet is unavailable", async () => {
    stubPlatform("darwin");
    mockedRunProcess.mockResolvedValue({ exitCode: 127, stdout: "", stderr: "not found" });
    const backend = await selectBackend("auto");
    expect(backend.kind).toBe("native");
  });

  it("auto-picks native on Linux regardless of dotnet availability", async () => {
    stubPlatform("linux");
    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
    const backend = await selectBackend("auto");
    expect(backend.kind).toBe("native");
  });

  it("auto-picks native on Windows", async () => {
    stubPlatform("win32");
    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
    const backend = await selectBackend("auto");
    expect(backend.kind).toBe("native");
  });
});

describe("describeAutoBackend", () => {
  let originalPlatform: PropertyDescriptor | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  });

  afterEach(() => {
    if (originalPlatform) {
      Object.defineProperty(process, "platform", originalPlatform);
    }
  });

  function stubPlatform(value: NodeJS.Platform): void {
    Object.defineProperty(process, "platform", {
      value,
      configurable: true,
    });
  }

  it("reports 'dotnet' on macOS when dotnet is available", async () => {
    stubPlatform("darwin");
    mockedRunProcess.mockResolvedValue({ exitCode: 0, stdout: "8.0.100", stderr: "" });
    expect(await describeAutoBackend()).toBe("dotnet");
  });

  it("reports 'native' everywhere else", async () => {
    stubPlatform("linux");
    expect(await describeAutoBackend()).toBe("native");
    stubPlatform("win32");
    expect(await describeAutoBackend()).toBe("native");
  });
});
