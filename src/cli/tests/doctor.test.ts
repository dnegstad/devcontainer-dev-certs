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

// `runDoctor` exercises three different shared-module surfaces:
// `runProcess`, `resolveSafeExecPath`, and `createPlatformStore`. Mock
// all three so the tests don't depend on what's actually installed on
// the host machine. `describeAutoBackend` is left real but its dotnet
// probe goes through the same `runProcess` mock.
vi.mock("@devcontainer-dev-certs/shared", async () => {
  const actual = await vi.importActual<typeof Shared>(
    "@devcontainer-dev-certs/shared"
  );
  return {
    ...actual,
    runProcess: vi.fn(),
    resolveSafeExecPath: vi.fn(),
    createPlatformStore: vi.fn(),
    describeAutoBackend: vi.fn(),
  };
});

import {
  createPlatformStore,
  describeAutoBackend,
  resolveSafeExecPath,
  runProcess,
} from "@devcontainer-dev-certs/shared";
import { runDoctor } from "../src/commands/doctor";

const mockedRunProcess = vi.mocked(runProcess);
const mockedResolveSafeExecPath = vi.mocked(resolveSafeExecPath);
const mockedCreatePlatformStore = vi.mocked(createPlatformStore);
const mockedDescribeAutoBackend = vi.mocked(describeAutoBackend);

const cleanupDirs: string[] = [];

function stubPlatform(value: NodeJS.Platform): () => void {
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value, configurable: true });
  return () => {
    if (original) Object.defineProperty(process, "platform", original);
  };
}

function collectStdout(): string {
  const writeMock = vi.mocked(process.stdout.write);
  return writeMock.mock.calls.map((c) => String(c[0])).join("");
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);

  // Default stubs: dotnet not on PATH, platform store empty, auto picks
  // native. Each test can override what it cares about.
  mockedRunProcess.mockResolvedValue({ exitCode: 1, stdout: "", stderr: "" });
  mockedResolveSafeExecPath.mockReturnValue(null);
  mockedDescribeAutoBackend.mockResolvedValue("native");
  mockedCreatePlatformStore.mockResolvedValue({
    checkStatus: vi.fn(async () => ({
      exists: false,
      isTrusted: false,
      thumbprint: null,
      notBefore: null,
      notAfter: null,
      version: null,
    })),
  } as never);
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of cleanupDirs) fs.rmSync(dir, { recursive: true, force: true });
  cleanupDirs.length = 0;
  process.exitCode = 0;
});

describe("ddc doctor — Linux", () => {
  it("reports [ok] when openssl and certutil are both on PATH", async () => {
    const restore = stubPlatform("linux");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-linux-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockImplementation(async (cmd: string, args: string[]) => {
      if (cmd === "which" && args[0] === "openssl") {
        return { exitCode: 0, stdout: "/usr/bin/openssl\n", stderr: "" };
      }
      if (cmd === "which" && args[0] === "certutil") {
        return { exitCode: 0, stdout: "/usr/bin/certutil\n", stderr: "" };
      }
      return { exitCode: 1, stdout: "", stderr: "" };
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[ok] openssl on PATH");
    expect(stdout).toContain("/usr/bin/openssl");
    expect(stdout).toContain("[ok] certutil on PATH");
  });

  it("reports [warn] when certutil is missing", async () => {
    const restore = stubPlatform("linux");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-linux-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockImplementation(async (cmd: string, args: string[]) => {
      if (cmd === "which" && args[0] === "openssl") {
        return { exitCode: 0, stdout: "/usr/bin/openssl\n", stderr: "" };
      }
      return { exitCode: 1, stdout: "", stderr: "" };
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[warn] certutil on PATH");
    expect(stdout).toContain("Chromium/Firefox won't auto-trust");
  });
});

describe("ddc doctor — macOS", () => {
  it("checks for the `security` keychain CLI", async () => {
    const restore = stubPlatform("darwin");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-mac-"));
    cleanupDirs.push(outDir);

    mockedRunProcess.mockImplementation(async (cmd: string, args: string[]) => {
      if (cmd === "which" && args[0] === "security") {
        return { exitCode: 0, stdout: "/usr/bin/security\n", stderr: "" };
      }
      return { exitCode: 1, stdout: "", stderr: "" };
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[ok] security on PATH");
    expect(stdout).toContain("/usr/bin/security");
  });

  it("does NOT run Linux-only checks on macOS", async () => {
    const restore = stubPlatform("darwin");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-mac-"));
    cleanupDirs.push(outDir);

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).not.toContain("openssl on PATH");
    expect(stdout).not.toContain("Linux NSS");
  });

  it("warns when `security` isn't on PATH", async () => {
    const restore = stubPlatform("darwin");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-mac-"));
    cleanupDirs.push(outDir);

    // Default mockedRunProcess returns exit 1 for everything — including
    // the `which security` probe.
    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[warn] security on PATH");
    expect(stdout).toContain("native backend cannot drive the keychain");
  });
});

describe("ddc doctor — Windows", () => {
  it("reports [ok] when both pwsh and certutil.exe resolve", async () => {
    const restore = stubPlatform("win32");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-win-"));
    cleanupDirs.push(outDir);

    mockedResolveSafeExecPath.mockImplementation((cmd: string) => {
      if (cmd === "pwsh") return "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
      if (cmd === "certutil.exe") return "C:\\Windows\\System32\\certutil.exe";
      return null;
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[ok] pwsh or powershell on PATH");
    expect(stdout).toContain("pwsh.exe");
    expect(stdout).toContain("[ok] certutil.exe on PATH");
  });

  it("accepts powershell as a fallback when pwsh is absent, with a note", async () => {
    const restore = stubPlatform("win32");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-win-"));
    cleanupDirs.push(outDir);

    mockedResolveSafeExecPath.mockImplementation((cmd: string) => {
      if (cmd === "pwsh") return null;
      if (cmd === "powershell")
        return "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
      if (cmd === "certutil.exe") return "C:\\Windows\\System32\\certutil.exe";
      return null;
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[ok] pwsh or powershell on PATH");
    expect(stdout).toContain("powershell.exe");
    expect(stdout).toContain("PowerShell 5.1");
  });

  it("warns when neither pwsh nor powershell is found", async () => {
    const restore = stubPlatform("win32");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-win-"));
    cleanupDirs.push(outDir);

    mockedResolveSafeExecPath.mockImplementation((cmd: string) => {
      if (cmd === "certutil.exe") return "C:\\Windows\\System32\\certutil.exe";
      return null; // both pwsh and powershell missing
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[warn] pwsh or powershell on PATH");
    expect(stdout).toContain("Windows store enumeration / cleanup will fail");
  });

  it("warns when certutil.exe is missing", async () => {
    const restore = stubPlatform("win32");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-win-"));
    cleanupDirs.push(outDir);

    mockedResolveSafeExecPath.mockImplementation((cmd: string) => {
      if (cmd === "pwsh") return "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
      return null;
    });

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    const stdout = collectStdout();
    expect(stdout).toContain("[warn] certutil.exe on PATH");
    expect(stdout).toContain("native trust step will fail");
  });

  it("does NOT shell out to `which` on Windows (uses resolveSafeExecPath)", async () => {
    const restore = stubPlatform("win32");
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ddc-doctor-win-"));
    cleanupDirs.push(outDir);

    try {
      await runDoctor({ outDir });
    } finally {
      restore();
    }

    // `which` is not the right tool on Windows (`where.exe` is), and we
    // explicitly skip it in favor of resolveSafeExecPath because the
    // latter is the same lookup runProcess uses and avoids a redundant
    // shell-out. Regression-guard the path: no `which` invocations.
    const whichCalls = mockedRunProcess.mock.calls.filter(
      ([cmd]) => cmd === "which"
    );
    expect(whichCalls).toHaveLength(0);
  });
});
