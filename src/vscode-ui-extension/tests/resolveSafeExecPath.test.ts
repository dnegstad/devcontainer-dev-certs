import { describe, it, expect, afterEach, vi } from "vitest";
import { resolveSafeExecPath, runProcess } from "@devcontainer-dev-certs/shared";

/**
 * The resolver is Windows-specific defense against `CreateProcess`'s
 * cwd-first executable lookup. These tests drive the Windows branch
 * from any host by passing `platform: "win32"` plus an injected
 * `fileExists` probe and synthetic PATH / PATHEXT — no fixture files
 * on disk, no real environment dependencies.
 */
describe("resolveSafeExecPath", () => {
  it("returns the command unchanged on Linux", () => {
    const result = resolveSafeExecPath("dotnet", {
      platform: "linux",
      searchPath: "/usr/bin",
      fileExists: () => false,
    });
    expect(result).toBe("dotnet");
  });

  it("returns the command unchanged on macOS", () => {
    const result = resolveSafeExecPath("dotnet", {
      platform: "darwin",
      searchPath: "/usr/local/bin",
      fileExists: () => false,
    });
    expect(result).toBe("dotnet");
  });

  it("passes through absolute Windows paths verbatim", () => {
    const explicit = "C:\\Program Files\\dotnet\\dotnet.exe";
    const result = resolveSafeExecPath(explicit, {
      platform: "win32",
      searchPath: "C:\\Windows\\System32",
      fileExists: () => true,
    });
    expect(result).toBe(explicit);
  });

  it("passes through Windows paths with a separator verbatim", () => {
    const result = resolveSafeExecPath("bin\\dotnet.exe", {
      platform: "win32",
      searchPath: "C:\\Windows\\System32",
      fileExists: () => true,
    });
    expect(result).toBe("bin\\dotnet.exe");
  });

  it("scans PATH and appends PATHEXT entries for bare names on Windows", () => {
    const fileExists = (candidate: string): boolean =>
      candidate === "C:\\Program Files\\dotnet\\dotnet.exe";

    const result = resolveSafeExecPath("dotnet", {
      platform: "win32",
      searchPath: [
        "C:\\Windows\\System32",
        "C:\\Program Files\\dotnet",
      ].join(";"),
      pathExt: ".COM;.EXE;.BAT;.CMD",
      fileExists,
    });

    expect(result).toBe("C:\\Program Files\\dotnet\\dotnet.exe");
  });

  it("returns null when the command isn't found anywhere on Windows PATH", () => {
    const result = resolveSafeExecPath("nonexistent-tool", {
      platform: "win32",
      searchPath: "C:\\Windows\\System32;C:\\Program Files\\dotnet",
      pathExt: ".EXE;.CMD",
      fileExists: () => false,
    });
    expect(result).toBeNull();
  });

  it("does not append an extension to a command that already has one", () => {
    const seen: string[] = [];
    const fileExists = (candidate: string): boolean => {
      seen.push(candidate);
      return candidate === "C:\\Windows\\System32\\certutil.exe";
    };

    const result = resolveSafeExecPath("certutil.exe", {
      platform: "win32",
      searchPath: "C:\\Windows\\System32",
      pathExt: ".EXE;.CMD;.BAT",
      fileExists,
    });

    expect(result).toBe("C:\\Windows\\System32\\certutil.exe");
    // None of the probed candidates should be `certutil.exe.cmd`,
    // `certutil.exe.bat`, etc. — the extension matcher must short-circuit.
    expect(seen.every((p) => !/\.exe\.[a-z]+$/i.test(p))).toBe(true);
  });

  it("skips relative PATH entries to defeat cwd-equivalent hijacks", () => {
    const fileExists = (candidate: string): boolean => {
      // Anything probed from a relative entry would be 'bad-dir\dotnet.exe'.
      // Our resolver should never even check it.
      if (candidate.startsWith("bad-dir")) {
        throw new Error(
          `Resolver probed a relative PATH entry: ${candidate} — that's exactly the hijack vector we're defending against.`
        );
      }
      return candidate === "C:\\Program Files\\dotnet\\dotnet.exe";
    };

    const result = resolveSafeExecPath("dotnet", {
      platform: "win32",
      searchPath: ["bad-dir", ".", "C:\\Program Files\\dotnet"].join(";"),
      pathExt: ".EXE",
      fileExists,
    });

    expect(result).toBe("C:\\Program Files\\dotnet\\dotnet.exe");
  });

  it("resolves a command with an extension verbatim even when PATHEXT omits it", () => {
    // Regression: "has an extension" used to be derived from PATHEXT
    // membership, so a user who customized PATHEXT to drop `.EXE` got
    // `certutil.exe` probed as `certutil.exe.cmd` / `.bat` and a 127
    // even though the binary was on PATH. Windows resolves any name
    // that carries an extension verbatim; PATHEXT only governs the
    // suffixes tried for extensionLESS names.
    const seen: string[] = [];
    const fileExists = (candidate: string): boolean => {
      seen.push(candidate);
      return candidate === "C:\\Windows\\System32\\certutil.exe";
    };

    const result = resolveSafeExecPath("certutil.exe", {
      platform: "win32",
      searchPath: "C:\\Windows\\System32",
      pathExt: ".CMD;.BAT",
      fileExists,
    });

    expect(result).toBe("C:\\Windows\\System32\\certutil.exe");
    expect(seen).toEqual(["C:\\Windows\\System32\\certutil.exe"]);
  });

  it("treats PATHEXT case-insensitively (handles upper/mixed case extensions)", () => {
    // Real-world Windows defaults to upper-case `.COM;.EXE;.BAT;.CMD`, but the
    // matcher must work whether the user has rewritten it or not — and whether
    // the command was passed with a `.EXE` or `.exe` suffix. The filesystem
    // itself is case-insensitive on Windows, mirrored here in the probe.
    const fileExists = (candidate: string): boolean =>
      candidate.toLowerCase() === "c:\\windows\\system32\\certutil.exe";

    const result = resolveSafeExecPath("certutil.EXE", {
      platform: "win32",
      searchPath: "C:\\Windows\\System32",
      pathExt: ".COM;.EXE;.BAT;.CMD",
      fileExists,
    });

    expect(result).toBe("C:\\Windows\\System32\\certutil.EXE");
  });

  it("returns the first match wins (PATH order preserved)", () => {
    // Two candidate matches; the earlier PATH entry must win.
    const fileExists = (candidate: string): boolean =>
      candidate === "C:\\first\\dotnet.exe" ||
      candidate === "C:\\second\\dotnet.exe";

    const result = resolveSafeExecPath("dotnet", {
      platform: "win32",
      searchPath: ["C:\\first", "C:\\second"].join(";"),
      pathExt: ".EXE",
      fileExists,
    });

    expect(result).toBe("C:\\first\\dotnet.exe");
  });
});

/**
 * `runProcess` is the single chokepoint every production shell-out goes
 * through (the only non-test `child_process` import in the tree lives in
 * `processUtil.ts`). The tests below pin the guard branch that makes the
 * resolver load-bearing: on Windows, a command that fails to resolve
 * must yield a well-defined exit code 127 — NEVER fall through to a
 * cwd-first spawn. The distinct stderr message doubles as proof of which
 * branch ran: the guard returns `command not found on PATH: ...` before
 * `execFile` is ever invoked, whereas an actual spawn failure surfaces
 * the OS error (ENOENT) with exit code 1.
 *
 * `runProcess` takes no injection options by design (the chokepoint
 * shouldn't be steerable by callers), so these tests stub
 * `process.platform` / `process.env.PATH` instead. Both stubs are also
 * valid on a real Windows host: the platform stub is a no-op there and
 * the PATH stub points at a directory that exists on no machine.
 */
describe("runProcess safe-exec guard", () => {
  const originalPlatform = Object.getOwnPropertyDescriptor(
    process,
    "platform"
  )!;

  afterEach(() => {
    Object.defineProperty(process, "platform", originalPlatform);
    vi.unstubAllEnvs();
  });

  it("returns exit code 127 on Windows when the command is not on PATH", async () => {
    Object.defineProperty(process, "platform", {
      value: "win32",
      configurable: true,
    });
    vi.stubEnv("PATH", "C:\\devcerts-test-nonexistent-dir-8f3a");

    const result = await runProcess("devcerts-no-such-tool-8f3a", ["--version"]);

    expect(result.exitCode).toBe(127);
    expect(result.stderr).toBe(
      "command not found on PATH: devcerts-no-such-tool-8f3a"
    );
    expect(result.stdout).toBe("");
  });

  it("returns exit code 127 on Windows when PATH holds only relative entries", async () => {
    // A PATH consisting entirely of relative directories is the
    // cwd-equivalent hijack setup. The resolver must filter every entry,
    // find nothing, and hit the guard — not probe relative dirs.
    Object.defineProperty(process, "platform", {
      value: "win32",
      configurable: true,
    });
    vi.stubEnv("PATH", ".;bin;..\\tools");

    const result = await runProcess("certutil.exe", ["-dump"]);

    expect(result.exitCode).toBe(127);
    expect(result.stderr).toContain("command not found on PATH");
  });

  it.skipIf(process.platform === "win32")(
    "falls through to the OS spawn on non-Windows (ENOENT, not 127)",
    async () => {
      // On Linux/macOS the resolver passes bare names through untouched
      // (execvp never consults cwd, so there's nothing to defend). A
      // missing command therefore fails at spawn time with the OS error
      // (generic exit code 1, empty stderr from execFile's spawn-error
      // shape) — NOT the Windows guard's 127 + "command not found"
      // message. Asserting the difference pins that the guard is
      // Windows-only and non-Windows behavior is unchanged.
      const result = await runProcess("devcerts-no-such-tool-8f3a", []);

      expect(result.exitCode).toBe(1);
      expect(result.stderr).not.toContain("command not found on PATH");
    }
  );
});
