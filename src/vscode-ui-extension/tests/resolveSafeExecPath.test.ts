import { describe, it, expect } from "vitest";
import { resolveSafeExecPath } from "@devcontainer-dev-certs/shared";

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
