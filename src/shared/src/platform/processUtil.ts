import { execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface ProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ResolveSafeExecPathOptions {
  /**
   * Override the detected platform. Default is `process.platform`. Tests
   * use this to drive the Windows branch from Linux/macOS hosts.
   */
  platform?: NodeJS.Platform;
  /**
   * PATH-like delimiter-separated list of directories to search. Default
   * is `process.env.PATH`.
   */
  searchPath?: string;
  /**
   * PATHEXT-style semicolon-separated list of executable suffixes to try
   * when the command has no extension. Default is `process.env.PATHEXT`,
   * falling back to the conventional Windows set if that's unset.
   */
  pathExt?: string;
  /**
   * File-existence probe. Injectable so tests can drive the resolver
   * without writing real fixture files to disk.
   */
  fileExists?: (candidate: string) => boolean;
}

/**
 * Resolve a bare command name (`"dotnet"`, `"certutil.exe"`) to an
 * absolute path on the executable search PATH, defeating Windows'
 * cwd-first `CreateProcess` lookup. By handing `child_process.spawn`
 * an absolute path, we skip the application-dir / cwd / system-dirs /
 * PATH cascade entirely — a malicious `dotnet.exe` dropped into the
 * user's workspace by a compromised dev-container repo can no longer
 * hijack our shell-outs.
 *
 * Behavior:
 *
 * - Non-Windows hosts: returns the command unchanged. `execvp`-family
 *   syscalls on Linux / macOS never consult `cwd`, so the cwd-first
 *   hijack vector doesn't exist there and we save the disk walk.
 * - Absolute paths or paths containing a separator: pass through
 *   verbatim. The caller has expressed explicit intent (e.g. an env
 *   var override) and we don't second-guess.
 * - Bare names on Windows: scan PATH, respecting PATHEXT for implicit
 *   extensions. Returns `null` if the command isn't found on PATH —
 *   the caller (typically `runProcess`) translates that into a
 *   well-defined "command not found" `ProcessResult` rather than
 *   falling through to the unsafe spawn.
 * - Relative PATH entries are skipped on Windows. A user who's added
 *   `.` (or `bin`, or any other relative directory) to PATH would
 *   re-introduce the exact hijack we're trying to prevent. Filtering
 *   them costs nothing for normal setups and provides defense in
 *   depth for hostile ones.
 */
export function resolveSafeExecPath(
  command: string,
  options: ResolveSafeExecPathOptions = {}
): string | null {
  const platform = options.platform ?? process.platform;

  if (platform !== "win32") {
    return command;
  }

  // Use Windows path semantics regardless of the host OS — tests drive
  // the Windows branch from Linux/macOS via the `platform` override and
  // expect `C:\...` to be recognized as absolute, `;` as the PATH
  // delimiter, etc.
  const winPath = path.win32;

  if (
    winPath.isAbsolute(command) ||
    command.includes("/") ||
    command.includes("\\")
  ) {
    return command;
  }

  const searchPath = options.searchPath ?? process.env.PATH ?? "";
  const pathExt =
    options.pathExt ?? process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD";
  const fileExists = options.fileExists ?? fs.existsSync;

  const dirs = searchPath
    .split(winPath.delimiter)
    .map((d) => d.trim())
    .filter((d) => d.length > 0 && winPath.isAbsolute(d));
  const extensions = pathExt
    .split(";")
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.length > 0);

  const commandLower = command.toLowerCase();
  const hasExplicitExtension = extensions.some((ext) =>
    commandLower.endsWith(ext)
  );

  for (const dir of dirs) {
    if (hasExplicitExtension) {
      const candidate = winPath.join(dir, command);
      if (fileExists(candidate)) return candidate;
    } else {
      for (const ext of extensions) {
        const candidate = winPath.join(dir, command + ext);
        if (fileExists(candidate)) return candidate;
      }
    }
  }

  return null;
}

/**
 * Run an external process and return its exit code, stdout, and stderr.
 * Does not throw on non-zero exit codes.
 *
 * On Windows, the command is resolved through `resolveSafeExecPath`
 * before being handed to `execFile`. This is the single chokepoint for
 * all of our shell-outs (dotnet backend, certutil.exe in the Windows
 * store, pwsh, openssl, etc.), so the cwd-planting defense applies
 * uniformly. Commands that resolve to `null` (not found on PATH) return
 * `exitCode: 127` rather than falling through to a `cwd`-first spawn.
 */
export async function runProcess(
  command: string,
  args: string[],
  timeout: number = 30000
): Promise<ProcessResult> {
  const resolved = resolveSafeExecPath(command);
  if (resolved === null) {
    return {
      exitCode: 127,
      stdout: "",
      stderr: `command not found on PATH: ${command}`,
    };
  }
  try {
    const result = await execFileAsync(resolved, args, { timeout });
    return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (err: unknown) {
    const error = err as Error & {
      code?: number | string;
      stdout?: string;
      stderr?: string;
    };
    // If the process ran but returned non-zero, we still have stdout/stderr
    const exitCode = typeof error.code === "number" ? error.code : 1;
    return {
      exitCode,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? error.message,
    };
  }
}
