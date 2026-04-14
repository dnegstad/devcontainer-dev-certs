import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface ProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * Run an external process and return its exit code, stdout, and stderr.
 * Does not throw on non-zero exit codes.
 */
export async function runProcess(
  command: string,
  args: string[],
  timeout: number = 30000
): Promise<ProcessResult> {
  try {
    const result = await execFileAsync(command, args, { timeout });
    return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (err: unknown) {
    const error = err as Error & {
      code?: number | string;
      stdout?: string;
      stderr?: string;
    };
    // If the process ran but returned non-zero, we still have stdout/stderr
    const exitCode =
      typeof error.code === "number" ? error.code : 1;
    return {
      exitCode,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? error.message,
    };
  }
}
