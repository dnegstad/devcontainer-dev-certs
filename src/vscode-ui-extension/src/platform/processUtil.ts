import { execFile } from "child_process";
import { promisify } from "util";
import * as vscode from "vscode";

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

/**
 * Run a command in a visible VS Code terminal and wait for it to complete.
 * Returns the process exit code. The terminal is disposed automatically
 * after the process exits.
 *
 * Use this for trust operations so users can see what's being executed.
 */
export function runInTerminal(
  name: string,
  command: string,
  args: string[]
): Promise<number> {
  return new Promise((resolve) => {
    const terminal = vscode.window.createTerminal({
      name,
      shellPath: command,
      shellArgs: args,
      isTransient: true,
    });
    terminal.show();

    const disposable = vscode.window.onDidCloseTerminal((t) => {
      if (t === terminal) {
        disposable.dispose();
        resolve(t.exitStatus?.code ?? 1);
      }
    });
  });
}
