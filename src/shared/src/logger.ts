import * as vscode from "vscode";

let channel: vscode.OutputChannel | undefined;

/**
 * Initialize the shared logger with an output channel.
 * Call once from the extension's activate() function.
 * Returns the channel so it can be registered as a disposable.
 */
export function initLogger(channelName: string): vscode.OutputChannel {
  channel = vscode.window.createOutputChannel(channelName);
  return channel;
}

/**
 * Log a timestamped message to the output channel.
 * Requires initLogger() to have been called first.
 */
export function log(message: string): void {
  channel?.appendLine(`[${new Date().toISOString()}] ${message}`);
}

/**
 * Reveal the shared output channel so the user can read what we just
 * logged. `preserveFocus = true` keeps the keyboard focus where it was
 * (typically a modal we're about to show), which avoids the panel
 * stealing focus mid-prompt. No-op when the logger hasn't been
 * initialised.
 */
export function revealLogger(): void {
  channel?.show(true);
}
