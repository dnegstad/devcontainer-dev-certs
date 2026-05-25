/**
 * Generic log sink interface — structurally compatible with
 * `vscode.OutputChannel` so the VS Code extension hosts can plug their
 * channel directly into `setLogSink`. Non-VS-Code consumers (the host CLI,
 * scripts) supply their own implementation (typically a console wrapper) so
 * the shared cert / platform layer can call `log()` without a `vscode`
 * dependency.
 */
export interface LogSink {
  appendLine(message: string): void;
  /** Optional. Honored by `revealLogger`. */
  show?(preserveFocus: boolean): void;
}

let sink: LogSink | undefined;

/**
 * Wire up the active log sink. `undefined` disables logging entirely. Safe
 * to call repeatedly — the most recent call wins.
 */
export function setLogSink(newSink: LogSink | undefined): void {
  sink = newSink;
}

/**
 * Log a timestamped message to the active sink. No-op if no sink is set —
 * the platform / cert layer calls this freely without coordinating with
 * its hosts about whether logging is enabled.
 */
export function log(message: string): void {
  sink?.appendLine(`[${new Date().toISOString()}] ${message}`);
}

/**
 * Reveal the active sink (VS Code OutputChannel.show). `preserveFocus = true`
 * so a concurrent prompt doesn't lose focus. No-op if uninitialized or the
 * sink doesn't implement `show`.
 */
export function revealLogger(): void {
  sink?.show?.(true);
}
