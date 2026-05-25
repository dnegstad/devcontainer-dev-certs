import * as vscode from "vscode";
import { setLogSink } from "./logger";

/**
 * VS Code-host helper: create a named OutputChannel and wire it up as the
 * shared log sink. Returns the channel so the caller can register it with
 * `context.subscriptions.push(...)` for automatic disposal.
 *
 * Kept in a dedicated submodule (not re-exported from the package barrel) so
 * the shared cert / platform layer remains importable from non-VS-Code
 * contexts (host CLI, scripts) without resolving `vscode` at module load.
 */
export function initLogger(channelName: string): vscode.OutputChannel {
  const channel = vscode.window.createOutputChannel(channelName);
  setLogSink(channel);
  return channel;
}
