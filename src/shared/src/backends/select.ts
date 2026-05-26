import { DotnetBackend } from "./dotnet";
import { NativeBackend } from "./native";
import type { Backend, BackendKind, BackendMode } from "./types";

/**
 * Resolve a `--backend` choice (possibly `auto`) into a concrete backend
 * instance. `auto` prefers `dotnet` on macOS when the `dotnet` CLI is on
 * PATH (better keychain-trust UX via a signed binary), `native` everywhere
 * else.
 */
export async function selectBackend(mode: BackendMode): Promise<Backend> {
  if (mode === "native") return new NativeBackend();
  if (mode === "dotnet") {
    const backend = new DotnetBackend();
    if (!(await backend.isAvailable())) {
      throw new Error(
        "Requested --backend dotnet but the `dotnet` CLI was not found on PATH."
      );
    }
    return backend;
  }
  if (mode === "auto") return autoSelect();
  throw new Error(`Unknown backend mode: ${String(mode)}`);
}

async function autoSelect(): Promise<Backend> {
  if (process.platform === "darwin") {
    const dotnet = new DotnetBackend();
    if (await dotnet.isAvailable()) return dotnet;
  }
  return new NativeBackend();
}

/**
 * Report which backend `auto` would pick on this host without actually
 * constructing it. Useful for `dcdc doctor` and for status surfaces in the
 * VS Code host extension.
 */
export async function describeAutoBackend(): Promise<BackendKind> {
  if (process.platform === "darwin") {
    const dotnet = new DotnetBackend();
    if (await dotnet.isAvailable()) return "dotnet";
  }
  return "native";
}
