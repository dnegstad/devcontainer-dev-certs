import * as path from "path";

export function getToolBinaryName(): string {
  return process.platform === "win32" ? "devcerts.exe" : "devcerts";
}

export function getToolPath(extensionPath: string): string {
  return path.join(extensionPath, "bin", getToolBinaryName());
}
