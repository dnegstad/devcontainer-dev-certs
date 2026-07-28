import * as vscode from "vscode";

const MODERN_SECTION = "devcontainerDevCerts";
const LEGACY_SECTION = "devcontainer-dev-certs";

/**
 * Read a setting that was renamed from the legacy hyphenated prefix
 * (`devcontainer-dev-certs.*`) to the canonical camelCase prefix
 * (`devcontainerDevCerts.*`) so every setting groups under one heading
 * in the Settings UI.
 *
 * Precedence: an explicitly-set modern value wins; otherwise an
 * explicitly-set legacy value is honored (so existing user config keeps
 * working without migration); otherwise `defaultValue`. "Explicitly
 * set" is determined via `inspect()` — the declared default on either
 * name never shadows a real user value on the other.
 */
export function getRenamedSetting<T>(key: string, defaultValue: T): T {
  const modern = vscode.workspace
    .getConfiguration(MODERN_SECTION)
    .inspect<T>(key);
  const modernValue =
    modern?.workspaceFolderValue ?? modern?.workspaceValue ?? modern?.globalValue;
  if (modernValue !== undefined) return modernValue;

  const legacy = vscode.workspace
    .getConfiguration(LEGACY_SECTION)
    .inspect<T>(key);
  const legacyValue =
    legacy?.workspaceFolderValue ?? legacy?.workspaceValue ?? legacy?.globalValue;
  if (legacyValue !== undefined) return legacyValue;

  return defaultValue;
}
