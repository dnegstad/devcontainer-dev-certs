import type * as vscode from "vscode";
import { log } from "@devcontainer-dev-certs/shared";

const KESTREL_PATH_ENV = "ASPNETCORE_Kestrel__Certificates__Default__Path";
const KESTREL_PASSWORD_ENV =
  "ASPNETCORE_Kestrel__Certificates__Default__Password";

export interface KestrelDefaultEnv {
  path: string;
  /** When undefined, the on-disk PFX is passwordless. */
  password?: string;
}

export interface KestrelDefaultEnvHolder {
  current: KestrelDefaultEnv | undefined;
}

/**
 * Module-level holder shared between the activation path (which sets
 * the selection when a bundle's `defaultKestrelCert` pointer resolves)
 * and the debug provider below (which reads it on every launch).
 *
 * Keeping the state in one place — rather than re-deriving from
 * `EnvironmentVariableCollection`, which is opaque — means the env
 * collection and the debug provider can't drift out of sync.
 */
export const kestrelDefaultEnvHolder: KestrelDefaultEnvHolder = {
  current: undefined,
};

/**
 * Counterpart to the EnvironmentVariableCollection path. VS Code applies
 * env collections to terminals it spawns, but debug adapters like
 * `coreclr` build the child-process environment themselves and don't
 * see those mutations. Without this provider, F5 launches via C# Dev
 * Kit / Aspire would miss the Kestrel default vars even though the
 * integrated terminal picks them up fine.
 *
 * The provider uses `resolveDebugConfigurationWithSubstitutedVariables`
 * (the late hook) so the C# Dev Kit's launchSettings.json merge has
 * already populated `config.env` by the time we run. We then layer our
 * two vars on top, taking precedence on key collisions — the user has
 * a single source of truth (`defaultKestrelCertificate`), and a stale
 * `__Path` or `__Password` in a launchSettings.json profile shouldn't
 * silently win over the current selection.
 *
 * The optional `holder` parameter lets tests inject an isolated state
 * object instead of mutating the module-level singleton.
 */
export function createDefaultKestrelDebugProvider(
  holder: KestrelDefaultEnvHolder = kestrelDefaultEnvHolder
): vscode.DebugConfigurationProvider {
  return {
    resolveDebugConfigurationWithSubstitutedVariables(_folder, config) {
      const selection = holder.current;
      if (!selection) return config;

      const existingEnv =
        (config.env as Record<string, string> | null | undefined) ?? {};

      const overrides: string[] = [];
      if (
        Object.prototype.hasOwnProperty.call(existingEnv, KESTREL_PATH_ENV) &&
        existingEnv[KESTREL_PATH_ENV] !== selection.path
      ) {
        overrides.push(KESTREL_PATH_ENV);
      }
      const desiredPassword = selection.password ?? "";
      if (
        Object.prototype.hasOwnProperty.call(
          existingEnv,
          KESTREL_PASSWORD_ENV
        ) &&
        existingEnv[KESTREL_PASSWORD_ENV] !== desiredPassword
      ) {
        overrides.push(KESTREL_PASSWORD_ENV);
      }

      const newEnv: Record<string, string> = {
        ...existingEnv,
        [KESTREL_PATH_ENV]: selection.path,
      };
      if (selection.password !== undefined) {
        newEnv[KESTREL_PASSWORD_ENV] = selection.password;
      } else {
        // Our PFX is passwordless. If the user's launchSettings.json had a
        // stale __Password, dropping it here keeps Kestrel from trying the
        // wrong password against our file.
        delete newEnv[KESTREL_PASSWORD_ENV];
      }

      if (overrides.length > 0) {
        log(
          `Debug config '${config.name ?? "<unnamed>"}': overrode ${overrides.join(
            ", "
          )} from launch config with defaultKestrelCertificate selection.`
        );
      }

      return { ...config, env: newEnv };
    },
  };
}
