import * as fs from "fs";
import { getOpenSslTrustDir, log } from "@devcontainer-dev-certs/shared";

// Absolute paths only. The value is sourced from workspace configuration
// (`devcontainer-dev-certs.sslCertDirs`), which a malicious workspace can set.
// It no longer reaches any shell-sourced file (we apply it only via VS Code's
// EnvironmentVariableCollection and process.env, neither of which evaluates
// shell metacharacters), so this is input hygiene rather than injection
// defense: reject anything that isn't a plain colon-separated list of POSIX
// absolute paths so we never hand OpenSSL a nonsense SSL_CERT_DIR.
const SAFE_PATH_CHAR = "[A-Za-z0-9._/+@%-]";
const SAFE_COLON_PATHS_RE = new RegExp(
  `^/${SAFE_PATH_CHAR}+(?::/${SAFE_PATH_CHAR}+)*$`
);

function isSafeColonPaths(value: string): boolean {
  return SAFE_COLON_PATHS_RE.test(value);
}

/**
 * The slice of VS Code's `EnvironmentVariableCollection` we use. Declared
 * structurally so this module stays free of a `vscode` import and the unit
 * tests can pass a trivial fake. `vscode.EnvironmentVariableCollection`
 * satisfies it (its methods take an optional extra options arg).
 */
export interface SslCertDirEnvSink {
  replace(variable: string, value: string): void;
  prepend(variable: string, value: string): void;
}

/**
 * Outcome of an {@link ensureSslCertDir} call, so the caller can log what
 * actually happened instead of unconditionally claiming success:
 *  - `configured`: we set SSL_CERT_DIR (`value` is the resulting value).
 *  - `already-present`: the trust dir was already on SSL_CERT_DIR; left as-is
 *    (`value` is the existing value).
 *  - `refused`: the input failed validation; nothing was changed (the reason
 *    has already been logged).
 */
export type EnsureSslCertDirResult =
  | { outcome: "configured"; value: string }
  | { outcome: "already-present"; value: string }
  | { outcome: "refused" };

/**
 * Ensure SSL_CERT_DIR includes the dev-certs trust directory alongside the
 * system CA directories, for processes launched from VS Code.
 *
 * Scope is deliberately VS Code-only. Two sinks, both transparent and
 * reversible — we do NOT edit `/etc/profile.d`, `~/.bashrc`, or any other
 * persistent config file:
 *   1. `envSink` (VS Code's `EnvironmentVariableCollection`) — applies to
 *      current and future integrated terminals and the tasks that run in them.
 *      VS Code attributes the change to this extension, shows it in the
 *      terminal UI, flags already-open terminals as stale, and tears it down
 *      when the extension is disabled/uninstalled.
 *   2. `process.env` — covers child processes the extension itself spawns
 *      during this run.
 *
 * Persistent, all-shell, system-wide configuration is intentionally NOT done
 * here. In devcontainers that is the feature's `install.sh` job (run at build
 * time, where the user has opted in by adding the feature). Non-devcontainer
 * remotes (raw SSH/WSL) are out of scope by design — if that need ever
 * materializes it should be an explicit, consented, user-invoked action rather
 * than a silent side effect of activation.
 *
 * When `pruneMissingDirs` is set (the default system-dir list is in use, not an
 * explicit user override), drop any system CA dir that doesn't exist on this
 * host. The defaults span several distros' paths; only a subset exists on any
 * given OS. OpenSSL ignores a missing dir, but some consumers (Rust's
 * openssl-probe / rustls-native-certs) error on one, so we keep only the dirs
 * that are actually present. An explicit override is honored as-is.
 *
 * Returns an {@link EnsureSslCertDirResult} describing what was done — the
 * caller should only report success when the outcome is `configured`.
 */
export function ensureSslCertDir(
  envSink: SslCertDirEnvSink,
  systemCertDirs: string,
  pruneMissingDirs = false
): EnsureSslCertDirResult {
  const trustDir = getOpenSslTrustDir();
  const currentValue = process.env["SSL_CERT_DIR"] ?? "";

  // Already includes the trust dir — the devcontainer feature's install.sh
  // (or a prior run) got there first. Adding it again would only produce a
  // duplicated path element, so leave it untouched.
  if (currentValue.split(":").includes(trustDir)) {
    return { outcome: "already-present", value: currentValue };
  }

  if (!isSafeColonPaths(systemCertDirs)) {
    log(
      `Refusing to configure SSL_CERT_DIR: sslCertDirs value contains unexpected characters. ` +
        `Expected colon-separated absolute paths only.`
    );
    return { outcome: "refused" };
  }
  if (!isSafeColonPaths(trustDir)) {
    log(
      `Refusing to configure SSL_CERT_DIR: computed trust dir contains unexpected characters.`
    );
    return { outcome: "refused" };
  }

  if (currentValue.length > 0) {
    // The environment already carries system CA dirs (a base image set
    // SSL_CERT_DIR but without our trust dir). Don't clobber them or re-inject
    // our own system-dir list — just prepend the trust dir so it takes
    // precedence. EnvironmentVariableCollection prepends onto each terminal's
    // own inherited value at launch; mirror that into process.env for this run.
    envSink.prepend("SSL_CERT_DIR", `${trustDir}:`);
    const resolved = `${trustDir}:${currentValue}`;
    process.env["SSL_CERT_DIR"] = resolved;
    return { outcome: "configured", value: resolved };
  }

  // Nothing inherited — we own the whole value, so we must supply the system CA
  // dirs ourselves (otherwise setting SSL_CERT_DIR to the trust dir alone would
  // override the system default and drop trust of the real CAs). Prune absent
  // dirs from the defaults; compose empty-safe so a fully-pruned list yields the
  // trust dir alone rather than a trailing-colon empty path element.
  let effectiveSystemDirs = systemCertDirs;
  if (pruneMissingDirs) {
    const present = systemCertDirs.split(":").filter((dir) => {
      try {
        return fs.statSync(dir).isDirectory();
      } catch {
        return false;
      }
    });
    effectiveSystemDirs = present.join(":");
  }

  const desiredValue = effectiveSystemDirs
    ? `${trustDir}:${effectiveSystemDirs}`
    : trustDir;

  envSink.replace("SSL_CERT_DIR", desiredValue);
  process.env["SSL_CERT_DIR"] = desiredValue;
  return { outcome: "configured", value: desiredValue };
}
