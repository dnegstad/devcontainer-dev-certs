import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { getOpenSslTrustDir, log } from "@devcontainer-dev-certs/shared";

// Absolute paths only, no shell metacharacters. The value is sourced from
// workspace configuration (`devcontainer-dev-certs.sslCertDirs`) which a
// malicious workspace can set — we get written into shell profile files
// that run at every login, so we reject anything that isn't a plain
// colon-separated list of POSIX paths.
const SAFE_PATH_CHAR = "[A-Za-z0-9._/+@%-]";
const SAFE_COLON_PATHS_RE = new RegExp(
  `^/${SAFE_PATH_CHAR}+(?::/${SAFE_PATH_CHAR}+)*$`
);

function isSafeColonPaths(value: string): boolean {
  return SAFE_COLON_PATHS_RE.test(value);
}

// Belt-and-braces: even though we've validated the input, we still emit the
// shell line with single quotes so a future regression in the validator
// can't smuggle through command substitution. POSIX shells don't expand
// anything inside single quotes — a literal `'` is encoded by closing the
// quoted string, emitting an escaped quote, and reopening.
function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Outcome of an {@link ensureSslCertDir} call, so the caller can log what
 * actually happened instead of unconditionally claiming success:
 *  - `configured`: we composed and set SSL_CERT_DIR (`value` is the new value).
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
 * Ensure SSL_CERT_DIR includes the dev-certs trust directory alongside
 * the system CA directories.
 *
 * In devcontainer scenarios, the feature's install.sh handles this by
 * writing /etc/profile.d/devcontainer-dev-certs.sh and /etc/environment.
 * For SSH remoting, WSL, and other remotes, the workspace extension
 * handles it here by writing a profile script if SSL_CERT_DIR isn't
 * already configured with the trust directory.
 *
 * When `pruneMissingDirs` is set (the default system-dir list is in use,
 * not an explicit user override), drop any system CA dir that doesn't exist
 * on this host. The defaults span several distros' paths; only a subset
 * exists on any given OS. OpenSSL ignores a missing dir, but some consumers
 * (Rust's openssl-probe / rustls-native-certs) error on one, so we keep only
 * the dirs that are actually present. An explicit override is honored as-is.
 *
 * Returns an {@link EnsureSslCertDirResult} describing what was done — the
 * caller should only report success when the outcome is `configured`.
 */
export function ensureSslCertDir(
  systemCertDirs: string,
  pruneMissingDirs = false
): EnsureSslCertDirResult {
  const trustDir = getOpenSslTrustDir();
  const currentValue = process.env["SSL_CERT_DIR"] ?? "";

  // Already includes the trust dir — devcontainer feature or prior run handled it
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

  // Compose empty-safe: when pruning leaves no system dirs, emit the trust
  // dir alone rather than `${trustDir}:` — a trailing empty path element is
  // exactly the artifact the pruning above is meant to avoid.
  const desiredValue = effectiveSystemDirs
    ? `${trustDir}:${effectiveSystemDirs}`
    : trustDir;
  const quoted = shellSingleQuote(desiredValue);

  // Set for the current process and any child processes we spawn
  process.env["SSL_CERT_DIR"] = desiredValue;

  // Write a profile script so new terminal sessions pick it up too.
  // This is best-effort — may fail if we don't have write access.
  const profileDir = "/etc/profile.d";
  const profileScript = path.join(profileDir, "devcerts-ssl-cert-dir.sh");
  try {
    if (fs.existsSync(profileDir) && !fs.existsSync(profileScript)) {
      fs.writeFileSync(
        profileScript,
        `export SSL_CERT_DIR=${quoted}\n`,
        { mode: 0o644 }
      );
    }
  } catch {
    // Not critical — the feature's profile.d script or manual configuration can handle it.
    // This just improves the experience for terminal sessions.
  }

  // Also try writing to the user's shell profile as a fallback (for SSH remoting
  // where we likely don't have root access to /etc/profile.d)
  try {
    const bashrc = path.join(os.homedir(), ".bashrc");
    if (fs.existsSync(bashrc)) {
      const content = fs.readFileSync(bashrc, "utf-8");
      const marker = "# devcerts-ssl-cert-dir";
      if (!content.includes(marker)) {
        fs.appendFileSync(
          bashrc,
          `\n${marker}\nexport SSL_CERT_DIR=${quoted}\n`
        );
      }
    }
  } catch {
    // Best-effort
  }

  return { outcome: "configured", value: desiredValue };
}
