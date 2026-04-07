import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { getOpenSslTrustDir } from "./paths";

/**
 * Ensure SSL_CERT_DIR includes the dev-certs trust directory alongside
 * the system CA directories.
 *
 * In devcontainer scenarios, the feature's containerEnv handles this.
 * For SSH remoting, WSL, and other remotes, the workspace extension
 * handles it here by writing a profile script if SSL_CERT_DIR isn't
 * already configured with the trust directory.
 */
export function ensureSslCertDir(systemCertDirs: string): void {
  const trustDir = getOpenSslTrustDir();
  const currentValue = process.env["SSL_CERT_DIR"] ?? "";

  // Already includes the trust dir — devcontainer feature or prior run handled it
  if (currentValue.split(":").includes(trustDir)) {
    return;
  }

  const desiredValue = `${trustDir}:${systemCertDirs}`;

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
        `export SSL_CERT_DIR="${desiredValue}"\n`,
        { mode: 0o644 }
      );
    }
  } catch {
    // Not critical — the containerEnv or manual configuration can handle it.
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
          `\n${marker}\nexport SSL_CERT_DIR="${desiredValue}"\n`
        );
      }
    }
  } catch {
    // Best-effort
  }
}
