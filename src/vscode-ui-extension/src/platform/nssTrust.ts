import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runProcess } from "./processUtil";
import { log } from "@devcontainer-dev-certs/shared";

export interface NssTrustResult {
  success: boolean;
  message: string;
}

const CERT_NAME = "Dev Container Dev Cert";

/**
 * Attempt to trust a PEM certificate in NSS databases used by Firefox and Chromium.
 *
 * Checks for `certutil` on the PATH. If available, enumerates known NSS database
 * locations (Chromium's ~/.pki/nssdb and Firefox profile directories) and adds the
 * certificate to each. Returns a result indicating success or explaining why
 * automatic trust could not be completed.
 */
export async function trustInNss(pemPath: string): Promise<NssTrustResult> {
  const which = await runProcess("which", ["certutil"]);
  if (which.exitCode !== 0) {
    return {
      success: false,
      message: "certutil is not installed. Install libnss3-tools (Debian/Ubuntu), nss-tools (Fedora/RHEL), or nss (Arch) to enable automatic browser trust.",
    };
  }

  const results: string[] = [];

  // Chromium uses a single well-known NSS database
  const chromiumNssDb = path.join(os.homedir(), ".pki", "nssdb");
  if (fs.existsSync(path.join(chromiumNssDb, "cert9.db"))) {
    const r = await trustInNssDb(`sql:${chromiumNssDb}`, pemPath);
    results.push(r.exitCode === 0
      ? "Chromium: trusted"
      : `Chromium: failed (${r.stderr.trim()})`);
  }

  // Firefox stores a separate NSS database in each profile directory
  const firefoxDir = path.join(os.homedir(), ".mozilla", "firefox");
  if (fs.existsSync(firefoxDir)) {
    try {
      const profiles = fs.readdirSync(firefoxDir).filter((d) => {
        try {
          return fs.existsSync(path.join(firefoxDir, d, "cert9.db"));
        } catch {
          return false;
        }
      });

      for (const profile of profiles) {
        const dbPath = path.join(firefoxDir, profile);
        const r = await trustInNssDb(`sql:${dbPath}`, pemPath);
        results.push(r.exitCode === 0
          ? `Firefox (${profile}): trusted`
          : `Firefox (${profile}): failed (${r.stderr.trim()})`);
      }
    } catch {
      log("Failed to enumerate Firefox profiles");
    }
  }

  if (results.length === 0) {
    return {
      success: false,
      message: "No browser NSS databases found. Open Firefox or Chromium at least once to create a profile, then try again.",
    };
  }

  const allSucceeded = results.every((r) => r.includes(": trusted"));
  return {
    success: allSucceeded,
    message: results.join("; "),
  };
}

async function trustInNssDb(
  dbArg: string,
  pemPath: string
): Promise<{ exitCode: number; stderr: string }> {
  // Remove any existing cert with this name first to make the operation idempotent
  await runProcess("certutil", ["-D", "-d", dbArg, "-n", CERT_NAME]);

  const result = await runProcess("certutil", [
    "-A",
    "-d", dbArg,
    "-t", "CT,,",
    "-n", CERT_NAME,
    "-i", pemPath,
  ]);

  if (result.exitCode === 0) {
    log(`Trusted cert in NSS database: ${dbArg}`);
  } else {
    log(`Failed to trust cert in ${dbArg}: ${result.stderr}`);
  }

  return { exitCode: result.exitCode, stderr: result.stderr };
}
