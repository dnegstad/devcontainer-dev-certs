import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runProcess } from "./processUtil";
import { log } from "../logger";

export interface NssTrustResult {
  success: boolean;
  message: string;
}

const CERT_NAME = "Dev Container Dev Cert";

type NssTargetKind = "chromium-shared" | "firefox-profiles";

interface NssTarget {
  label: string;
  kind: NssTargetKind;
  root: string;
}

interface DbOutcome {
  label: string;
  ok: boolean;
  stderr?: string;
}

/**
 * Enumerate well-known NSS database roots on Linux. Covers native packages,
 * Snap and Flatpak sandbox roots, and a handful of Firefox forks that keep
 * their own profile directory. The list is ordered most-common-first; missing
 * roots are silently skipped at scan time.
 */
function getNssTargets(home: string): NssTarget[] {
  const chromium = (label: string, ...segs: string[]): NssTarget => ({
    label,
    kind: "chromium-shared",
    root: path.join(home, ...segs),
  });
  const firefox = (label: string, ...segs: string[]): NssTarget => ({
    label,
    kind: "firefox-profiles",
    root: path.join(home, ...segs),
  });

  return [
    // Chromium-family browsers share a single user NSS DB. The native
    // ~/.pki/nssdb path is the historical shared store used by Chromium,
    // Chrome, Brave, Vivaldi, Edge, and Opera when installed as deb/rpm/AUR.
    chromium("Chromium", ".pki", "nssdb"),
    chromium("Chromium (Snap)", "snap", "chromium", "common", ".pki", "nssdb"),
    chromium(
      "Chromium (Flatpak)",
      ".var",
      "app",
      "org.chromium.Chromium",
      ".pki",
      "nssdb"
    ),
    chromium(
      "Chrome (Flatpak)",
      ".var",
      "app",
      "com.google.Chrome",
      ".pki",
      "nssdb"
    ),
    chromium(
      "Brave (Flatpak)",
      ".var",
      "app",
      "com.brave.Browser",
      ".pki",
      "nssdb"
    ),
    chromium(
      "Vivaldi (Flatpak)",
      ".var",
      "app",
      "com.vivaldi.Vivaldi",
      ".pki",
      "nssdb"
    ),
    chromium(
      "Edge (Flatpak)",
      ".var",
      "app",
      "com.microsoft.Edge",
      ".pki",
      "nssdb"
    ),

    // Firefox-family browsers keep an NSS DB per profile under a known root.
    firefox("Firefox", ".mozilla", "firefox"),
    firefox(
      "Firefox (Snap)",
      "snap",
      "firefox",
      "common",
      ".mozilla",
      "firefox"
    ),
    firefox(
      "Firefox (Flatpak)",
      ".var",
      "app",
      "org.mozilla.firefox",
      ".mozilla",
      "firefox"
    ),
    firefox("Firefox ESR", ".mozilla", "firefox-esr"),
    firefox("LibreWolf", ".librewolf"),
    firefox(
      "LibreWolf (Flatpak)",
      ".var",
      "app",
      "io.gitlab.librewolf-community",
      ".librewolf"
    ),
    firefox("Waterfox", ".waterfox"),
    firefox("Floorp", ".floorp"),
  ];
}

/**
 * Attempt to trust a PEM certificate in NSS databases used by Linux browsers.
 *
 * Requires `certutil` on the PATH (from libnss3-tools / nss-tools / nss).
 * Enumerates well-known NSS database roots — native deb/rpm installs, Snap
 * and Flatpak sandboxes, and Firefox forks — and adds the certificate to each
 * existing database. Targets that aren't installed are skipped silently; the
 * returned message lists only databases we actually touched.
 */
export async function trustInNss(pemPath: string): Promise<NssTrustResult> {
  const which = await runProcess("which", ["certutil"]);
  if (which.exitCode !== 0) {
    return {
      success: false,
      message:
        "certutil is not installed. Install libnss3-tools (Debian/Ubuntu), nss-tools (Fedora/RHEL), or nss (Arch) to enable automatic browser trust.",
    };
  }

  const outcomes: DbOutcome[] = [];
  const targets = getNssTargets(os.homedir());

  for (const target of targets) {
    if (target.kind === "chromium-shared") {
      await scanChromiumShared(target, pemPath, outcomes);
    } else {
      await scanFirefoxProfiles(target, pemPath, outcomes);
    }
  }

  if (outcomes.length === 0) {
    return {
      success: false,
      message:
        "No browser NSS databases found. Open Firefox or Chromium at least once to create a profile, then try again.",
    };
  }

  const trusted = outcomes.filter((o) => o.ok).map((o) => o.label);
  const failed = outcomes.filter((o) => !o.ok);

  const parts: string[] = [];
  if (trusted.length > 0) parts.push(`Trusted in: ${trusted.join(", ")}`);
  for (const f of failed) {
    parts.push(`${f.label}: failed (${f.stderr?.trim() ?? "unknown error"})`);
  }

  return {
    success: failed.length === 0,
    message: parts.join("; "),
  };
}

async function scanChromiumShared(
  target: NssTarget,
  pemPath: string,
  outcomes: DbOutcome[]
): Promise<void> {
  if (!fs.existsSync(path.join(target.root, "cert9.db"))) {
    log(`NSS scan: ${target.label} not present at ${target.root}, skipping.`);
    return;
  }
  const r = await trustInNssDb(`sql:${target.root}`, pemPath);
  outcomes.push({
    label: target.label,
    ok: r.exitCode === 0,
    stderr: r.stderr,
  });
}

async function scanFirefoxProfiles(
  target: NssTarget,
  pemPath: string,
  outcomes: DbOutcome[]
): Promise<void> {
  if (!fs.existsSync(target.root)) {
    log(`NSS scan: ${target.label} not present at ${target.root}, skipping.`);
    return;
  }

  let entries: string[];
  try {
    entries = fs.readdirSync(target.root);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`NSS scan: failed to enumerate ${target.label} profiles: ${message}`);
    return;
  }

  const profiles = entries.filter((d) => {
    try {
      return fs.existsSync(path.join(target.root, d, "cert9.db"));
    } catch {
      return false;
    }
  });

  if (profiles.length === 0) {
    log(`NSS scan: ${target.label} has no profiles with cert9.db, skipping.`);
    return;
  }

  for (const profile of profiles) {
    const dbPath = path.join(target.root, profile);
    const r = await trustInNssDb(`sql:${dbPath}`, pemPath);
    outcomes.push({
      label: `${target.label} (${profile})`,
      ok: r.exitCode === 0,
      stderr: r.stderr,
    });
  }
}

async function trustInNssDb(
  dbArg: string,
  pemPath: string
): Promise<{ exitCode: number; stderr: string }> {
  // Remove any existing cert with this name first to make the operation idempotent
  await runProcess("certutil", ["-D", "-d", dbArg, "-n", CERT_NAME]);

  const result = await runProcess("certutil", [
    "-A",
    "-d",
    dbArg,
    "-t",
    "CT,,",
    "-n",
    CERT_NAME,
    "-i",
    pemPath,
  ]);

  if (result.exitCode === 0) {
    log(`Trusted cert in NSS database: ${dbArg}`);
  } else {
    log(`Failed to trust cert in ${dbArg}: ${result.stderr}`);
  }

  return { exitCode: result.exitCode, stderr: result.stderr };
}
