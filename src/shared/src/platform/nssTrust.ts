import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runProcess } from "./processUtil";
import { log } from "../logger";
import { DevCert } from "../cert/types";

export interface NssTrustResult {
  success: boolean;
  message: string;
}

/**
 * Nickname stem. NSS nicknames are unique per database, so the thumbprint is
 * appended (see `nicknameFor`) — without it, trusting a second dev cert would
 * evict the first from every browser DB, which is exactly the ping-ponging
 * `LinuxCertificateStore.trustViaOpenSsl` was deliberately made additive to
 * avoid. Host-generated and container-pushed certs have to coexist here too.
 */
const CERT_NAME = "Dev Container Dev Cert";

/**
 * Nickname used by versions before per-cert nicknames existed. Removed
 * alongside the per-cert entry on every add so an upgrade doesn't strand a
 * permanently-trusted cert under a name we no longer write.
 */
const LEGACY_CERT_NAME = CERT_NAME;

/**
 * Per-certificate NSS nickname. Falls back to the bare stem when the PEM
 * can't be parsed — `certutil -A` would fail on that input anyway, so the
 * nickname is moot at that point.
 */
function nicknameFor(pemPath: string): string {
  try {
    const cert = new DevCert(fs.readFileSync(pemPath, "utf-8"));
    return `${CERT_NAME} (${cert.thumbprintSha1})`;
  } catch {
    return CERT_NAME;
  }
}

type NssTargetKind = "chromium-shared" | "firefox-profiles";

/**
 * NSS SSL trust flag, chosen per browser family.
 *
 * The cert we add is a self-signed **end entity** (`generateCertificate`
 * emits `basicConstraints` `cA=FALSE`), not a CA, so the honest encoding is
 * `P` — `CERTDB_TRUSTED`, "trusted peer", consulted when the cert *is* the
 * certificate being validated. `C` is `CERTDB_TRUSTED_CA`, consulted only
 * when the cert sits in an *issuer* position, which ours never does.
 *
 * Firefox is the exception, and it's an empirical one: it does not honour
 * `P` for server certs, so `C` is what actually produces trust there. This
 * mirrors `dotnet dev-certs https --trust`, whose `UnixCertificateManager`
 * makes the same split (`usage = nssDb.IsFirefox ? "C" : "P"`) with the
 * comment "Firefox doesn't seem to respected the more correct 'trusted
 * peer' (P) usage". Microsoft validated that against real browsers; we
 * follow it rather than re-deriving it.
 *
 * Sending `C` to a Chromium DB does not work: `certutil -V -u V` rejects
 * such an entry with "Issuer certificate is invalid", because nothing ever
 * consults the CA bit for an end entity. dotnet's own verify step encodes
 * the same asymmetry — it runs `-V -u V` for Chromium but only `-L`
 * (existence) for Firefox, since `-V` cannot pass under `C`.
 */
function trustFlagsFor(kind: NssTargetKind): string {
  return kind === "firefox-profiles" ? "C,," : "P,,";
}

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
  const nickname = nicknameFor(pemPath);

  for (const target of targets) {
    if (target.kind === "chromium-shared") {
      await scanChromiumShared(target, pemPath, nickname, outcomes);
    } else {
      await scanFirefoxProfiles(target, pemPath, nickname, outcomes);
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
  nickname: string,
  outcomes: DbOutcome[]
): Promise<void> {
  if (!fs.existsSync(path.join(target.root, "cert9.db"))) {
    log(`NSS scan: ${target.label} not present at ${target.root}, skipping.`);
    return;
  }
  const r = await trustInNssDb(
    `sql:${target.root}`,
    pemPath,
    nickname,
    target.kind
  );
  outcomes.push({
    label: target.label,
    ok: r.exitCode === 0,
    stderr: r.stderr,
  });
}

async function scanFirefoxProfiles(
  target: NssTarget,
  pemPath: string,
  nickname: string,
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
    const r = await trustInNssDb(
      `sql:${dbPath}`,
      pemPath,
      nickname,
      target.kind
    );
    outcomes.push({
      label: `${target.label} (${profile})`,
      ok: r.exitCode === 0,
      stderr: r.stderr,
    });
  }
}

async function trustInNssDb(
  dbArg: string,
  pemPath: string,
  nickname: string,
  kind: NssTargetKind
): Promise<{ exitCode: number; stderr: string }> {
  // Drop the shared nickname older versions used, so upgrading doesn't leave
  // a cert permanently trusted under a name we no longer manage. Skipped when
  // this cert IS the legacy-named one (unparseable PEM fallback) — the
  // per-nickname delete below covers that case.
  if (nickname !== LEGACY_CERT_NAME) {
    await runProcess("certutil", ["-D", "-d", dbArg, "-n", LEGACY_CERT_NAME]);
  }
  // Remove any existing cert with this name first to make the operation
  // idempotent. Both deletes exit non-zero when there's nothing to remove;
  // that's the common case and not an error.
  await runProcess("certutil", ["-D", "-d", dbArg, "-n", nickname]);

  // The deletes above also migrate an entry written by an older version
  // under different flags: `certutil -A` does not rewrite the trust string
  // of an existing nickname, so delete-then-add is what actually moves a
  // Chromium DB off the previous blanket `CT,,`.
  const result = await runProcess("certutil", [
    "-A",
    "-d",
    dbArg,
    "-t",
    trustFlagsFor(kind),
    "-n",
    nickname,
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
