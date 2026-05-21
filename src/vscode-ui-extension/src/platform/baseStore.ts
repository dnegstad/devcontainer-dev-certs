import * as fs from "fs";
import * as path from "path";
import { type PlatformCertificateStore, type CertificateStatus } from "./types";
import { isValidDevCert, getCertificateVersion } from "../cert/generator";
import { type DevCert, type DevKey } from "../cert/types";
import { buildPfx, parsePfx } from "../cert/pfx";
import { log } from "@devcontainer-dev-certs/shared";

/**
 * Resolved dev cert + private key that's ready to sync.
 */
export interface UsableDevCert {
  cert: DevCert;
  key: DevKey;
  thumbprint: string;
}

/**
 * Result of classifying a single dev-cert candidate.
 *
 * - `usable`: cert + key fully loadable and `isValidDevCert` passes; safe to
 *   pass into selection.
 * - `skipped`: would-be-valid candidate that we can't actually use (missing
 *   private key, parse failure, key not exportable from a system keychain,
 *   orphaned cache file, etc.). A diagnostic warning has already been logged
 *   at classification time; selection MUST exclude these.
 * - `null` return (not a kind): the input isn't a dev-cert candidate at all
 *   (e.g. unrelated cert in a shared store, expired, CN ≠ localhost). Silent
 *   — these aren't worth surfacing.
 */
export type ClassifiedCandidate =
  | { kind: "usable"; cert: DevCert; key: DevKey; thumbprint: string }
  | { kind: "skipped"; thumbprint: string | null; reason: string };

/**
 * Optional metadata describing a candidate when we don't (yet) have a parsed
 * cert object — e.g. when PowerShell hands us a `skipped[]` entry derived
 * from the Windows cert store, or when we're surfacing a keychain-only
 * entry on macOS.
 */
export interface CandidateMetadata {
  thumbprint?: string | null;
  subjectCN?: string | null;
  version?: number | null;
  notBefore?: Date | null;
  notAfter?: Date | null;
}

/**
 * Inputs to `classifyCandidate`. Exactly one of `loaded` / `forcedSkip` /
 * `parseFailure` must be set; `source` is the human-readable provenance
 * (file path, store path, "macOS login keychain") that appears in the
 * warning log.
 */
export type CandidateInput =
  | {
      kind: "loaded";
      source: string;
      loaded: { cert: DevCert; key: DevKey | null; thumbprint: string };
    }
  | {
      kind: "parseFailure";
      source: string;
      thumbprintHint?: string | null;
    }
  | {
      kind: "forcedSkip";
      source: string;
      reason: string;
      metadata?: CandidateMetadata;
    };

/**
 * Classify a single candidate into `usable` / `skipped`, or return `null`
 * for an input that isn't dev-cert-shaped (silent, not logged).
 *
 * Side effect: when the return is `kind: "skipped"`, a single human-readable
 * `log()` line is emitted at classification time so the warning surfaces
 * BEFORE any selection happens.
 */
export function classifyCandidate(
  input: CandidateInput
): ClassifiedCandidate | null {
  if (input.kind === "loaded") {
    const { cert, key, thumbprint } = input.loaded;
    const certPassesValidity = isValidDevCert(cert);

    if (!certPassesValidity) {
      // Not a dev cert (CN ≠ localhost, expired, no OID extension, version <
      // MIN). Silent — there's nothing the user can act on.
      return null;
    }

    if (!key) {
      const reason = "PFX contains certificate without matching private key";
      logSkipReason(thumbprint, input.source, reason, {
        subjectCN: cert.subjectCN,
        version: getCertificateVersion(cert),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
      });
      return { kind: "skipped", thumbprint, reason };
    }

    return { kind: "usable", cert, key, thumbprint };
  }

  if (input.kind === "parseFailure") {
    // We only warn on parse failures for files whose name matches the
    // canonical aspnetcore-localhost-<thumb>.pfx pattern (the caller passes
    // the extracted hint). Generic .pfx files in a shared directory aren't
    // ours to worry about.
    if (!input.thumbprintHint) return null;
    const reason = "failed to parse PFX (corrupt or wrong password)";
    logSkipReason(input.thumbprintHint, input.source, reason, {});
    return { kind: "skipped", thumbprint: input.thumbprintHint, reason };
  }

  // forcedSkip
  logSkipReason(
    input.metadata?.thumbprint ?? null,
    input.source,
    input.reason,
    input.metadata ?? {}
  );
  return {
    kind: "skipped",
    thumbprint: input.metadata?.thumbprint ?? null,
    reason: input.reason,
  };
}

/**
 * Choose the best dev cert among a set of pre-classified usable candidates.
 * Sort key: highest version byte first, then latest `notAfter` as the
 * tiebreaker — mirrors .NET's `dotnet dev-certs` resolution behaviour.
 *
 * When more than one usable candidate is present, emits a single
 * multi-candidate selection warning so the user can see exactly which
 * thumbprints were considered. The warning is NOT emitted for unusable
 * candidates — those get their own warning at classification time.
 */
export function selectBestDevCert(
  usable: UsableDevCert[],
  context: string
): UsableDevCert | null {
  if (usable.length === 0) return null;

  const sorted = [...usable].sort((a, b) => {
    const versionA = getCertificateVersion(a.cert);
    const versionB = getCertificateVersion(b.cert);
    if (versionA !== versionB) return versionB - versionA;
    return b.cert.notAfter.getTime() - a.cert.notAfter.getTime();
  });

  const selected = sorted[0];

  if (sorted.length > 1) {
    const lines = [
      `Multiple valid ASP.NET dev certs found in ${context}; selected ${selected.thumbprint}.`,
      `  Candidates:`,
      ...sorted.map((c, i) => {
        const tag = i === 0 ? "[selected]" : "[skipped] ";
        return `    ${tag} thumbprint=${c.thumbprint} version=${getCertificateVersion(c.cert)} notBefore=${c.cert.notBefore.toISOString()} notAfter=${c.cert.notAfter.toISOString()}`;
      }),
    ];
    log(lines.join("\n"));
  }

  return selected;
}

function logSkipReason(
  thumbprint: string | null,
  source: string,
  reason: string,
  meta: CandidateMetadata
): void {
  const subjectCN = meta.subjectCN ?? "(unknown)";
  const version =
    meta.version === undefined || meta.version === null
      ? "(unknown)"
      : String(meta.version);
  const notBefore = meta.notBefore
    ? meta.notBefore.toISOString()
    : "(unknown)";
  const notAfter = meta.notAfter ? meta.notAfter.toISOString() : "(unknown)";
  log(
    `Skipping ASP.NET dev cert ${thumbprint ?? "(unknown)"} (${source}): ${reason}.\n` +
      `  subjectCN=${subjectCN} version=${version} notBefore=${notBefore} notAfter=${notAfter}`
  );
}

/**
 * Extract the canonical SHA-1 thumbprint embedded in a PFX filename that
 * follows the `aspnetcore-localhost-<thumb>.pfx` or `<thumb>.pfx` patterns.
 * Returns null when the filename doesn't match — caller treats parse
 * failures on non-canonical names as silent (they aren't ours).
 */
export function extractThumbprintHintFromFilename(
  filename: string
): string | null {
  const base = path.basename(filename, ".pfx");
  const aspnetMatch = base.match(/^aspnetcore-localhost-([0-9A-Fa-f]{40})$/);
  if (aspnetMatch) return aspnetMatch[1].toUpperCase();
  const bareMatch = base.match(/^([0-9A-Fa-f]{40})$/);
  if (bareMatch) return bareMatch[1].toUpperCase();
  return null;
}

/**
 * Base implementation for platform certificate stores.
 *
 * Provides common logic shared across Windows, macOS, and Linux:
 * - checkStatus() with a consistent pattern (find → check trust → build status)
 * - PFX loading and writing helpers
 *
 * Subclasses implement the platform-specific methods: findExistingDevCert,
 * saveCertificate, trustCertificate, removeCertificates, and isTrusted.
 */
export abstract class BaseCertificateStore implements PlatformCertificateStore {
  async checkStatus(): Promise<CertificateStatus> {
    const found = await this.findExistingDevCert();
    if (!found) {
      return {
        exists: false,
        isTrusted: false,
        thumbprint: null,
        notBefore: null,
        notAfter: null,
        version: -1,
      };
    }

    const { cert, thumbprint } = found;
    const trusted = await this.isTrusted(cert, thumbprint);
    const version = getCertificateVersion(cert);

    return {
      exists: true,
      isTrusted: trusted,
      thumbprint,
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      version,
    };
  }

  abstract findExistingDevCert(): Promise<UsableDevCert | null>;

  abstract saveCertificate(
    cert: DevCert,
    key: DevKey,
    thumbprint: string
  ): Promise<void>;

  abstract trustCertificate(cert: DevCert): Promise<void>;

  abstract removeCertificates(): Promise<void>;

  /**
   * Platform-specific trust verification.
   * Called by checkStatus() to determine if the certificate is trusted.
   */
  protected abstract isTrusted(
    cert: DevCert,
    thumbprint: string
  ): Promise<boolean>;

  // --- Shared helpers ---

  /**
   * Parse a PFX file and extract the certificate, private key, and thumbprint.
   * Returns `{ cert, key }` where `key` may be null when the PFX is cert-only.
   * Returns null only on outright parse failure (corrupt bytes, wrong
   * password, unsupported PBE).
   */
  protected async loadPfxLenient(
    pfxPath: string,
    password: string = ""
  ): Promise<{ cert: DevCert; key: DevKey | null; thumbprint: string } | null> {
    try {
      const pfxBytes = fs.readFileSync(pfxPath);
      const { cert, key } = await parsePfx(pfxBytes, password);
      return { cert, key: key ?? null, thumbprint: cert.thumbprintSha1 };
    } catch {
      return null;
    }
  }

  /**
   * Parse a PFX file and extract the certificate, private key, and thumbprint.
   * Returns null if the file cannot be parsed or is missing cert/key bags.
   * Strict variant — used by existing call sites that want a usable identity
   * or nothing.
   */
  protected async loadPfx(
    pfxPath: string,
    password: string = ""
  ): Promise<UsableDevCert | null> {
    const loaded = await this.loadPfxLenient(pfxPath, password);
    if (!loaded || !loaded.key) return null;
    return { cert: loaded.cert, key: loaded.key, thumbprint: loaded.thumbprint };
  }

  /**
   * Write a certificate and key as a PFX file.
   */
  protected async writePfx(
    cert: DevCert,
    key: DevKey,
    pfxPath: string,
    password: string = "",
    mode?: number
  ): Promise<void> {
    const der = await buildPfx({ cert, key, password });
    const options = mode !== undefined ? { mode } : undefined;
    fs.writeFileSync(pfxPath, der, options);
  }

  /**
   * Scan a directory for `*.pfx` files and classify each one. For every
   * match:
   *
   * 1. Try to parse it. Parse failures on canonically-named files
   *    (`aspnetcore-localhost-<thumb>.pfx` or `<thumb>.pfx`) emit the
   *    "failed to parse PFX" unusable warning; parse failures on other
   *    filenames are silent — they may belong to other tools.
   * 2. If parsed and the cert passes `isValidDevCert` but there's no private
   *    key, emit the "no matching private key" unusable warning.
   * 3. Otherwise classify as `usable`.
   *
   * Selection runs only over the surviving usable candidates via
   * `selectBestDevCert`. Multi-candidate selection emits its own warning.
   *
   * Callers may narrow which files to consider via `filenamePredicate`
   * (default: accept every `*.pfx`). Whether a parse failure produces a
   * warning is controlled separately by `extractThumbprintHintFromFilename`
   * — see step 1.
   */
  protected async findBestDevCertInDir(
    dir: string,
    password: string = "",
    options: {
      filenamePredicate?: (filename: string) => boolean;
      context?: string;
    } = {}
  ): Promise<UsableDevCert | null> {
    if (!fs.existsSync(dir)) return null;

    const context = options.context ?? dir;
    const usable: UsableDevCert[] = [];

    const files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".pfx"))
      .filter((f) =>
        options.filenamePredicate ? options.filenamePredicate(f) : true
      );

    for (const file of files) {
      const filePath = path.join(dir, file);
      const thumbprintHint = extractThumbprintHintFromFilename(file);
      const loaded = await this.loadPfxLenient(filePath, password);

      if (!loaded) {
        // Canonical name + parse failure → warn; otherwise silent.
        classifyCandidate({
          kind: "parseFailure",
          source: filePath,
          thumbprintHint,
        });
        continue;
      }

      const classified = classifyCandidate({
        kind: "loaded",
        source: filePath,
        loaded,
      });

      if (classified === null) continue;
      if (classified.kind === "usable") {
        usable.push(classified);
      }
      // skipped → already logged inside classifyCandidate
    }

    return selectBestDevCert(usable, context);
  }
}
