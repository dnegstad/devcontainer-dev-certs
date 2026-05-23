import { type DevCert, type DevKey } from "./types";
import { isValidDevCert, getCertificateVersion } from "./validation";

/**
 * Resolved dev cert + private key that's ready to sync.
 */
export interface UsableDevCert {
  cert: DevCert;
  key: DevKey;
  thumbprint: string;
}

/**
 * Reason codes for `kind: "skipped"` classifications. Callers map these to
 * localized strings — keeping them as codes rather than English keeps
 * `vscode.l10n.t` calls statically extractable (the localizer source must
 * be a literal, which only works when each caller passes a known literal
 * for each code).
 */
export type SkipReasonCode =
  | "missing-private-key"
  | "parse-failed"
  | "forced";

/**
 * Result of classifying a single dev-cert candidate.
 *
 * - `usable`: cert + key fully loadable and `isValidDevCert` passes; safe to
 *   pass into selection.
 * - `skipped`: would-be-valid candidate that we can't actually use (missing
 *   private key, parse failure, key not exportable from a system keychain,
 *   orphaned cache file, etc.). The reason code + free-form `forcedReason`
 *   are surfaced via `onSkipped` so callers can render a localized log
 *   line.
 * - `null` return (not a kind): the input isn't a dev-cert candidate at all
 *   (e.g. unrelated cert in a shared store, expired, CN ≠ localhost). Silent
 *   — these aren't worth surfacing.
 */
export type ClassifiedCandidate =
  | { kind: "usable"; cert: DevCert; key: DevKey; thumbprint: string }
  | {
      kind: "skipped";
      thumbprint: string | null;
      reasonCode: SkipReasonCode;
      /** Caller-supplied free-form reason; only set for `kind: "forcedSkip"` inputs. */
      forcedReason?: string;
    };

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
 * `parseFailure` is set; `source` is the human-readable provenance
 * (file path, store path, "macOS login keychain") that callers can use
 * when rendering log lines.
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
 * Side-effect-free metadata about a skipped candidate, surfaced to callers
 * via the `onSkipped` callback so they can render a localized log line.
 */
export interface SkipReport {
  source: string;
  reasonCode: SkipReasonCode;
  /** Caller-supplied free-form reason; only present for `forced` skips. */
  forcedReason?: string;
  metadata: CandidateMetadata;
}

export interface ClassifyOptions {
  /**
   * Called once per skipped candidate. Use to render a log line in the
   * caller's localization context — the shared classifier doesn't log
   * anything itself so it can stay vscode-free.
   */
  onSkipped?: (report: SkipReport) => void;
}

/**
 * Classify a single candidate into `usable` / `skipped`, or return `null`
 * for an input that isn't dev-cert-shaped.
 *
 * Pure: the only side effect is invoking `options.onSkipped` when supplied.
 * Callers in vscode contexts pass a callback that emits a localized log
 * line; library / test callers can omit it.
 */
export function classifyCandidate(
  input: CandidateInput,
  options: ClassifyOptions = {}
): ClassifiedCandidate | null {
  if (input.kind === "loaded") {
    const { cert, key, thumbprint } = input.loaded;
    if (!isValidDevCert(cert)) {
      // Not a dev cert (CN ≠ localhost, expired, no OID extension, version <
      // MIN). Silent — there's nothing the user can act on.
      return null;
    }

    if (!key) {
      const metadata: CandidateMetadata = {
        thumbprint,
        subjectCN: cert.subjectCN,
        version: getCertificateVersion(cert),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
      };
      options.onSkipped?.({
        source: input.source,
        reasonCode: "missing-private-key",
        metadata,
      });
      return { kind: "skipped", thumbprint, reasonCode: "missing-private-key" };
    }

    return { kind: "usable", cert, key, thumbprint };
  }

  if (input.kind === "parseFailure") {
    // We only warn on parse failures for files whose name matches the
    // canonical aspnetcore-localhost-<thumb>.pfx pattern (the caller passes
    // the extracted hint). Generic .pfx files in a shared directory aren't
    // ours to worry about.
    if (!input.thumbprintHint) return null;
    options.onSkipped?.({
      source: input.source,
      reasonCode: "parse-failed",
      metadata: { thumbprint: input.thumbprintHint },
    });
    return {
      kind: "skipped",
      thumbprint: input.thumbprintHint,
      reasonCode: "parse-failed",
    };
  }

  // forcedSkip — reason and metadata are caller-supplied. The reason string
  // is opaque to the shared classifier; callers receive it back verbatim
  // via the SkipReport so they can route it through their own l10n.
  options.onSkipped?.({
    source: input.source,
    reasonCode: "forced",
    forcedReason: input.reason,
    metadata: { ...(input.metadata ?? {}), thumbprint: input.metadata?.thumbprint ?? null },
  });
  return {
    kind: "skipped",
    thumbprint: input.metadata?.thumbprint ?? null,
    reasonCode: "forced",
    forcedReason: input.reason,
  };
}

export interface SelectionReport {
  selected: UsableDevCert;
  candidates: UsableDevCert[];
  context: string;
}

export interface SelectBestOptions {
  /**
   * Called when more than one usable candidate is present, so callers can
   * render a localized multi-candidate warning. Receives the sorted
   * candidates (selected first).
   */
  onMultipleCandidates?: (report: SelectionReport) => void;
}

/**
 * Choose the best dev cert among a set of pre-classified usable candidates.
 * Sort key: highest version byte first, then latest `notAfter` as the
 * tiebreaker — mirrors .NET's `dotnet dev-certs` resolution behaviour.
 *
 * Pure aside from invoking `options.onMultipleCandidates` when supplied.
 */
export function selectBestDevCert(
  usable: UsableDevCert[],
  context: string,
  options: SelectBestOptions = {}
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
    options.onMultipleCandidates?.({
      selected,
      candidates: sorted,
      context,
    });
  }

  return selected;
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
  // Strip directory + extension manually (don't pull node:path into shared).
  const slashIdx = Math.max(
    filename.lastIndexOf("/"),
    filename.lastIndexOf("\\")
  );
  const stem = slashIdx >= 0 ? filename.slice(slashIdx + 1) : filename;
  const base = stem.endsWith(".pfx") ? stem.slice(0, -4) : stem;

  const aspnetMatch = base.match(/^aspnetcore-localhost-([0-9A-Fa-f]{40})$/);
  if (aspnetMatch) return aspnetMatch[1].toUpperCase();
  const bareMatch = base.match(/^([0-9A-Fa-f]{40})$/);
  if (bareMatch) return bareMatch[1].toUpperCase();
  return null;
}
