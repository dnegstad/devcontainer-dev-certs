import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { type PlatformCertificateStore, type CertificateStatus } from "./types";
import {
  log,
  type DevCert,
  type DevKey,
  buildPfx,
  parsePfx,
  getCertificateVersion,
  classifyCandidate as classifyCandidateShared,
  selectBestDevCert as selectBestDevCertShared,
  extractThumbprintHintFromFilename,
  type CandidateInput,
  type ClassifiedCandidate,
  type SkipReport,
  type UsableDevCert,
} from "@devcontainer-dev-certs/shared";

// Re-export the pure shared types so existing imports of
// `../platform/baseStore` keep working without touching ~15 test files.
export type {
  ClassifiedCandidate,
  CandidateInput,
  UsableDevCert,
} from "@devcontainer-dev-certs/shared";
export { extractThumbprintHintFromFilename } from "@devcontainer-dev-certs/shared";

/**
 * Side-effectful host-side classifier wrapper. Delegates the pure
 * classification to the shared module and emits the same localized "skipping
 * ASP.NET dev cert ..." log line via `vscode.l10n.t` that the host has
 * always produced. New container-side scan paths can call the shared
 * `classifyCandidate` directly with their own (or no) localizer.
 */
export function classifyCandidate(
  input: CandidateInput
): ClassifiedCandidate | null {
  return classifyCandidateShared(input, {
    onSkipped: (report) => emitHostSkipLog(report),
  });
}

/**
 * Side-effectful host-side selection wrapper. Delegates to the shared
 * selector and emits the multi-candidate localized warning when more than
 * one usable candidate is present.
 */
export function selectBestDevCert(
  usable: UsableDevCert[],
  context: string
): UsableDevCert | null {
  return selectBestDevCertShared(usable, context, {
    onMultipleCandidates: ({ selected, candidates }) => {
      const header = vscode.l10n.t(
        "Multiple valid ASP.NET dev certs found in {0}; selected {1}.",
        context,
        selected.thumbprint
      );
      const candidatesHeader = vscode.l10n.t("  Candidates:");
      const selectedTag = vscode.l10n.t("[selected]");
      const skippedTag = vscode.l10n.t("[skipped] ");
      const lines = [
        header,
        candidatesHeader,
        ...candidates.map((c, i) =>
          vscode.l10n.t(
            "    {0} thumbprint={1} version={2} notBefore={3} notAfter={4}",
            i === 0 ? selectedTag : skippedTag,
            c.thumbprint,
            getCertificateVersion(c.cert),
            c.cert.notBefore.toISOString(),
            c.cert.notAfter.toISOString()
          )
        ),
      ];
      log(lines.join("\n"));
    },
  });
}

/**
 * Render the localized "skipping ASP.NET dev cert" log line for one skipped
 * candidate. Maps the shared classifier's reason code to a host-localized
 * string. `forced` skips carry the caller's free-form reason verbatim — the
 * platform stores (linuxStore / macStore / windowsStore) localize their own
 * forced-skip reasons before handing them in, so we pass through.
 */
function emitHostSkipLog(report: SkipReport): void {
  let localizedReason: string;
  switch (report.reasonCode) {
    case "missing-private-key":
      localizedReason = vscode.l10n.t(
        "PFX contains certificate without matching private key"
      );
      break;
    case "parse-failed":
      localizedReason = vscode.l10n.t(
        "failed to parse PFX (corrupt or wrong password)"
      );
      break;
    case "forced":
      // Caller localized this string before classifyCandidate received it.
      localizedReason = report.forcedReason ?? "";
      break;
  }
  const unknown = vscode.l10n.t("(unknown)");
  const meta = report.metadata;
  const subjectCN = meta.subjectCN ?? unknown;
  const version =
    meta.version === undefined || meta.version === null
      ? unknown
      : String(meta.version);
  const notBefore = meta.notBefore ? meta.notBefore.toISOString() : unknown;
  const notAfter = meta.notAfter ? meta.notAfter.toISOString() : unknown;
  log(
    vscode.l10n.t(
      "Skipping ASP.NET dev cert {0} ({1}): {2}.\n  subjectCN={3} version={4} notBefore={5} notAfter={6}",
      meta.thumbprint ?? unknown,
      report.source,
      localizedReason,
      subjectCN,
      version,
      notBefore,
      notAfter
    )
  );
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
   * Public wrapper around `isTrusted` that satisfies the
   * `PlatformCertificateStore.isCertTrusted` contract — verify the
   * current on-disk / OS trust state for a specific certificate. Lets
   * callers (notably `CertManager.trustExternalCertificate`) decide
   * whether the platform-level trust step needs to run at all,
   * avoiding redundant `security add-trusted-cert` / `certutil
   * -addstore` calls that aren't true no-ops.
   */
  async isCertTrusted(cert: DevCert): Promise<boolean> {
    return this.isTrusted(cert, cert.thumbprintSha1);
  }

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
