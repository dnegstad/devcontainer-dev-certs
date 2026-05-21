import * as fs from "fs";
import * as path from "path";
import {
  getDotNetRootStorePath,
  getDotNetStorePath,
  getOpenSslTrustDir,
  getPemFileName,
  getPfxFileName,
} from "@devcontainer-dev-certs/shared";
import type { CertBundleV3 } from "@devcontainer-dev-certs/shared";
import { scanPfxForDevCertOid } from "./util/pkcs12DevCertScan";
import { rehashDirectory } from "./util/rehash";

/**
 * Filename convention shared by .NET's OpenSslDirectoryBasedStoreProvider and
 * by `getPfxFileName(thumbprint)` (`src/shared/src/paths.ts:52`): a 40-character
 * uppercase SHA-1 hex stem with `.pfx` extension. Matching this conservatively
 * keeps us from touching anything that wasn't placed by ASP.NET dev-cert
 * tooling.
 */
const PFX_FILENAME_RE = /^([A-F0-9]{40})\.pfx$/i;

export type ArtifactLocation = "my-store" | "root-store" | "trust-dir";

export interface StaleArtifact {
  location: ArtifactLocation;
  fullPath: string;
  /** Thumbprint (PFX) or full filename (PEM) — useful for log lines. */
  identifier: string;
}

/**
 * A foreign dev cert discovered in the .NET CurrentUser\My store, plus
 * every on-disk file that shares its thumbprint. My is the discovery
 * driver — Root and the trust dir are only swept by association.
 */
export interface StaleDevCert {
  /** Uppercase SHA-1 thumbprint (the My-store PFX filename stem). */
  thumbprint: string;
  /** My-store PFX (always), plus the Root PFX and trust-dir PEM when
   *  those files exist on disk. */
  artifacts: StaleArtifact[];
}

/**
 * The cleanup command's premise is "remove dev cert artifacts that aren't
 * the one this extension manages". When the bundle carries no dotnet-dev
 * cert (generation disabled via DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET, or
 * the host couldn't provide one), there is nothing to preserve and every
 * dev cert on disk would otherwise be classified as "other" — callers must
 * refuse to operate in that state.
 */
export function bundleHasManagedDevCert(bundle: CertBundleV3): boolean {
  return bundle.certs.some((c) => c.kind === "dotnet-dev");
}

/**
 * Build the set of thumbprints expected in the My store given the
 * currently-advertised bundle. Mirrors the conditions under which
 * `installDotNetDevCert` and the My-store branch of `installUserCert`
 * actually write a `{thumbprint}.pfx`.
 */
export function buildManagedMyStoreThumbprints(
  bundle: CertBundleV3
): ReadonlySet<string> {
  const set = new Set<string>();
  for (const cert of bundle.certs) {
    const thumb = cert.thumbprint.toUpperCase();
    if (cert.kind === "dotnet-dev") {
      set.add(thumb);
      continue;
    }
    if (cert.installToDotNetStore && cert.dotNetStorePfxBase64) {
      set.add(thumb);
    }
  }
  return set;
}

/**
 * Enumerate foreign dev certs in the .NET CurrentUser\My store and gather
 * the on-disk files that belong to each one — best-effort, never throws.
 * Only the My store is scanned; Root-store / trust-dir files are looked
 * up by thumbprint after the fact.
 */
export function findStaleDevCerts(
  managedMyStoreThumbprints: ReadonlySet<string>
): StaleDevCert[] {
  const myStoreDir = getDotNetStorePath();
  if (!fs.existsSync(myStoreDir)) return [];

  let entries: string[];
  try {
    entries = fs.readdirSync(myStoreDir);
  } catch {
    return [];
  }

  const rootStoreDir = getDotNetRootStorePath();
  const trustDir = getOpenSslTrustDir();
  const stale: StaleDevCert[] = [];

  for (const entry of entries) {
    const match = PFX_FILENAME_RE.exec(entry);
    if (!match) continue;
    // Preserve on-disk casing for sibling lookups (case-sensitive FS);
    // normalize separately for the managed-set check + display.
    const onDiskThumb = match[1];
    const normalThumb = onDiskThumb.toUpperCase();
    if (managedMyStoreThumbprints.has(normalThumb)) continue;

    const myPath = path.join(myStoreDir, entry);
    let bytes: Buffer;
    try {
      bytes = fs.readFileSync(myPath);
    } catch {
      continue;
    }
    // Fail-closed: only delete files we positively identify as dev certs.
    if (!scanPfxForDevCertOid(bytes, "")) continue;

    const artifacts: StaleArtifact[] = [
      { location: "my-store", fullPath: myPath, identifier: normalThumb },
    ];

    const rootCandidate = path.join(
      rootStoreDir,
      getPfxFileName(onDiskThumb)
    );
    if (fs.existsSync(rootCandidate)) {
      artifacts.push({
        location: "root-store",
        fullPath: rootCandidate,
        identifier: normalThumb,
      });
    }

    const pemFile = getPemFileName(onDiskThumb);
    const pemCandidate = path.join(trustDir, pemFile);
    if (fs.existsSync(pemCandidate)) {
      artifacts.push({
        location: "trust-dir",
        fullPath: pemCandidate,
        identifier: pemFile,
      });
    }

    stale.push({ thumbprint: normalThumb, artifacts });
  }

  return stale;
}

export interface CleanupResult {
  /** Certs whose every artifact was successfully removed. Drives the
   *  user-visible "removed N certs" count. */
  removedCerts: StaleDevCert[];
  /** Per-file successful unlinks, tagged with the owning thumbprint.
   *  Includes partial-success entries from certs not in `removedCerts`. */
  removed: { thumbprint: string; artifact: StaleArtifact }[];
  /** Per-file unlink failures, tagged with thumbprint. */
  failed: { thumbprint: string; artifact: StaleArtifact; error: string }[];
  rehashedTrustDir: boolean;
}

/**
 * Delete every artifact for every stale dev cert. The My-store PFX is
 * unlinked LAST and only when every downstream file (Root PFX, trust-dir
 * PEM) was removed or absent, so a partial failure leaves the cert
 * discoverable on the next run. Rehashes the trust dir if any PEM was
 * removed.
 */
export function cleanupStaleDevCerts(
  stale: readonly StaleDevCert[]
): CleanupResult {
  const removedCerts: StaleDevCert[] = [];
  const removed: { thumbprint: string; artifact: StaleArtifact }[] = [];
  const failed: { thumbprint: string; artifact: StaleArtifact; error: string }[] = [];
  let removedAnyTrustPem = false;

  for (const cert of stale) {
    let myArtifact: StaleArtifact | null = null;
    const downstream: StaleArtifact[] = [];
    for (const a of cert.artifacts) {
      if (a.location === "my-store") myArtifact = a;
      else downstream.push(a);
    }

    let downstreamOk = true;
    for (const artifact of downstream) {
      try {
        fs.unlinkSync(artifact.fullPath);
        removed.push({ thumbprint: cert.thumbprint, artifact });
        if (artifact.location === "trust-dir") removedAnyTrustPem = true;
      } catch (err: unknown) {
        downstreamOk = false;
        const message = err instanceof Error ? err.message : String(err);
        failed.push({ thumbprint: cert.thumbprint, artifact, error: message });
      }
    }

    // Skip My deletion when any downstream file remains — the cert must
    // stay discoverable on the next run.
    if (!downstreamOk || !myArtifact) continue;

    try {
      fs.unlinkSync(myArtifact.fullPath);
      removed.push({ thumbprint: cert.thumbprint, artifact: myArtifact });
      removedCerts.push(cert);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      failed.push({ thumbprint: cert.thumbprint, artifact: myArtifact, error: message });
    }
  }

  let rehashedTrustDir = false;
  if (removedAnyTrustPem) {
    try {
      rehashDirectory(getOpenSslTrustDir());
      rehashedTrustDir = true;
    } catch {
      // Best-effort — leave rehashedTrustDir false so the caller can log it.
    }
  }

  return { removedCerts, removed, failed, rehashedTrustDir };
}
