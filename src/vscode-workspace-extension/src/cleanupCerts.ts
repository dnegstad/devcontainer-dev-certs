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
 * A foreign dev cert discovered in the .NET CurrentUser\My store, plus every
 * on-disk file that belongs to its thumbprint and would be removed by
 * cleanup. The My store is the discovery driver because .NET / Aspire
 * enumerate certs from there — anything found there shapes what users
 * actually experience. Root-store PFXes and trust-dir PEMs are only
 * surfaced as downstream "associated files" of a thumbprint we've already
 * decided is foreign in My; we never proactively scan those directories.
 */
export interface StaleDevCert {
  /** Uppercase SHA-1 thumbprint (the My-store PFX filename stem). */
  thumbprint: string;
  /**
   * All on-disk files that belong to this thumbprint and would be removed.
   * Always includes the My-store PFX (that's how it was discovered); the
   * Root-store PFX and trust-dir PEM appear only when the file actually
   * exists.
   */
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
    const thumb = match[1].toUpperCase();
    if (managedMyStoreThumbprints.has(thumb)) continue;

    const myPath = path.join(myStoreDir, entry);
    let bytes: Buffer;
    try {
      bytes = fs.readFileSync(myPath);
    } catch {
      continue;
    }
    // Dev cert PFXes in the store dirs are passwordless; the scanner
    // decrypts the PBES2/AES cert bag and looks for the ASP.NET HTTPS
    // OID in the plaintext. Fail-closed means anything we can't
    // identify stays put.
    if (!scanPfxForDevCertOid(bytes, "")) continue;

    const artifacts: StaleArtifact[] = [
      { location: "my-store", fullPath: myPath, identifier: thumb },
    ];

    // Associated Root-store PFX (.NET dev-certs install writes here too).
    const rootCandidate = path.join(rootStoreDir, getPfxFileName(thumb));
    if (fs.existsSync(rootCandidate)) {
      artifacts.push({
        location: "root-store",
        fullPath: rootCandidate,
        identifier: thumb,
      });
    }

    // Associated trust-dir PEM (`aspnetcore-localhost-{thumbprint}.pem`).
    const pemFile = getPemFileName(thumb);
    const pemCandidate = path.join(trustDir, pemFile);
    if (fs.existsSync(pemCandidate)) {
      artifacts.push({
        location: "trust-dir",
        fullPath: pemCandidate,
        identifier: pemFile,
      });
    }

    stale.push({ thumbprint: thumb, artifacts });
  }

  return stale;
}

export interface CleanupResult {
  /**
   * Certs whose CurrentUser\My PFX was successfully removed. `.NET` /
   * Aspire enumerate from there, so this is the count users care about.
   * A cert appears here even if a downstream Root / trust-dir delete
   * failed — those failures are surfaced separately via `failed`.
   */
  removedCerts: StaleDevCert[];
  /** Per-file unlink failures across every location. */
  failed: { artifact: StaleArtifact; error: string }[];
  rehashedTrustDir: boolean;
}

/**
 * Delete every artifact for every stale dev cert. Rehashes the trust dir
 * if any PEM was actually removed.
 */
export function cleanupStaleDevCerts(
  stale: readonly StaleDevCert[]
): CleanupResult {
  const removedCerts: StaleDevCert[] = [];
  const failed: { artifact: StaleArtifact; error: string }[] = [];
  let removedAnyTrustPem = false;

  for (const cert of stale) {
    let myStoreRemoved = false;
    for (const artifact of cert.artifacts) {
      try {
        fs.unlinkSync(artifact.fullPath);
        if (artifact.location === "my-store") myStoreRemoved = true;
        if (artifact.location === "trust-dir") removedAnyTrustPem = true;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        failed.push({ artifact, error: message });
      }
    }
    if (myStoreRemoved) removedCerts.push(cert);
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

  return { removedCerts, failed, rehashedTrustDir };
}
