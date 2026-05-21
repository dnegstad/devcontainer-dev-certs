import * as fs from "fs";
import * as path from "path";
import {
  getDotNetRootStorePath,
  getDotNetStorePath,
  getOpenSslTrustDir,
  getPemFileName,
  getPemFileNameForUser,
} from "@devcontainer-dev-certs/shared";
import type { CertBundleV3 } from "@devcontainer-dev-certs/shared";
import { isDotNetDevCertPfx } from "./util/devCertDetect";
import { rehashDirectory } from "./util/rehash";

/**
 * Filename convention shared by .NET's OpenSslDirectoryBasedStoreProvider and
 * by `getPfxFileName(thumbprint)` (`src/shared/src/paths.ts:52`): a 40-character
 * uppercase SHA-1 hex stem with `.pfx` extension. Matching this conservatively
 * keeps us from touching anything that wasn't placed by ASP.NET dev-cert
 * tooling.
 */
const PFX_FILENAME_RE = /^([A-F0-9]{40})\.pfx$/i;

/**
 * PEM filename prefix used by `installDotNetDevCert` (mirrors the
 * `aspnetcore-localhost-{thumbprint}.pem` convention in
 * `src/shared/src/paths.ts:60`). We only consider files starting with this
 * prefix as deletion candidates in the trust dir — user-cert PEMs (`{name}.pem`)
 * have no reliable marker so we leave them alone.
 */
const DEV_CERT_PEM_PREFIX = "aspnetcore-localhost-";

export type ArtifactLocation = "my-store" | "root-store" | "trust-dir";

export interface StaleArtifact {
  location: ArtifactLocation;
  fullPath: string;
  /** Thumbprint parsed from the filename (PFX) or the full filename (PEM). */
  identifier: string;
}

export interface ManagedSets {
  myStoreThumbprints: ReadonlySet<string>;
  rootStoreThumbprints: ReadonlySet<string>;
  trustDirPemFileNames: ReadonlySet<string>;
}

/**
 * Build the canonical "what we expect to find on disk" sets from the bundle
 * currently advertised by the host extension. The conditions here must mirror
 * the write conditions in `installDotNetDevCert` and `installUserCert` — if a
 * code path is added that writes a new artifact, that artifact's identifier
 * must be reflected here or the cleanup command will treat it as stale.
 */
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

export function buildManagedSets(bundle: CertBundleV3): ManagedSets {
  const myStore = new Set<string>();
  const rootStore = new Set<string>();
  const trustDir = new Set<string>();

  for (const cert of bundle.certs) {
    const thumb = cert.thumbprint.toUpperCase();
    if (cert.kind === "dotnet-dev") {
      // installDotNetDevCert always writes all three.
      myStore.add(thumb);
      rootStore.add(thumb);
      trustDir.add(getPemFileName(cert.thumbprint));
      continue;
    }
    // user cert — see installUserCert in certInstaller.ts for the gates.
    if (cert.installToDotNetStore && cert.dotNetStorePfxBase64) {
      myStore.add(thumb);
    }
    if (cert.trustInContainer) {
      if (cert.rootPfxBase64) rootStore.add(thumb);
      trustDir.add(getPemFileNameForUser(cert.name));
    }
  }

  return {
    myStoreThumbprints: myStore,
    rootStoreThumbprints: rootStore,
    trustDirPemFileNames: trustDir,
  };
}

interface PfxScanContext {
  dir: string;
  location: Extract<ArtifactLocation, "my-store" | "root-store">;
  managed: ReadonlySet<string>;
}

function scanPfxStore(ctx: PfxScanContext): StaleArtifact[] {
  if (!fs.existsSync(ctx.dir)) return [];
  let entries: string[];
  try {
    entries = fs.readdirSync(ctx.dir);
  } catch {
    return [];
  }
  const stale: StaleArtifact[] = [];
  for (const entry of entries) {
    const match = PFX_FILENAME_RE.exec(entry);
    if (!match) continue;
    const thumb = match[1].toUpperCase();
    if (ctx.managed.has(thumb)) continue;
    const fullPath = path.join(ctx.dir, entry);
    let bytes: Buffer;
    try {
      bytes = fs.readFileSync(fullPath);
    } catch {
      continue;
    }
    if (!isDotNetDevCertPfx(bytes)) continue;
    stale.push({ location: ctx.location, fullPath, identifier: thumb });
  }
  return stale;
}

function scanTrustDir(managed: ReadonlySet<string>): StaleArtifact[] {
  const dir = getOpenSslTrustDir();
  if (!fs.existsSync(dir)) return [];
  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const stale: StaleArtifact[] = [];
  for (const entry of entries) {
    if (!entry.startsWith(DEV_CERT_PEM_PREFIX)) continue;
    if (!entry.endsWith(".pem")) continue;
    if (managed.has(entry)) continue;
    stale.push({
      location: "trust-dir",
      fullPath: path.join(dir, entry),
      identifier: entry,
    });
  }
  return stale;
}

/**
 * Enumerate stale ASP.NET dev cert artifacts across the three managed
 * locations without touching them. Best-effort — never throws.
 */
export function findStaleDevCertArtifacts(
  managed: ManagedSets
): StaleArtifact[] {
  return [
    ...scanPfxStore({
      dir: getDotNetStorePath(),
      location: "my-store",
      managed: managed.myStoreThumbprints,
    }),
    ...scanPfxStore({
      dir: getDotNetRootStorePath(),
      location: "root-store",
      managed: managed.rootStoreThumbprints,
    }),
    ...scanTrustDir(managed.trustDirPemFileNames),
  ];
}

export interface CleanupResult {
  removed: StaleArtifact[];
  failed: { artifact: StaleArtifact; error: string }[];
  rehashedTrustDir: boolean;
}

/**
 * Delete every artifact reported by `findStaleDevCertArtifacts`. If any PEM
 * in the trust dir was removed, rehash the directory so dangling hash
 * symlinks are dropped and remaining PEMs keep working.
 */
export function cleanupStaleDevCertArtifacts(
  managed: ManagedSets
): CleanupResult {
  const stale = findStaleDevCertArtifacts(managed);
  const removed: StaleArtifact[] = [];
  const failed: { artifact: StaleArtifact; error: string }[] = [];
  let removedAnyTrustPem = false;

  for (const artifact of stale) {
    try {
      fs.unlinkSync(artifact.fullPath);
      removed.push(artifact);
      if (artifact.location === "trust-dir") removedAnyTrustPem = true;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      failed.push({ artifact, error: message });
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

  return { removed, failed, rehashedTrustDir };
}
