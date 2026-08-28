import * as fs from "fs";
import * as path from "path";
import {
  assertValidCertName,
  getDotNetStorePath,
  getDotNetRootStorePath,
  getKestrelDefaultCertPath,
  getOpenSslTrustDir,
  getPfxFileName,
  getPemFileName,
  getPemFileNameForUser,
  computeSubjectHash,
  ensureHashSymlink,
  hasHashSymlink,
  rehashDirectory,
} from "@devcontainer-dev-certs/shared";
import type { CertMaterialV3 } from "@devcontainer-dev-certs/shared";
import type { ExtraDestination } from "./util/destinations";

export type {
  CertMaterial,
  CertMaterialV2,
  CertMaterialV3,
} from "@devcontainer-dev-certs/shared";

function chmodSafe(filePath: string, mode: number): void {
  try {
    fs.chmodSync(filePath, mode);
  } catch {
    // chmod may not be supported on all filesystems
  }
}

/**
 * Install the auto-generated .NET dev cert into the canonical .NET store and
 * OpenSSL trust locations using thumbprint-keyed filenames that Kestrel
 * expects. Byte-identical to the legacy single-cert behavior.
 */
export function installDotNetDevCert(material: CertMaterialV3): void {
  if (material.kind !== "dotnet-dev") {
    throw new Error(
      `installDotNetDevCert called with non-dotnet-dev cert (kind=${material.kind})`
    );
  }
  if (!material.pfxBase64 || !material.rootPfxBase64) {
    throw new Error(
      "dotnet-dev cert material is missing PFX or root PFX bytes."
    );
  }

  const dotNetStoreDir = getDotNetStorePath();
  const dotNetRootStoreDir = getDotNetRootStorePath();
  const trustDir = getOpenSslTrustDir();

  fs.mkdirSync(dotNetStoreDir, { recursive: true });
  fs.mkdirSync(dotNetRootStoreDir, { recursive: true });
  fs.mkdirSync(trustDir, { recursive: true });

  const pfxPath = path.join(dotNetStoreDir, getPfxFileName(material.thumbprint));
  fs.writeFileSync(pfxPath, Buffer.from(material.pfxBase64, "base64"));
  chmodSafe(pfxPath, 0o600);

  const rootPfxPath = path.join(
    dotNetRootStoreDir,
    getPfxFileName(material.thumbprint)
  );
  fs.writeFileSync(rootPfxPath, Buffer.from(material.rootPfxBase64, "base64"));
  chmodSafe(rootPfxPath, 0o644);

  const pemFileName = getPemFileName(material.thumbprint);
  const pemPath = path.join(trustDir, pemFileName);
  const pemContent = Buffer.from(material.pemCertBase64, "base64").toString(
    "utf-8"
  );

  fs.writeFileSync(pemPath, pemContent);
  chmodSafe(pemPath, 0o644);

  // Targeted symlink — only touches the slot for our PEM. PEMs from
  // prior rotations and their hash symlinks are deliberately left in
  // place; the user-invoked "Clean Up Other Dev Certificates in Dev
  // Container" command is the only path that mutates adjacent files.
  ensureHashSymlink(trustDir, pemFileName, pemContent);
}

/**
 * Install a user-managed certificate. Writes the thumbprint-keyed PFX into
 * the .NET store when a key is available so Kestrel can find it. When
 * trustInContainer is true the public cert also lands in the .NET Root store
 * and the OpenSSL trust directory under a stable `{name}.pem` filename.
 */
export function installUserCert(material: CertMaterialV3): void {
  if (material.kind !== "user") {
    throw new Error(
      `installUserCert called with non-user cert (kind=${material.kind})`
    );
  }
  // Re-validate on the receive side too: the v2 IPC payload crosses a trust
  // boundary, and the UI-side check could be bypassed by a downgraded or
  // modified host extension.
  assertValidCertName(material.name);

  const dotNetStoreDir = getDotNetStorePath();
  const dotNetRootStoreDir = getDotNetRootStorePath();
  const trustDir = getOpenSslTrustDir();

  fs.mkdirSync(dotNetStoreDir, { recursive: true });
  fs.mkdirSync(dotNetRootStoreDir, { recursive: true });
  fs.mkdirSync(trustDir, { recursive: true });

  const storePath = path.join(
    dotNetStoreDir,
    getPfxFileName(material.thumbprint)
  );
  if (material.installToDotNetStore && material.dotNetStorePfxBase64) {
    // The user opted into a plain-text-equivalent copy in the store. The
    // bytes here are the host-built passwordless re-encode; pfxBase64 (with
    // the user's password preserved) is for other destinations only.
    fs.writeFileSync(
      storePath,
      Buffer.from(material.dotNetStorePfxBase64, "base64")
    );
    chmodSafe(storePath, 0o600);
  } else {
    // Sweep stale state — if the user previously opted in and now opted out
    // (global setting flipped off, or `excludeFromDotNetStore` added), remove
    // the cached plain-text copy rather than orphaning it.
    fs.rmSync(storePath, { force: true });
  }

  if (material.trustInContainer) {
    if (material.rootPfxBase64) {
      const rootPfxPath = path.join(
        dotNetRootStoreDir,
        getPfxFileName(material.thumbprint)
      );
      fs.writeFileSync(
        rootPfxPath,
        Buffer.from(material.rootPfxBase64, "base64")
      );
      chmodSafe(rootPfxPath, 0o644);
    }

    const pemFileName = getPemFileNameForUser(material.name);
    const pemPath = path.join(trustDir, pemFileName);
    const pemContent = Buffer.from(material.pemCertBase64, "base64").toString(
      "utf-8"
    );
    fs.writeFileSync(pemPath, pemContent);
    chmodSafe(pemPath, 0o644);

    ensureHashSymlink(trustDir, pemFileName, pemContent);
  }
}

/**
 * Check if a certificate's canonical artifacts are already installed. For
 * dotnet-dev we check the three historic paths; for user certs we check that
 * the thumbprint-keyed PFX (when applicable) and, when trust is requested,
 * the named PEM exist.
 *
 * "Installed" includes a hash symlink OpenSSL would actually resolve, not just
 * the PEM being present. Without that, a container installed before the subject
 * hash was computed canonically has its symlink under the WRONG hash: the files
 * all exist, this returns true, the install is skipped, and the symlink is never
 * repaired — so upgrading would leave trust broken precisely for the users the
 * fix exists for. Re-running the install is cheap and rewrites identical bytes.
 */
export function isCertInstalled(material: CertMaterialV3): boolean {
  const trustDir = getOpenSslTrustDir();

  if (material.kind === "dotnet-dev") {
    const pfxPath = path.join(
      getDotNetStorePath(),
      getPfxFileName(material.thumbprint)
    );
    const rootPfxPath = path.join(
      getDotNetRootStorePath(),
      getPfxFileName(material.thumbprint)
    );
    if (!fs.existsSync(pfxPath) || !fs.existsSync(rootPfxPath)) return false;
    return pemInstalledAndLinked(
      trustDir,
      getPemFileName(material.thumbprint),
      decodePem(material)
    );
  }

  const storePfxPath = path.join(
    getDotNetStorePath(),
    getPfxFileName(material.thumbprint)
  );
  if (material.installToDotNetStore) {
    if (!fs.existsSync(storePfxPath)) return false;
  } else if (fs.existsSync(storePfxPath)) {
    // Opted out, but a passwordless copy from a previous opt-in is still
    // sitting in the .NET store. Report "not installed" so the caller runs
    // `installUserCert`, whose else-branch sweeps that file — otherwise the
    // sweep is unreachable and the plain-text key copy lives on forever
    // after the user flips `installUserCertsToDotNetStore` off (or adds
    // `excludeFromDotNetStore`).
    return false;
  }
  if (material.trustInContainer) {
    // `installUserCert` writes the .NET Root-store PFX too whenever the bundle
    // carries one, so checking only the OpenSSL side would report a user cert
    // fully installed after its Root PFX was deleted (or a previous install
    // stopped between the two writes) — activation would skip the reinstall
    // and .NET clients in the container would go on distrusting it. Gated on
    // `rootPfxBase64` so a bundle that never supplied one isn't held to a file
    // the install would not have written.
    if (material.rootPfxBase64) {
      const rootPfxPath = path.join(
        getDotNetRootStorePath(),
        getPfxFileName(material.thumbprint)
      );
      if (!fs.existsSync(rootPfxPath)) return false;
    }
    return pemInstalledAndLinked(
      trustDir,
      getPemFileNameForUser(material.name),
      decodePem(material)
    );
  }
  return true;
}

function decodePem(material: CertMaterialV3): string {
  return Buffer.from(material.pemCertBase64, "base64").toString("utf-8");
}

/**
 * True when the trust directory already holds exactly this certificate under
 * `pemFileName`, with a hash symlink OpenSSL can resolve to it.
 *
 * Compares content, not just existence, because user certs are keyed by the
 * user-chosen `name` rather than by thumbprint: rotating the certificate while
 * keeping the same name leaves a stale `{name}.pem` whose own hash link
 * resolves perfectly well, so an existence check would report "installed" and
 * the container would go on serving the superseded certificate indefinitely.
 * (The dotnet-dev PEM is thumbprint-keyed, so rotation changes its filename —
 * comparing content there is merely consistent rather than load-bearing.)
 *
 * A PEM whose subject can't be hashed counts as settled: `ensureHashSymlink`
 * is a no-op for it, so demanding a link would re-run the install on every
 * activation and never converge.
 */
function pemInstalledAndLinked(
  trustDir: string,
  pemFileName: string,
  expectedPem: string
): boolean {
  let onDisk: string;
  try {
    onDisk = fs.readFileSync(path.join(trustDir, pemFileName), "utf-8");
  } catch {
    return false;
  }
  if (onDisk !== expectedPem) return false;
  if (computeSubjectHash(onDisk) === null) return true;
  return hasHashSymlink(trustDir, pemFileName, onDisk);
}

/**
 * Write the cert's artifacts to an extra destination per its format. Returns
 * the rehash directory (if any) so the caller can rehash once at the end.
 */
export function writeExtraDestination(
  dest: ExtraDestination,
  material: CertMaterialV3
): { rehashDir: string | null; errors: string[] } {
  // The name is used verbatim as a filename stem under the destination dir.
  assertValidCertName(material.name);
  const errors: string[] = [];
  const pemCert = Buffer.from(material.pemCertBase64, "base64").toString(
    "utf-8"
  );
  const pemKey = material.pemKeyBase64
    ? Buffer.from(material.pemKeyBase64, "base64").toString("utf-8")
    : null;
  const pfx = material.pfxBase64
    ? Buffer.from(material.pfxBase64, "base64")
    : null;

  const dir = dest.path;
  const pathFor = (suffix: string) => path.join(dir, `${material.name}${suffix}`);

  const writeText = (filePath: string, content: string, mode: number) => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
    chmodSafe(filePath, mode);
  };
  const writeBinary = (filePath: string, buf: Buffer, mode: number) => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, buf);
    chmodSafe(filePath, mode);
  };

  const writePem = () => writeText(pathFor(".pem"), pemCert, 0o644);
  const writeKey = () => {
    if (!pemKey) return;
    writeText(pathFor(".key"), pemKey, 0o600);
  };
  const writePfx = () => {
    if (!pfx) return;
    writeBinary(pathFor(".pfx"), pfx, 0o600);
  };
  const writeBundle = () => {
    const content = pemKey ? `${pemCert}${pemKey}` : pemCert;
    writeText(pathFor("-bundle.pem"), content, 0o600);
  };

  // For format=pfx specifically, the user asked for a .pfx but the cert has
  // no private key to put in one (CA-only entry). Surface that as a warning
  // rather than silently skipping. For format=all the same skip is normal.
  if (dest.format === "pfx" && !pfx) {
    errors.push(
      `Cert '${material.name}' has no private key — skipping .pfx ` +
        `destination '${dest.path}'.`
    );
  }

  try {
    switch (dest.format) {
      case "pem":
        writePem();
        break;
      case "key":
        writeKey();
        break;
      case "pem-bundle":
        writeBundle();
        break;
      case "pfx":
        writePfx();
        break;
      case "all":
        writePem();
        writeKey();
        writePfx();
        writeBundle();
        break;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(
      `Failed writing cert '${material.name}' to '${dest.path}' (format=${dest.format}): ${msg}`
    );
  }

  const isPemCapable = dest.format === "pem" || dest.format === "all";
  return { rehashDir: isPemCapable ? dir : null, errors };
}

/**
 * Rehash the set of directories that received PEM writes. Runs
 * rehashDirectory() once per unique directory.
 */
export function rehashExtraDestinations(dirs: Iterable<string>): void {
  const unique = new Set<string>(dirs);
  for (const dir of unique) {
    try {
      rehashDirectory(dir);
    } catch {
      // best-effort
    }
  }
}

/**
 * Write the user-selected default Kestrel PFX to the well-known path.
 * Returns the path written so the caller can surface it in env vars.
 * Throws if the source material has no PFX bytes (which the host should
 * have prevented — defense in depth).
 */
export function writeKestrelDefaultCert(material: CertMaterialV3): string {
  if (!material.pfxBase64) {
    throw new Error(
      `cert '${material.name}' has no PFX bytes; cannot write Kestrel default.`
    );
  }
  const destPath = getKestrelDefaultCertPath();
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.writeFileSync(destPath, Buffer.from(material.pfxBase64, "base64"));
  chmodSafe(destPath, 0o600);
  return destPath;
}

/**
 * Remove the well-known Kestrel default PFX if it exists. No-ops when
 * the file is already absent.
 */
export function removeKestrelDefaultCert(): void {
  fs.rmSync(getKestrelDefaultCertPath(), { force: true });
}
