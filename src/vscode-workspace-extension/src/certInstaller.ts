import * as fs from "fs";
import * as path from "path";
import {
  assertValidCertName,
  getDotNetStorePath,
  getDotNetRootStorePath,
  getOpenSslTrustDir,
  getPfxFileName,
  getPemFileName,
  getPemFileNameForUser,
} from "@devcontainer-dev-certs/shared";
import type { CertMaterialV2 } from "@devcontainer-dev-certs/shared";
import { createHashSymlink, rehashDirectory } from "./util/rehash";
import type { ExtraDestination } from "./util/destinations";

export type { CertMaterial, CertMaterialV2 } from "@devcontainer-dev-certs/shared";

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
export function installDotNetDevCert(material: CertMaterialV2): void {
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

  createHashSymlink(trustDir, pemFileName, pemContent);
}

/**
 * Install a user-managed certificate. Writes the thumbprint-keyed PFX into
 * the .NET store when a key is available so Kestrel can find it. When
 * trustInContainer is true the public cert also lands in the .NET Root store
 * and the OpenSSL trust directory under a stable `{name}.pem` filename.
 */
export function installUserCert(material: CertMaterialV2): void {
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

  if (material.pfxBase64) {
    const pfxPath = path.join(
      dotNetStoreDir,
      getPfxFileName(material.thumbprint)
    );
    fs.writeFileSync(pfxPath, Buffer.from(material.pfxBase64, "base64"));
    chmodSafe(pfxPath, 0o600);
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

    createHashSymlink(trustDir, pemFileName, pemContent);
  }
}

/**
 * Check if a certificate's canonical artifacts are already installed. For
 * dotnet-dev we check the three historic paths; for user certs we check that
 * the thumbprint-keyed PFX (when applicable) and, when trust is requested,
 * the named PEM exist.
 */
export function isCertInstalled(material: CertMaterialV2): boolean {
  if (material.kind === "dotnet-dev") {
    const pfxPath = path.join(
      getDotNetStorePath(),
      getPfxFileName(material.thumbprint)
    );
    const rootPfxPath = path.join(
      getDotNetRootStorePath(),
      getPfxFileName(material.thumbprint)
    );
    const pemPath = path.join(
      getOpenSslTrustDir(),
      getPemFileName(material.thumbprint)
    );
    return (
      fs.existsSync(pfxPath) &&
      fs.existsSync(rootPfxPath) &&
      fs.existsSync(pemPath)
    );
  }

  if (material.pfxBase64) {
    const pfxPath = path.join(
      getDotNetStorePath(),
      getPfxFileName(material.thumbprint)
    );
    if (!fs.existsSync(pfxPath)) return false;
  }
  if (material.trustInContainer) {
    const pemPath = path.join(
      getOpenSslTrustDir(),
      getPemFileNameForUser(material.name)
    );
    if (!fs.existsSync(pemPath)) return false;
  }
  return true;
}

/**
 * Write the cert's artifacts to an extra destination per its format. Returns
 * the rehash directory (if any) so the caller can rehash once at the end.
 */
export function writeExtraDestination(
  dest: ExtraDestination,
  material: CertMaterialV2
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
