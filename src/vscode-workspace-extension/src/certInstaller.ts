import * as fs from "fs";
import * as path from "path";
import {
  getDotNetStorePath,
  getOpenSslTrustDir,
  getPfxFileName,
  getPemFileName,
} from "@devcontainer-dev-certs/shared";
import { createHashSymlink } from "./util/rehash";

export type { CertMaterial } from "@devcontainer-dev-certs/shared";

/**
 * Install certificate material into the correct paths on the remote filesystem.
 */
export function installCert(material: {
  thumbprint: string;
  pfxBase64: string;
  pemCertBase64: string;
}): void {
  const dotNetStoreDir = getDotNetStorePath();
  const trustDir = getOpenSslTrustDir();

  // Ensure directories exist
  fs.mkdirSync(dotNetStoreDir, { recursive: true });
  fs.mkdirSync(trustDir, { recursive: true });

  // 1. Write PFX to .NET cert store
  //    Kestrel discovers this via X509Store(StoreName.My, StoreLocation.CurrentUser)
  const pfxPath = path.join(dotNetStoreDir, getPfxFileName(material.thumbprint));
  fs.writeFileSync(pfxPath, Buffer.from(material.pfxBase64, "base64"));
  try {
    fs.chmodSync(pfxPath, 0o600);
  } catch {
    // chmod may not be supported on all platforms
  }

  // 2. Write PEM cert to OpenSSL trust directory
  const pemFileName = getPemFileName(material.thumbprint);
  const pemPath = path.join(trustDir, pemFileName);
  const pemContent = Buffer.from(material.pemCertBase64, "base64").toString(
    "utf-8"
  );
  fs.writeFileSync(pemPath, pemContent);
  try {
    fs.chmodSync(pemPath, 0o644);
  } catch {
    // chmod may not be supported on all platforms
  }

  // 3. Create hash symlink for OpenSSL discovery
  createHashSymlink(trustDir, pemFileName, pemContent);
}

/**
 * Check if a certificate with the given thumbprint is already installed.
 */
export function isCertInstalled(thumbprint: string): boolean {
  const pfxPath = path.join(
    getDotNetStorePath(),
    getPfxFileName(thumbprint)
  );
  const pemPath = path.join(
    getOpenSslTrustDir(),
    getPemFileName(thumbprint)
  );
  return fs.existsSync(pfxPath) && fs.existsSync(pemPath);
}
