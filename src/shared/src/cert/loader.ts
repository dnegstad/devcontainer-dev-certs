import * as fs from "fs";
import { DevCert, DevKey } from "./types";
import { parsePfx } from "./pfx";

export interface LoadedCert {
  cert: DevCert;
  key: DevKey | null;
  /**
   * SHA-1 thumbprint, uppercase hex (matches .NET's
   * `X509Certificate2.Thumbprint`). Used as the .NET X509Store filename
   * stem and as the OpenSSL trust dir filename. For a stronger cert
   * identifier inside the UI extension, use `cert.thumbprint` (SHA-256).
   */
  thumbprint: string;
  isExpired: boolean;
}

function buildLoadedCert(cert: DevCert, key: DevKey | null): LoadedCert {
  return {
    cert,
    key,
    thumbprint: cert.thumbprintSha1,
    isExpired: cert.notAfter.getTime() < Date.now(),
  };
}

/**
 * Load a PFX/PKCS#12 certificate from disk. Returns the first certificate bag
 * and, when present, its matching private key.
 */
export async function loadPfx(
  filePath: string,
  password?: string
): Promise<LoadedCert> {
  const bytes = fs.readFileSync(filePath);
  const { cert, key } = await parsePfx(bytes, password);
  return buildLoadedCert(cert, key);
}

/**
 * Load a PEM certificate (and optional matching private key) from disk.
 */
export function loadPemPair(
  certPath: string,
  keyPath?: string | null
): LoadedCert {
  const certPem = fs.readFileSync(certPath, "utf-8");
  const cert = new DevCert(certPem);

  let key: DevKey | null = null;
  if (keyPath) {
    const keyPem = fs.readFileSync(keyPath, "utf-8");
    key = DevKey.fromPem(keyPem);
  }

  return buildLoadedCert(cert, key);
}

/**
 * Locate a sibling PEM private key next to a cert PEM, returning the
 * first match or null. Probes both naming conventions in the wild:
 *
 * - `<stem>.key` — what our exporter writes, what `openssl` writes by
 *   convention.
 * - `<filename>.key` — what `dotnet dev-certs --format PEM
 *   --export-path foo.pem` writes (`foo.pem.key`).
 *
 * Stem-form wins when both exist; that's the path `loadPemPair`
 * documents and the more common case for openssl- / our-exporter-
 * produced pairs.
 */
export function findSiblingKey(certPath: string): string | null {
  const stem = certPath.replace(/\.[^.]+$/, "");
  for (const candidate of [`${stem}.key`, `${certPath}.key`]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}
