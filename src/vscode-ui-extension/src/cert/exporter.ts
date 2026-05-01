import * as fs from "fs";
import * as path from "path";
import type { LoadedCert } from "./loader";
import { DevCert, DevKey } from "./types";
import { ASPNET_HTTPS_OID_FRIENDLY_NAME } from "./properties";
import { buildPfx } from "./pfx";

/**
 * Export a certificate with its private key as a PFX/PKCS12 file.
 */
export async function exportPfx(
  cert: DevCert,
  key: DevKey,
  outputDir: string,
  password?: string
): Promise<string> {
  fs.mkdirSync(outputDir, { recursive: true });
  const der = await buildPfx({
    cert,
    key,
    password,
    friendlyName: ASPNET_HTTPS_OID_FRIENDLY_NAME,
  });
  const outPath = path.join(outputDir, "aspnetcore-dev.pfx");
  fs.writeFileSync(outPath, der);
  return outPath;
}

/**
 * Export a certificate and private key as PEM files.
 * Returns { certPath, keyPath }.
 */
export function exportPem(
  cert: DevCert,
  key: DevKey,
  outputDir: string
): { certPath: string; keyPath: string } {
  fs.mkdirSync(outputDir, { recursive: true });

  const certPath = path.join(outputDir, "aspnetcore-dev.pem");
  const keyPath = path.join(outputDir, "aspnetcore-dev.key");

  fs.writeFileSync(certPath, cert.pem);
  fs.writeFileSync(keyPath, key.pem);

  return { certPath, keyPath };
}

/**
 * Convert a certificate to PEM format string.
 */
export function certToPem(cert: DevCert): string {
  return cert.pem;
}

/**
 * Convert a private key to PEM format string (PKCS#8 unencrypted).
 */
export function keyToPem(key: DevKey): string {
  return key.pem;
}

/**
 * Export certificate as DER-encoded bytes (public cert only, no private key).
 */
export function certToDer(cert: DevCert): Buffer {
  return cert.der;
}

/**
 * Export a public-cert-only PFX for the .NET Root store.
 * This matches what `dotnet dev-certs https --trust` writes to
 * ~/.dotnet/corefx/cryptography/x509stores/root/ on Linux.
 */
export async function exportRootPfx(
  cert: DevCert,
  outputDir: string
): Promise<string> {
  fs.mkdirSync(outputDir, { recursive: true });
  const der = await buildPfx({ cert });
  const outPath = path.join(outputDir, "aspnetcore-dev-root.pfx");
  fs.writeFileSync(outPath, der);
  return outPath;
}

export interface ExportedLoadedCert {
  pemCertPath: string;
  pemKeyPath: string | null;
  pfxPath: string | null;
  rootPfxPath: string | null;
}

/**
 * Export a user-managed (or generically loaded) certificate to a directory
 * under a stable `{name}.*` filename scheme. PFX artifacts are only produced
 * when the cert has a private key attached; the root PFX is only produced
 * when `includeRootPfx` is true.
 */
export async function exportLoadedCert(
  loaded: LoadedCert,
  name: string,
  outputDir: string,
  options: { includeRootPfx?: boolean } = {}
): Promise<ExportedLoadedCert> {
  fs.mkdirSync(outputDir, { recursive: true });

  const pemCertPath = path.join(outputDir, `${name}.pem`);
  fs.writeFileSync(pemCertPath, loaded.cert.pem);

  let pemKeyPath: string | null = null;
  let pfxPath: string | null = null;
  if (loaded.key) {
    pemKeyPath = path.join(outputDir, `${name}.key`);
    fs.writeFileSync(pemKeyPath, loaded.key.pem);

    const pfxBytes = await buildPfx({
      cert: loaded.cert,
      key: loaded.key,
    });
    pfxPath = path.join(outputDir, `${name}.pfx`);
    fs.writeFileSync(pfxPath, pfxBytes);
  }

  let rootPfxPath: string | null = null;
  if (options.includeRootPfx) {
    const rootBytes = await buildPfx({ cert: loaded.cert });
    rootPfxPath = path.join(outputDir, `${name}-root.pfx`);
    fs.writeFileSync(rootPfxPath, rootBytes);
  }

  return { pemCertPath, pemKeyPath, pfxPath, rootPfxPath };
}
