import * as fs from "fs";
import * as path from "path";
import type { LoadedCert } from "./loader";
import { type DevCert, type DevKey } from "./types";
import { ASPNET_HTTPS_OID_FRIENDLY_NAME } from "./properties";
import { buildPfx } from "./pfx";

// PFX and unencrypted key PEM contain private key material. Use mode 0o600 on
// every write — the temp dir created upstream is already mkdtemp'd 0o700, but
// explicit file modes survive being copied or extracted elsewhere.
const PRIVATE_FILE_MODE = 0o600;
const PUBLIC_FILE_MODE = 0o644;

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
  fs.writeFileSync(outPath, der, { mode: PRIVATE_FILE_MODE });
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

  fs.writeFileSync(certPath, cert.pem, { mode: PUBLIC_FILE_MODE });
  fs.writeFileSync(keyPath, key.pem, { mode: PRIVATE_FILE_MODE });

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
  fs.writeFileSync(outPath, der, { mode: PUBLIC_FILE_MODE });
  return outPath;
}

export interface ExportedLoadedCert {
  pemCertPath: string;
  pemKeyPath: string | null;
  rootPfxPath: string | null;
}

/**
 * Export a user-managed (or generically loaded) certificate's PEM artifacts
 * to a directory under a stable `{name}.*` filename scheme. The cert is
 * always written; the key is only written when a key is attached; the
 * public-cert-only root PFX is only produced when `includeRootPfx` is true.
 *
 * Notably this does NOT synthesize a key-bearing `{name}.pfx`. That decision
 * lives with the host orchestrator, where the user's pfxPassword is in
 * scope — silently encoding a passwordless PFX here would strip the user's
 * password without their consent.
 */
export async function exportLoadedCert(
  loaded: LoadedCert,
  name: string,
  outputDir: string,
  options: { includeRootPfx?: boolean } = {}
): Promise<ExportedLoadedCert> {
  fs.mkdirSync(outputDir, { recursive: true });

  const pemCertPath = path.join(outputDir, `${name}.pem`);
  fs.writeFileSync(pemCertPath, loaded.cert.pem, { mode: PUBLIC_FILE_MODE });

  let pemKeyPath: string | null = null;
  if (loaded.key) {
    pemKeyPath = path.join(outputDir, `${name}.key`);
    fs.writeFileSync(pemKeyPath, loaded.key.pem, { mode: PRIVATE_FILE_MODE });
  }

  let rootPfxPath: string | null = null;
  if (options.includeRootPfx) {
    const rootBytes = await buildPfx({ cert: loaded.cert });
    rootPfxPath = path.join(outputDir, `${name}-root.pfx`);
    fs.writeFileSync(rootPfxPath, rootBytes, { mode: PUBLIC_FILE_MODE });
  }

  return { pemCertPath, pemKeyPath, rootPfxPath };
}
