import * as forge from "node-forge";
import * as fs from "fs";
import * as path from "path";
import type { LoadedCert } from "./loader";
import { ASPNET_HTTPS_OID_FRIENDLY_NAME } from "./properties";

/**
 * Export a certificate with its private key as a PFX/PKCS12 file.
 */
export function exportPfx(
  cert: forge.pki.Certificate,
  key: forge.pki.rsa.PrivateKey,
  outputDir: string,
  password?: string
): string {
  fs.mkdirSync(outputDir, { recursive: true });

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], password ?? "", {
    algorithm: "3des",
    friendlyName: ASPNET_HTTPS_OID_FRIENDLY_NAME,
  });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  const outPath = path.join(outputDir, "aspnetcore-dev.pfx");
  fs.writeFileSync(outPath, Buffer.from(p12Der, "binary"));
  return outPath;
}

/**
 * Export a certificate and private key as PEM files.
 * Returns { certPath, keyPath }.
 */
export function exportPem(
  cert: forge.pki.Certificate,
  key: forge.pki.rsa.PrivateKey,
  outputDir: string
): { certPath: string; keyPath: string } {
  fs.mkdirSync(outputDir, { recursive: true });

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(key);

  const certPath = path.join(outputDir, "aspnetcore-dev.pem");
  const keyPath = path.join(outputDir, "aspnetcore-dev.key");

  fs.writeFileSync(certPath, certPem);
  fs.writeFileSync(keyPath, keyPem);

  return { certPath, keyPath };
}

/**
 * Convert a certificate to PEM format string.
 */
export function certToPem(cert: forge.pki.Certificate): string {
  return forge.pki.certificateToPem(cert);
}

/**
 * Convert a private key to PEM format string (PKCS#8 unencrypted).
 */
export function keyToPem(key: forge.pki.rsa.PrivateKey): string {
  return forge.pki.privateKeyToPem(key);
}

/**
 * Export certificate as DER-encoded bytes (public cert only, no private key).
 */
export function certToDer(cert: forge.pki.Certificate): Buffer {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
  return Buffer.from(derBytes.getBytes(), "binary");
}

/**
 * Export a public-cert-only PFX for the .NET Root store.
 * This matches what `dotnet dev-certs https --trust` writes to
 * ~/.dotnet/corefx/cryptography/x509stores/root/ on Linux.
 */
export function exportRootPfx(
  cert: forge.pki.Certificate,
  outputDir: string
): string {
  fs.mkdirSync(outputDir, { recursive: true });

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    null as unknown as forge.pki.rsa.PrivateKey,
    [cert],
    "",
    { algorithm: "3des" }
  );
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  const outPath = path.join(outputDir, "aspnetcore-dev-root.pfx");
  fs.writeFileSync(outPath, Buffer.from(p12Der, "binary"));
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
export function exportLoadedCert(
  loaded: LoadedCert,
  name: string,
  outputDir: string,
  options: { includeRootPfx?: boolean } = {}
): ExportedLoadedCert {
  fs.mkdirSync(outputDir, { recursive: true });

  const pemCertPath = path.join(outputDir, `${name}.pem`);
  fs.writeFileSync(pemCertPath, forge.pki.certificateToPem(loaded.cert));

  let pemKeyPath: string | null = null;
  let pfxPath: string | null = null;
  if (loaded.key) {
    pemKeyPath = path.join(outputDir, `${name}.key`);
    fs.writeFileSync(pemKeyPath, forge.pki.privateKeyToPem(loaded.key));

    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
      loaded.key,
      [loaded.cert],
      "",
      { algorithm: "3des" }
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    pfxPath = path.join(outputDir, `${name}.pfx`);
    fs.writeFileSync(pfxPath, Buffer.from(p12Der, "binary"));
  }

  let rootPfxPath: string | null = null;
  if (options.includeRootPfx) {
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
      null as unknown as forge.pki.rsa.PrivateKey,
      [loaded.cert],
      "",
      { algorithm: "3des" }
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    rootPfxPath = path.join(outputDir, `${name}-root.pfx`);
    fs.writeFileSync(rootPfxPath, Buffer.from(p12Der, "binary"));
  }

  return { pemCertPath, pemKeyPath, pfxPath, rootPfxPath };
}
