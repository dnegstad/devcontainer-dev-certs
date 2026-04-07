import * as forge from "node-forge";
import * as fs from "fs";
import * as path from "path";

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

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], password ?? null, {
    algorithm: "3des",
    friendlyName: "ASP.NET Core HTTPS development certificate",
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
