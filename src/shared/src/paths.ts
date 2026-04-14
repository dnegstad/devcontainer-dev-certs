import * as os from "os";
import * as path from "path";

/**
 * .NET X509Store CurrentUser\My path on Linux.
 * Kestrel discovers dev certs from here via GetDevelopmentCertificateFromStore().
 */
export function getDotNetStorePath(): string {
  return path.join(
    os.homedir(),
    ".dotnet",
    "corefx",
    "cryptography",
    "x509stores",
    "my"
  );
}

/**
 * OpenSSL trust directory for dev certs.
 * Honors DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY if set,
 * matching the behavior of .NET's UnixCertificateManager.
 */
export function getOpenSslTrustDir(): string {
  return (
    process.env["DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY"] ??
    path.join(os.homedir(), ".aspnet", "dev-certs", "trust")
  );
}

/**
 * PFX filename in the .NET store — matches what .NET's
 * OpenSslDirectoryBasedStoreProvider expects.
 */
export function getPfxFileName(thumbprint: string): string {
  return `${thumbprint}.pfx`;
}

/**
 * PEM filename in the OpenSSL trust directory — matches
 * UnixCertificateManager naming.
 */
export function getPemFileName(thumbprint: string): string {
  return `aspnetcore-localhost-${thumbprint}.pem`;
}
