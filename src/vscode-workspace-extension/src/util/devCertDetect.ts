import { scanPfxForDevCertOid } from "./pkcs12DevCertScan";

/**
 * Identify a PKCS#12 (PFX) file as an ASP.NET Core HTTPS dev certificate by
 * decrypting its cert bag with the empty password and looking for the
 * Microsoft-assigned custom-OID extension `1.3.6.1.4.1.311.84.1.1` (mirrors
 * the `ASPNET_HTTPS_OID` constant in
 * `src/vscode-ui-extension/src/cert/properties.ts:16` — duplicated rather
 * than imported to keep this leaf module free of cross-package edges).
 *
 * Handles both producers whose PFXes can end up in
 * `~/.dotnet/corefx/cryptography/x509stores/{my,root}/`:
 *  - this extension's host writer (PBES2 / PBKDF2-SHA-256 / AES-256-CBC), and
 *  - the .NET runtime's own `Pkcs12Builder` (what `dotnet dev-certs --trust`
 *    lands in those directories — PBE-SHA1-3DES on legacy SDKs, PBES2 on
 *    modern SDKs).
 *
 * Fail-closed: any parse or decrypt failure returns `false`, so we never
 * delete a PFX we couldn't positively identify.
 */
export function isDotNetDevCertPfx(pfxBytes: Buffer): boolean {
  return scanPfxForDevCertOid(pfxBytes, "");
}

export { ASPNET_HTTPS_OID_DER } from "./pkcs12DevCertScan";
