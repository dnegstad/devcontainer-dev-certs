import { scanPfxForDevCertOid } from "./pkcs12DevCertScan";

/**
 * Identify a PKCS#12 (PFX) file as an ASP.NET Core HTTPS dev certificate by
 * decrypting its cert bag with the empty password and looking for the
 * Microsoft-assigned custom-OID extension `1.3.6.1.4.1.311.84.1.1` (mirrors
 * the `ASPNET_HTTPS_OID` constant in
 * `src/vscode-ui-extension/src/cert/properties.ts:16` — duplicated rather
 * than imported to keep this leaf module free of cross-package edges).
 *
 * Handles both producers we care about:
 *  - this extension's host (PBES2 / PBKDF2-SHA-256 / AES-256-CBC), and
 *  - `dotnet dev-certs https --export-path foo.pfx --no-password` on legacy
 *    .NET (PBE-SHA1-3DES) and modern .NET (PBES2).
 *
 * Fail-closed: any parse or decrypt failure returns `false`, so we never
 * delete a PFX we couldn't positively identify.
 */
export function isDotNetDevCertPfx(pfxBytes: Buffer): boolean {
  return scanPfxForDevCertOid(pfxBytes, "");
}

export { ASPNET_HTTPS_OID_DER } from "./pkcs12DevCertScan";
