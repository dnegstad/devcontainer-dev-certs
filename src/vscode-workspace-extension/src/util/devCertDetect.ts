/**
 * Heuristic detection of ASP.NET Core HTTPS dev certificates by scanning
 * passwordless PKCS#12 (PFX) bytes for the Microsoft-assigned OID
 * `1.3.6.1.4.1.311.84.1.1` (mirrors the `ASPNET_HTTPS_OID` constant in
 * `src/vscode-ui-extension/src/cert/properties.ts:16` — kept duplicated so this
 * leaf module stays free of cross-package imports).
 *
 * The .NET store's PFX files are passwordless, so the X.509 cert lives in an
 * unencrypted `data` ContentInfo and the DER-encoded OID appears as a
 * contiguous byte run in the file.
 */

/**
 * DER encoding of OBJECT IDENTIFIER 1.3.6.1.4.1.311.84.1.1:
 *   06 0A                            — OID tag, length 10
 *   2B 06 01 04 01 82 37 54 01 01    — base-128 encoded arcs
 */
export const ASPNET_HTTPS_OID_DER = Buffer.from([
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x54, 0x01, 0x01,
]);

/**
 * Returns true when the PFX bytes look like an ASP.NET Core HTTPS dev cert.
 * Fail-closed: returns false when the OID isn't found (so we never delete
 * something we couldn't positively identify).
 */
export function isDotNetDevCertPfx(pfxBytes: Buffer): boolean {
  return pfxBytes.includes(ASPNET_HTTPS_OID_DER);
}
