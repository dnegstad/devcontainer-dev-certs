/**
 * Legacy certificate material transferred from the UI (host) extension
 * to the workspace (remote) extension. Kept for backward compatibility
 * with pinned older extension versions on either side of the IPC.
 */
export interface CertMaterial {
  /**
   * SHA-1 thumbprint, uppercase hex (matches `X509Certificate2.Thumbprint`).
   * The workspace extension uses this directly as the .NET X509Store
   * filename stem (`{thumbprint}.pfx`) and the OpenSSL trust dir filename
   * stem, so it has to be SHA-1.
   */
  thumbprint: string;
  pfxBase64: string;
  pemCertBase64: string;
  pemKeyBase64: string;
  /** Public-cert-only PFX for the .NET Root store (no private key). */
  rootPfxBase64: string;
}

export type CertKind = "dotnet-dev" | "user";
export type DestFormat = "pem" | "key" | "pem-bundle" | "pfx" | "all";

/**
 * Stable filename stem for the auto-generated .NET dev cert when written to
 * extra destinations. The canonical .NET store paths continue to use the
 * thumbprint-keyed naming that Kestrel expects.
 */
export const DOTNET_DEV_CERT_NAME = "aspnetcore-dev";

export interface CertMaterialV2 {
  kind: CertKind;
  /** Filename stem used in extra destinations. */
  name: string;
  /**
   * SHA-1 thumbprint, uppercase hex. The workspace extension keys files
   * by this in the .NET X509Store and OpenSSL trust dir; .NET tooling
   * defines "thumbprint" as SHA-1 so the wire-protocol field has to match.
   */
  thumbprint: string;
  /**
   * PFX bytes with the user's password preserved. For PFX-sourced user
   * entries these are the original file bytes verbatim. For PEM-sourced
   * entries this is a freshly-built PFX encrypted with `pfxPassword` from
   * the user's settings, or omitted if no password was provided. For the
   * auto-generated dotnet-dev cert these are intrinsically passwordless
   * (no password to preserve). Consumers that don't have the password
   * cannot open these — that's the point.
   */
  pfxBase64?: string;
  pemCertBase64: string;
  /** Omitted for CA-only user certs. */
  pemKeyBase64?: string;
  /** Public-cert-only PFX for the .NET Root store. Only present when trustInContainer = true. */
  rootPfxBase64?: string;
  trustInContainer: boolean;
  /**
   * True when the cert should be installed into ~/.dotnet/corefx/cryptography/
   * x509stores/my/ — the .NET CurrentUser\My store on Linux. Always true for
   * the dotnet-dev cert (canonical location). For user certs this reflects
   * the resolved opt-in: global `installUserCertsToDotNetStore` AND not the
   * per-cert `excludeFromDotNetStore`. The workspace extension MUST NOT write
   * to the store when this is false, and MUST sweep any prior store copy.
   */
  installToDotNetStore: boolean;
  /**
   * Passwordless PFX bytes — populated ONLY when `installToDotNetStore` is
   * true. For the dotnet-dev cert this is the same payload as `pfxBase64`
   * (no password either way). For user certs this is a separate passwordless
   * re-encode of the same cert+key, kept distinct from `pfxBase64` so we
   * don't strip the user's password from artifacts written elsewhere. NEVER
   * write these bytes to any location other than the X509Store directory.
   */
  dotNetStorePfxBase64?: string;
}

export interface CertBundle {
  certs: CertMaterialV2[];
}
