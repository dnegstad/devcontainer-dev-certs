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
   * Passwordless PFX bytes. The V2 IPC contract assumes any cert that
   * carries a PFX is openable with the empty password — the .NET X509Store
   * on Linux can't accept per-file passwords, and V2 consumers wrote these
   * bytes directly to it. Omitted when no private key is available
   * (CA-only user certs).
   */
  pfxBase64?: string;
  pemCertBase64: string;
  /** Omitted for CA-only user certs. */
  pemKeyBase64?: string;
  /** Public-cert-only PFX for the .NET Root store. Only present when trustInContainer = true. */
  rootPfxBase64?: string;
  trustInContainer: boolean;
}

export interface CertBundle {
  certs: CertMaterialV2[];
}

/**
 * V3 certificate material. Adds a deliberate split between the
 * password-preserving payload for "elsewhere" destinations and the
 * passwordless payload for the .NET X509Store, gated by an explicit
 * per-cert install flag. V3 consumers (new workspace extension) read
 * these fields directly; older workspaces continue speaking V2 via the
 * downmap on the host side.
 */
export interface CertMaterialV3 {
  kind: CertKind;
  name: string;
  thumbprint: string;
  /**
   * PFX bytes with the user's password preserved. For PFX-sourced user
   * entries these are the original file bytes verbatim. For PEM-sourced
   * entries this is a freshly-built PFX encrypted with `pfxPassword` from
   * the user's settings, or with an empty password if `pfxPassword` was
   * unset (matching the source PEM key file's on-disk posture). For the
   * auto-generated dotnet-dev cert these are intrinsically passwordless.
   * V3 consumers must NOT write these bytes to the .NET X509Store — they
   * may carry a password the store-enumeration code can't supply.
   */
  pfxBase64?: string;
  pemCertBase64: string;
  pemKeyBase64?: string;
  rootPfxBase64?: string;
  trustInContainer: boolean;
  /**
   * True when the cert should be installed into ~/.dotnet/corefx/cryptography/
   * x509stores/my/. Always true for the dotnet-dev cert. For user certs this
   * reflects the resolved opt-in: global `installUserCertsToDotNetStore` AND
   * not the per-cert `excludeFromDotNetStore`. The workspace extension MUST
   * NOT write to the store when this is false, and MUST sweep any prior
   * store copy keyed by this cert's thumbprint.
   */
  installToDotNetStore: boolean;
  /**
   * Passwordless PFX bytes — populated ONLY when `installToDotNetStore` is
   * true. The deliberate side-effect of opting into the store: the bytes
   * here have the user's password stripped so .NET's null-password
   * enumeration can open them. NEVER write these bytes anywhere other than
   * the X509Store directory.
   */
  dotNetStorePfxBase64?: string;
}

export interface CertBundleV3 {
  certs: CertMaterialV3[];
}
