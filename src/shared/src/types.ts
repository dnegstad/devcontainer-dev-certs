/**
 * Legacy certificate material transferred from the UI (host) extension
 * to the workspace (remote) extension. Kept for backward compatibility
 * with pinned older extension versions on either side of the IPC.
 */
export interface CertMaterial {
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
  thumbprint: string;
  /** Omitted when no private key is available (CA-only user certs). */
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
