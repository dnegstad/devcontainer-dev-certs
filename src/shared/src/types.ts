/**
 * Certificate material transferred from the UI (host) extension
 * to the workspace (remote) extension.
 */
export interface CertMaterial {
  thumbprint: string;
  pfxBase64: string;
  pemCertBase64: string;
  pemKeyBase64: string;
  /** Public-cert-only PFX for the .NET Root store (no private key). */
  rootPfxBase64: string;
}
