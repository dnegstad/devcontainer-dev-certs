/**
 * Certificate material transferred from the UI (host) extension
 * to the workspace (remote) extension.
 */
export interface CertMaterial {
  thumbprint: string;
  pfxBase64: string;
  pemCertBase64: string;
  pemKeyBase64: string;
}
