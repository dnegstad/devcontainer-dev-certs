import * as forge from "node-forge";

export interface CertificateStatus {
  exists: boolean;
  isTrusted: boolean;
  thumbprint: string | null;
  notBefore: string | null;
  notAfter: string | null;
  version: number;
}

/**
 * Platform-specific certificate store interface.
 * Each platform implements this to handle finding, saving, trusting, and removing dev certs.
 */
export interface PlatformCertificateStore {
  /**
   * Find an existing valid ASP.NET dev cert in the platform store.
   * Returns the cert, key, and thumbprint if found.
   */
  findExistingDevCert(): Promise<{
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null>;

  /**
   * Save a certificate with its private key to the platform store.
   */
  saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    thumbprint: string
  ): Promise<void>;

  /**
   * Trust a certificate so the OS/browser accepts it.
   */
  trustCertificate(cert: forge.pki.Certificate): Promise<void>;

  /**
   * Remove dev certificates from all stores.
   */
  removeCertificates(): Promise<void>;

  /**
   * Check the status of the dev certificate.
   */
  checkStatus(): Promise<CertificateStatus>;
}

/**
 * Create the appropriate store for the current platform.
 */
export async function createPlatformStore(): Promise<PlatformCertificateStore> {
  switch (process.platform) {
    case "win32": {
      const { WindowsCertificateStore } = await import("./windowsStore");
      return new WindowsCertificateStore();
    }
    case "darwin": {
      const { MacCertificateStore } = await import("./macStore");
      return new MacCertificateStore();
    }
    case "linux": {
      const { LinuxCertificateStore } = await import("./linuxStore");
      return new LinuxCertificateStore();
    }
    default:
      throw new Error(`Unsupported platform: ${process.platform}`);
  }
}
