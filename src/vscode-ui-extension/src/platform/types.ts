import { type DevCert, type DevKey } from "../cert/types";

export interface CertificateStatus {
  exists: boolean;
  isTrusted: boolean;
  /** SHA-1 thumbprint, uppercase hex (matches `X509Certificate2.Thumbprint`). */
  thumbprint: string | null;
  notBefore: string | null;
  notAfter: string | null;
  version: number;
}

/**
 * Platform-specific certificate store interface.
 *
 * Throughout this interface, `thumbprint` is the SHA-1 thumbprint
 * (`DevCert.thumbprintSha1`). This is what .NET, OpenSSL trust dirs, and
 * the Windows / macOS stores use to identify and name cert files. The
 * stronger `DevCert.thumbprint` (SHA-256) is for in-process identity only.
 */
export interface PlatformCertificateStore {
  /**
   * Find an existing valid ASP.NET dev cert in the platform store.
   * Returns the cert, key, and SHA-1 thumbprint if found.
   */
  findExistingDevCert(): Promise<{
    cert: DevCert;
    key: DevKey;
    thumbprint: string;
  } | null>;

  /**
   * Save a certificate with its private key to the platform store.
   * `thumbprint` is the SHA-1 thumbprint and becomes the .NET X509Store
   * filename stem (`{thumbprint}.pfx`).
   */
  saveCertificate(
    cert: DevCert,
    key: DevKey,
    thumbprint: string
  ): Promise<void>;

  /**
   * Trust a certificate so the OS/browser accepts it.
   */
  trustCertificate(cert: DevCert): Promise<void>;

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
      const { WindowsCertificateStore } = await import("./windowsStore.js");
      return new WindowsCertificateStore();
    }
    case "darwin": {
      const { MacCertificateStore } = await import("./macStore.js");
      return new MacCertificateStore();
    }
    case "linux": {
      const { LinuxCertificateStore } = await import("./linuxStore.js");
      return new LinuxCertificateStore();
    }
    default:
      throw new Error(`Unsupported platform: ${process.platform}`);
  }
}
