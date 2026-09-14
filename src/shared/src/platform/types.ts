import { type DevCert, type DevKey } from "../cert/types";
import { type Localizer } from "../localizer";
import { type NssTrustResult } from "./nssTrust";

/**
 * Callback the Linux store invokes after attempting browser-NSS trust as
 * part of `trustCertificate`. Lets the extension host surface a guidance
 * toast on failure without giving the platform store a direct dependency
 * on `vscode`.
 */
export type LinuxNssTrustReporter = (
  result: NssTrustResult,
  pemPath: string
) => void;

/**
 * Common options accepted by every platform certificate store. Currently
 * carries the host-supplied `Localizer` so log lines produced inside the
 * shared platform layer match what the host extension surfaces via
 * `vscode.l10n.t`. Non-VS-Code consumers (CLI, scripts, tests) can omit it
 * and fall back to the identity localizer.
 */
export interface BaseStoreOptions {
  /** Optional Localizer; defaults to `identityLocalizer`. */
  localize?: Localizer;
}

export interface CreatePlatformStoreOptions extends BaseStoreOptions {
  /** Optional reporter for NSS trust outcomes; honored only on Linux. */
  linuxNssTrustReporter?: LinuxNssTrustReporter;
}

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
   * Verify on-disk / OS trust state for a specific certificate. Callers
   * use this to short-circuit redundant `trustCertificate` calls — on
   * macOS in particular, `security add-trusted-cert` is not a true
   * no-op for an already-trusted cert (it re-touches the trust-settings
   * record and may re-prompt for the keychain password). The cache that
   * the host's CertProvider maintains is a goal-state, not a record of
   * machine state — every trust operation re-verifies trust here
   * before deciding whether to invoke trustCertificate again.
   */
  isCertTrusted(cert: DevCert): Promise<boolean>;

  /**
   * Check the status of the dev certificate.
   */
  checkStatus(): Promise<CertificateStatus>;
}

/**
 * Create the appropriate store for the current platform.
 */
export async function createPlatformStore(
  options: CreatePlatformStoreOptions = {}
): Promise<PlatformCertificateStore> {
  const baseOptions: BaseStoreOptions = { localize: options.localize };
  switch (process.platform) {
    case "win32": {
      const { WindowsCertificateStore } = await import("./windowsStore.js");
      return new WindowsCertificateStore("CurrentUser", baseOptions);
    }
    case "darwin": {
      const { MacCertificateStore } = await import("./macStore.js");
      return new MacCertificateStore(baseOptions);
    }
    case "linux": {
      const { LinuxCertificateStore } = await import("./linuxStore.js");
      return new LinuxCertificateStore({
        ...baseOptions,
        nssTrustReporter: options.linuxNssTrustReporter,
      });
    }
    default:
      throw new Error(`Unsupported platform: ${process.platform}`);
  }
}
