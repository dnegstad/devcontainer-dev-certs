import * as fs from "fs";
import { type PlatformCertificateStore, type CertificateStatus } from "./types";
import { isValidDevCert, getCertificateVersion } from "../cert/generator";
import { type DevCert, type DevKey } from "../cert/types";
import { buildPfx, parsePfx } from "../cert/pfx";

/**
 * Base implementation for platform certificate stores.
 *
 * Provides common logic shared across Windows, macOS, and Linux:
 * - checkStatus() with a consistent pattern (find → check trust → build status)
 * - PFX loading and writing helpers
 *
 * Subclasses implement the platform-specific methods: findExistingDevCert,
 * saveCertificate, trustCertificate, removeCertificates, and isTrusted.
 */
export abstract class BaseCertificateStore implements PlatformCertificateStore {
  async checkStatus(): Promise<CertificateStatus> {
    const found = await this.findExistingDevCert();
    if (!found) {
      return {
        exists: false,
        isTrusted: false,
        thumbprint: null,
        notBefore: null,
        notAfter: null,
        version: -1,
      };
    }

    const { cert, thumbprint } = found;
    const trusted = await this.isTrusted(cert, thumbprint);
    const version = getCertificateVersion(cert);

    return {
      exists: true,
      isTrusted: trusted,
      thumbprint,
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      version,
    };
  }

  abstract findExistingDevCert(): Promise<{
    cert: DevCert;
    key: DevKey;
    thumbprint: string;
  } | null>;

  abstract saveCertificate(
    cert: DevCert,
    key: DevKey,
    thumbprint: string
  ): Promise<void>;

  abstract trustCertificate(cert: DevCert): Promise<void>;

  abstract removeCertificates(): Promise<void>;

  /**
   * Platform-specific trust verification.
   * Called by checkStatus() to determine if the certificate is trusted.
   */
  protected abstract isTrusted(
    cert: DevCert,
    thumbprint: string
  ): Promise<boolean>;

  // --- Shared helpers ---

  /**
   * Parse a PFX file and extract the certificate, private key, and thumbprint.
   * Returns null if the file cannot be parsed or is missing cert/key bags.
   */
  protected async loadPfx(
    pfxPath: string,
    password: string = ""
  ): Promise<{ cert: DevCert; key: DevKey; thumbprint: string } | null> {
    try {
      const pfxBytes = fs.readFileSync(pfxPath);
      const { cert, key } = await parsePfx(pfxBytes, password);
      if (!key) return null;
      // .NET X509Store keys files by SHA-1, so the thumbprint we hand
      // back here (which becomes the {thumbprint}.pfx filename) is SHA-1.
      return { cert, key, thumbprint: cert.thumbprintSha1 };
    } catch {
      return null;
    }
  }

  /**
   * Write a certificate and key as a PFX file.
   */
  protected async writePfx(
    cert: DevCert,
    key: DevKey,
    pfxPath: string,
    password: string = "",
    mode?: number
  ): Promise<void> {
    const der = await buildPfx({ cert, key, password });
    const options = mode !== undefined ? { mode } : undefined;
    fs.writeFileSync(pfxPath, der, options);
  }

  /**
   * Scan a directory for PFX files containing valid dev certs.
   * Returns the one with the highest version, or null if none found.
   */
  protected async findBestDevCertInDir(
    dir: string,
    password: string = ""
  ): Promise<{ cert: DevCert; key: DevKey; thumbprint: string } | null> {
    if (!fs.existsSync(dir)) return null;

    let best: { cert: DevCert; key: DevKey; thumbprint: string } | null = null;
    let bestVersion = -1;

    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".pfx"));
    for (const file of files) {
      try {
        const result = await this.loadPfx(`${dir}/${file}`, password);
        if (!result || !isValidDevCert(result.cert)) continue;

        const version = getCertificateVersion(result.cert);
        if (version > bestVersion) {
          best = result;
          bestVersion = version;
        }
      } catch {
        // Skip invalid PFX files
      }
    }

    return best;
  }
}
