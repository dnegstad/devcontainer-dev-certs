import * as forge from "node-forge";
import * as fs from "fs";
import { PlatformCertificateStore, CertificateStatus } from "./types";
import {
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
} from "../cert/generator";

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
      notBefore: cert.validity.notBefore.toISOString(),
      notAfter: cert.validity.notAfter.toISOString(),
      version,
    };
  }

  abstract findExistingDevCert(): Promise<{
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null>;

  abstract saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    thumbprint: string
  ): Promise<void>;

  abstract trustCertificate(cert: forge.pki.Certificate): Promise<void>;

  abstract removeCertificates(): Promise<void>;

  /**
   * Platform-specific trust verification.
   * Called by checkStatus() to determine if the certificate is trusted.
   */
  protected abstract isTrusted(
    cert: forge.pki.Certificate,
    thumbprint: string
  ): Promise<boolean>;

  // --- Shared helpers ---

  /**
   * Parse a PFX file and extract the certificate, private key, and thumbprint.
   * Returns null if the file cannot be parsed or is missing cert/key bags.
   */
  protected loadPfx(
    pfxPath: string,
    password: string = ""
  ): {
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null {
    const pfxBytes = fs.readFileSync(pfxPath);
    const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBag = certBags[forge.pki.oids.certBag];
    if (!certBag || certBag.length === 0) return null;
    const cert = certBag[0].cert;
    if (!cert) return null;

    const keyBags = p12.getBags({
      bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
    });
    const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
    if (!keyBag || keyBag.length === 0) return null;
    const key = keyBag[0].key;
    if (!key) return null;

    const thumbprint = computeThumbprint(forge.pki.certificateToPem(cert));
    return { cert, key, thumbprint };
  }

  /**
   * Write a certificate and key as a PFX file.
   */
  protected writePfx(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    pfxPath: string,
    password: string = "",
    mode?: number
  ): void {
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], password, {
      algorithm: "3des",
    });
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    const options = mode !== undefined ? { mode } : undefined;
    fs.writeFileSync(pfxPath, Buffer.from(p12Der, "binary"), options);
  }

  /**
   * Scan a directory for PFX files containing valid dev certs.
   * Returns the one with the highest version, or null if none found.
   */
  protected findBestDevCertInDir(
    dir: string,
    password: string = ""
  ): {
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null {
    if (!fs.existsSync(dir)) return null;

    let best: {
      cert: forge.pki.Certificate;
      key: forge.pki.rsa.PrivateKey;
      thumbprint: string;
    } | null = null;
    let bestVersion = -1;

    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".pfx"));
    for (const file of files) {
      try {
        const result = this.loadPfx(`${dir}/${file}`, password);
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
