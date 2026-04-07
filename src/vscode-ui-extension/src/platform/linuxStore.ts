import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { PlatformCertificateStore, CertificateStatus } from "./types";
import { runProcess } from "./processUtil";
import {
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
} from "../cert/generator";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { certToPem } from "../cert/exporter";

/**
 * Linux certificate store implementation.
 *
 * Storage locations:
 * - .NET X509Store path: ~/.dotnet/corefx/cryptography/x509stores/my/
 * - OpenSSL trust dir: ~/.aspnet/dev-certs/trust/ (or DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY)
 *
 * Trust is established by:
 * 1. Writing a PFX to the .NET X509Store path (for .NET runtime discovery)
 * 2. Writing a PEM to the OpenSSL trust directory with hash symlinks (for OpenSSL/curl/etc.)
 */
export class LinuxCertificateStore implements PlatformCertificateStore {
  private get dotNetStorePath(): string {
    return path.join(
      os.homedir(),
      ".dotnet",
      "corefx",
      "cryptography",
      "x509stores",
      "my"
    );
  }

  private get dotNetRootStorePath(): string {
    return path.join(
      os.homedir(),
      ".dotnet",
      "corefx",
      "cryptography",
      "x509stores",
      "root"
    );
  }

  private get openSslTrustDir(): string {
    return (
      process.env.DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY ??
      path.join(os.homedir(), ".aspnet", "dev-certs", "trust")
    );
  }

  async findExistingDevCert(): Promise<{
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null> {
    // Search the .NET X509Store My directory for PFX files
    if (!fs.existsSync(this.dotNetStorePath)) return null;

    let best: {
      cert: forge.pki.Certificate;
      key: forge.pki.rsa.PrivateKey;
      thumbprint: string;
    } | null = null;
    let bestVersion = -1;

    const files = fs
      .readdirSync(this.dotNetStorePath)
      .filter((f) => f.endsWith(".pfx"));

    for (const file of files) {
      try {
        const pfxPath = path.join(this.dotNetStorePath, file);
        const result = this.loadPfx(pfxPath);
        if (!result) continue;

        if (!isValidDevCert(result.cert)) continue;

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

  async saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    thumbprint: string
  ): Promise<void> {
    // Save PFX to .NET X509Store My directory
    fs.mkdirSync(this.dotNetStorePath, { recursive: true });

    const pfxPath = path.join(this.dotNetStorePath, `${thumbprint}.pfx`);

    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], null, {
      algorithm: "3des",
    });
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    fs.writeFileSync(pfxPath, Buffer.from(p12Der, "binary"), { mode: 0o600 });
  }

  async trustCertificate(cert: forge.pki.Certificate): Promise<void> {
    // 1. Trust in .NET's Root store
    await this.trustInDotNetRootStore(cert);

    // 2. Trust via OpenSSL directory with hash symlinks
    await this.trustViaOpenSsl(cert);
  }

  async removeCertificates(): Promise<void> {
    // Remove from .NET My store
    this.removeDevCertsFromDir(this.dotNetStorePath);

    // Remove from .NET Root store
    this.removeDevCertsFromDir(this.dotNetRootStorePath);

    // Remove OpenSSL trust files
    if (fs.existsSync(this.openSslTrustDir)) {
      const entries = fs.readdirSync(this.openSslTrustDir);
      for (const entry of entries) {
        if (entry.startsWith("aspnetcore-localhost-")) {
          fs.unlinkSync(path.join(this.openSslTrustDir, entry));
        }
        if (isHashSymlink(entry)) {
          const fullPath = path.join(this.openSslTrustDir, entry);
          try {
            if (fs.lstatSync(fullPath).isSymbolicLink()) {
              fs.unlinkSync(fullPath);
            }
          } catch {
            // ignore
          }
        }
      }
    }
  }

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
    const isTrusted = this.isTrustedViaOpenSsl(thumbprint);
    const version = getCertificateVersion(cert);

    return {
      exists: true,
      isTrusted,
      thumbprint,
      notBefore: cert.validity.notBefore.toISOString(),
      notAfter: cert.validity.notAfter.toISOString(),
      version,
    };
  }

  private async trustInDotNetRootStore(
    cert: forge.pki.Certificate
  ): Promise<void> {
    fs.mkdirSync(this.dotNetRootStorePath, { recursive: true });

    const thumbprint = computeThumbprint(forge.pki.certificateToPem(cert));
    const certPath = path.join(
      this.dotNetRootStorePath,
      `${thumbprint}.pfx`
    );

    // .NET's X509Store on Linux stores certs as individual PFX files.
    // For the Root store, we need a PFX containing only the public cert (no private key).
    // node-forge's toPkcs12Asn1 accepts null for the key parameter.
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
      null as unknown as forge.pki.rsa.PrivateKey,
      [cert],
      null,
      { algorithm: "3des" }
    );
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    fs.writeFileSync(certPath, Buffer.from(p12Der, "binary"), { mode: 0o644 });
  }

  private async trustViaOpenSsl(cert: forge.pki.Certificate): Promise<void> {
    fs.mkdirSync(this.openSslTrustDir, { recursive: true });

    const thumbprint = computeThumbprint(forge.pki.certificateToPem(cert));
    const pemFileName = `aspnetcore-localhost-${thumbprint}.pem`;
    const pemPath = path.join(this.openSslTrustDir, pemFileName);

    // Export public cert as PEM
    const pemContent = certToPem(cert);
    fs.writeFileSync(pemPath, pemContent, { mode: 0o644 });

    // Rehash the directory
    await this.rehashDirectory(this.openSslTrustDir);
  }

  private async rehashDirectory(directory: string): Promise<void> {
    const entries = fs.readdirSync(directory);

    // Remove existing hash symlinks
    for (const entry of entries) {
      if (isHashSymlink(entry)) {
        const fullPath = path.join(directory, entry);
        try {
          if (fs.lstatSync(fullPath).isSymbolicLink()) {
            fs.unlinkSync(fullPath);
          }
        } catch {
          // ignore
        }
      }
    }

    // Create new hash symlinks for all PEM/CRT files
    const certFiles = fs
      .readdirSync(directory)
      .filter((f) => /\.(pem|crt|cer)$/i.test(f));

    for (const certFile of certFiles) {
      const fullPath = path.join(directory, certFile);
      try {
        if (fs.lstatSync(fullPath).isSymbolicLink()) continue;
      } catch {
        continue;
      }

      const hash = await this.getOpenSslSubjectHash(fullPath);
      if (!hash) continue;

      for (let i = 0; i < 10; i++) {
        const linkPath = path.join(directory, `${hash}.${i}`);
        if (!fs.existsSync(linkPath)) {
          fs.symlinkSync(certFile, linkPath);
          break;
        }
      }
    }
  }

  private async getOpenSslSubjectHash(
    certPath: string
  ): Promise<string | null> {
    const result = await runProcess("openssl", [
      "x509",
      "-hash",
      "-noout",
      "-in",
      certPath,
    ]);
    if (result.exitCode !== 0) return null;
    return result.stdout.trim() || null;
  }

  private isTrustedViaOpenSsl(thumbprint: string): boolean {
    const pemPath = path.join(
      this.openSslTrustDir,
      `aspnetcore-localhost-${thumbprint}.pem`
    );
    return fs.existsSync(pemPath);
  }

  private removeDevCertsFromDir(dir: string): void {
    if (!fs.existsSync(dir)) return;

    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".pfx"));
    for (const file of files) {
      const pfxPath = path.join(dir, file);
      try {
        const result = this.loadPfx(pfxPath);
        if (
          result &&
          result.cert.getExtension(ASPNET_HTTPS_OID)
        ) {
          fs.unlinkSync(pfxPath);
        }
      } catch {
        // Skip files that can't be parsed
      }
    }
  }

  private loadPfx(pfxPath: string): {
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null {
    const pfxBytes = fs.readFileSync(pfxPath);
    const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, "");

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
}

function isHashSymlink(filename: string): boolean {
  return /^[0-9a-f]{8}\.\d+$/.test(filename);
}
