import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { runProcess } from "./processUtil";
import { computeThumbprint } from "../cert/generator";
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
 * 1. Writing a PFX to the .NET Root store path (for .NET runtime validation)
 * 2. Writing a PEM to the OpenSSL trust directory with hash symlinks (for OpenSSL/curl/etc.)
 */
export class LinuxCertificateStore extends BaseCertificateStore {
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
    return this.findBestDevCertInDir(this.dotNetStorePath);
  }

  async saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    thumbprint: string
  ): Promise<void> {
    fs.mkdirSync(this.dotNetStorePath, { recursive: true });
    const pfxPath = path.join(this.dotNetStorePath, `${thumbprint}.pfx`);
    this.writePfx(cert, key, pfxPath, "", 0o600);
  }

  async trustCertificate(cert: forge.pki.Certificate): Promise<void> {
    await this.trustInDotNetRootStore(cert);
    await this.trustViaOpenSsl(cert);
  }

  async removeCertificates(): Promise<void> {
    this.removeDevCertsFromDir(this.dotNetStorePath);
    this.removeDevCertsFromDir(this.dotNetRootStorePath);

    if (fs.existsSync(this.openSslTrustDir)) {
      const entries = fs.readdirSync(this.openSslTrustDir);
      for (const entry of entries) {
        const fullPath = path.join(this.openSslTrustDir, entry);
        if (entry.startsWith("aspnetcore-localhost-")) {
          fs.unlinkSync(fullPath);
        } else if (isHashSymlink(entry)) {
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

  protected async isTrusted(
    _cert: forge.pki.Certificate,
    thumbprint: string
  ): Promise<boolean> {
    const pemPath = path.join(
      this.openSslTrustDir,
      `aspnetcore-localhost-${thumbprint}.pem`
    );
    return fs.existsSync(pemPath);
  }

  // --- Linux-specific trust helpers ---

  private async trustInDotNetRootStore(
    cert: forge.pki.Certificate
  ): Promise<void> {
    fs.mkdirSync(this.dotNetRootStorePath, { recursive: true });

    const thumbprint = computeThumbprint(forge.pki.certificateToPem(cert));
    const certPath = path.join(this.dotNetRootStorePath, `${thumbprint}.pfx`);

    // .NET's X509Store on Linux stores certs as individual PFX files.
    // For the Root store, we need a PFX containing only the public cert (no private key).
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
      null as unknown as forge.pki.rsa.PrivateKey,
      [cert],
      "",
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

    fs.writeFileSync(pemPath, certToPem(cert), { mode: 0o644 });
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

  private removeDevCertsFromDir(dir: string): void {
    if (!fs.existsSync(dir)) return;

    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".pfx"));
    for (const file of files) {
      const pfxPath = path.join(dir, file);
      try {
        const result = this.loadPfx(pfxPath);
        if (result && result.cert.getExtension({ id: ASPNET_HTTPS_OID })) {
          fs.unlinkSync(pfxPath);
        }
      } catch {
        // Skip files that can't be parsed
      }
    }
  }
}

function isHashSymlink(filename: string): boolean {
  return /^[0-9a-f]{8}\.\d+$/.test(filename);
}
