import * as fs from "fs";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { runProcess } from "./processUtil";
import { type DevCert, type DevKey } from "../cert/types";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { buildPfx } from "../cert/pfx";
import {
  getDotNetStorePath,
  getDotNetRootStorePath,
  getOpenSslTrustDir,
  getPemFileName,
} from "@devcontainer-dev-certs/shared";

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
  private get dotNetRootStorePath(): string {
    return getDotNetRootStorePath();
  }

  async findExistingDevCert(): Promise<{
    cert: DevCert;
    key: DevKey;
    thumbprint: string;
  } | null> {
    return this.findBestDevCertInDir(getDotNetStorePath());
  }

  async saveCertificate(
    cert: DevCert,
    key: DevKey,
    thumbprint: string
  ): Promise<void> {
    const storeDir = getDotNetStorePath();
    fs.mkdirSync(storeDir, { recursive: true });
    await this.writePfx(
      cert,
      key,
      path.join(storeDir, `${thumbprint}.pfx`),
      "",
      0o600
    );
  }

  async trustCertificate(cert: DevCert): Promise<void> {
    await this.trustInDotNetRootStore(cert);
    await this.trustViaOpenSsl(cert);
  }

  async removeCertificates(): Promise<void> {
    await this.removeDevCertsFromDir(getDotNetStorePath());
    await this.removeDevCertsFromDir(this.dotNetRootStorePath);

    const trustDir = getOpenSslTrustDir();
    if (fs.existsSync(trustDir)) {
      const entries = fs.readdirSync(trustDir);
      for (const entry of entries) {
        const fullPath = path.join(trustDir, entry);
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

  protected isTrusted(
    _cert: DevCert,
    thumbprint: string
  ): Promise<boolean> {
    const pemPath = path.join(getOpenSslTrustDir(), getPemFileName(thumbprint));
    return Promise.resolve(fs.existsSync(pemPath));
  }

  // --- Linux-specific trust helpers ---

  private async trustInDotNetRootStore(cert: DevCert): Promise<void> {
    fs.mkdirSync(this.dotNetRootStorePath, { recursive: true });

    const thumbprint = cert.thumbprintSha1;
    const certPath = path.join(this.dotNetRootStorePath, `${thumbprint}.pfx`);

    // .NET's X509Store on Linux stores certs as individual PFX files.
    // For the Root store, we need a PFX containing only the public cert (no private key).
    const pfxBytes = await buildPfx({ cert });
    fs.writeFileSync(certPath, pfxBytes, { mode: 0o644 });
  }

  private async trustViaOpenSsl(cert: DevCert): Promise<void> {
    const trustDir = getOpenSslTrustDir();
    fs.mkdirSync(trustDir, { recursive: true });

    const thumbprint = cert.thumbprintSha1;
    const pemFileName = getPemFileName(thumbprint);
    const pemPath = path.join(trustDir, pemFileName);

    fs.writeFileSync(pemPath, cert.pem, { mode: 0o644 });
    await this.rehashDirectory(trustDir);
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

  private async removeDevCertsFromDir(dir: string): Promise<void> {
    if (!fs.existsSync(dir)) return;

    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".pfx"));
    for (const file of files) {
      const pfxPath = path.join(dir, file);
      try {
        const result = await this.loadPfx(pfxPath);
        if (result && result.cert.hasExtension(ASPNET_HTTPS_OID)) {
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
