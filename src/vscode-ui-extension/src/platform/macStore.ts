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
import { certToDer } from "../cert/exporter";

/**
 * macOS certificate store implementation.
 *
 * Storage locations:
 * - Disk: ~/.aspnet/dev-certs/https/aspnetcore-localhost-{thumbprint}.pfx
 * - Keychain: login keychain for trust validation
 *
 * Uses the `security` CLI for keychain trust operations.
 */
export class MacCertificateStore implements PlatformCertificateStore {
  private get devCertsDir(): string {
    return path.join(os.homedir(), ".aspnet", "dev-certs", "https");
  }

  private get keychainPath(): string {
    return path.join(os.homedir(), "Library", "Keychains", "login.keychain-db");
  }

  async findExistingDevCert(): Promise<{
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null> {
    // Check disk storage first
    if (fs.existsSync(this.devCertsDir)) {
      const pfxFiles = fs
        .readdirSync(this.devCertsDir)
        .filter((f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx"));

      for (const pfxFile of pfxFiles) {
        try {
          const pfxPath = path.join(this.devCertsDir, pfxFile);
          const result = this.loadPfx(pfxPath, null);
          if (result && isValidDevCert(result.cert)) {
            return result;
          }
        } catch {
          // Skip invalid PFX files
        }
      }
    }

    return null;
  }

  async saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    thumbprint: string
  ): Promise<void> {
    // Save to disk
    fs.mkdirSync(this.devCertsDir, { recursive: true });
    const pfxPath = path.join(
      this.devCertsDir,
      `aspnetcore-localhost-${thumbprint}.pfx`
    );

    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], null, {
      algorithm: "3des",
    });
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    fs.writeFileSync(pfxPath, Buffer.from(p12Der, "binary"));
  }

  async trustCertificate(cert: forge.pki.Certificate): Promise<void> {
    // Export public cert to temp file
    const tmpCert = path.join(
      os.tmpdir(),
      `devcert-trust-${Date.now()}.cer`
    );
    try {
      const derBytes = certToDer(cert);
      fs.writeFileSync(tmpCert, derBytes);

      const result = await runProcess("security", [
        "add-trusted-cert",
        "-p",
        "basic",
        "-p",
        "ssl",
        "-k",
        this.keychainPath,
        tmpCert,
      ]);

      if (result.exitCode !== 0) {
        throw new Error(
          `Failed to trust certificate in keychain: ${result.stderr}`
        );
      }
    } finally {
      try {
        fs.unlinkSync(tmpCert);
      } catch {
        // best effort cleanup
      }
    }
  }

  async removeCertificates(): Promise<void> {
    // Remove trust entries from keychain (loop because there may be multiple)
    for (let i = 0; i < 10; i++) {
      const result = await runProcess("security", [
        "delete-certificate",
        "-c",
        "localhost",
        this.keychainPath,
      ]);
      if (result.exitCode !== 0) break;
    }

    // Remove trust settings
    await runProcess("security", [
      "remove-trusted-cert",
      "-d",
      this.keychainPath,
    ]);

    // Remove PFX files from disk
    if (fs.existsSync(this.devCertsDir)) {
      const pfxFiles = fs
        .readdirSync(this.devCertsDir)
        .filter((f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx"));
      for (const pfxFile of pfxFiles) {
        fs.unlinkSync(path.join(this.devCertsDir, pfxFile));
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
    const isTrusted = await this.checkTrust(cert);
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

  private async checkTrust(cert: forge.pki.Certificate): Promise<boolean> {
    const tmpCert = path.join(
      os.tmpdir(),
      `devcert-verify-${Date.now()}.cer`
    );
    try {
      const derBytes = certToDer(cert);
      fs.writeFileSync(tmpCert, derBytes);

      const result = await runProcess("security", [
        "verify-cert",
        "-c",
        tmpCert,
        "-p",
        "ssl",
      ]);

      return result.exitCode === 0;
    } finally {
      try {
        fs.unlinkSync(tmpCert);
      } catch {
        // best effort cleanup
      }
    }
  }

  private loadPfx(
    pfxPath: string,
    password: string | null
  ): {
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null {
    const pfxBytes = fs.readFileSync(pfxPath);
    const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password ?? "");

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
