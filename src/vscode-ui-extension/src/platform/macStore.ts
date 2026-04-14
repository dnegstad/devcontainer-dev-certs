import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { runProcess, runInTerminal } from "./processUtil";
import { isValidDevCert } from "../cert/generator";
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
export class MacCertificateStore extends BaseCertificateStore {
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
    if (!fs.existsSync(this.devCertsDir)) return null;

    const pfxFiles = fs
      .readdirSync(this.devCertsDir)
      .filter(
        (f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx")
      );

    for (const pfxFile of pfxFiles) {
      try {
        const pfxPath = path.join(this.devCertsDir, pfxFile);
        const result = this.loadPfx(pfxPath);
        if (result && isValidDevCert(result.cert)) {
          return result;
        }
      } catch {
        // Skip invalid PFX files
      }
    }

    return null;
  }

  async saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    thumbprint: string
  ): Promise<void> {
    fs.mkdirSync(this.devCertsDir, { recursive: true });
    const pfxPath = path.join(
      this.devCertsDir,
      `aspnetcore-localhost-${thumbprint}.pfx`
    );
    this.writePfx(cert, key, pfxPath);
  }

  async trustCertificate(cert: forge.pki.Certificate): Promise<void> {
    const tmpCert = path.join(
      os.tmpdir(),
      `devcert-trust-${Date.now()}.cer`
    );
    fs.writeFileSync(tmpCert, certToDer(cert));

    const exitCode = await runInTerminal(
      "Dev Certs: Trust Certificate",
      "security",
      [
        "add-trusted-cert",
        "-p", "basic",
        "-p", "ssl",
        "-k", this.keychainPath,
        tmpCert,
      ]
    );

    // Clean up temp file after the terminal process exits
    try { fs.unlinkSync(tmpCert); } catch { /* ignore */ }

    if (exitCode !== 0) {
      throw new Error("Failed to trust certificate in keychain. Check the terminal output for details.");
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
        .filter(
          (f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx")
        );
      for (const pfxFile of pfxFiles) {
        fs.unlinkSync(path.join(this.devCertsDir, pfxFile));
      }
    }
  }

  protected async isTrusted(
    cert: forge.pki.Certificate,
    _thumbprint: string
  ): Promise<boolean> {
    const tmpCert = path.join(
      os.tmpdir(),
      `devcert-verify-${Date.now()}.cer`
    );
    try {
      fs.writeFileSync(tmpCert, certToDer(cert));

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
}
