import { randomUUID } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { runProcess } from "./processUtil";
import { isValidDevCert } from "../cert/generator";
import { certToDer } from "../cert/exporter";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { type DevCert, type DevKey } from "../cert/types";

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
    cert: DevCert;
    key: DevKey;
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
        const result = await this.loadPfx(pfxPath);
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
    cert: DevCert,
    key: DevKey,
    thumbprint: string
  ): Promise<void> {
    fs.mkdirSync(this.devCertsDir, { recursive: true });
    const pfxPath = path.join(
      this.devCertsDir,
      `aspnetcore-localhost-${thumbprint}.pfx`
    );
    // ~/.aspnet/dev-certs/https/*.pfx contains the private key; force 0o600
    // so it can't be read by other users on a multi-user mac.
    await this.writePfx(cert, key, pfxPath, "", 0o600);
  }

  async trustCertificate(cert: DevCert): Promise<void> {
    // /tmp is shared on macOS; an unguessable filename rules out symlink
    // races on the temporary public-cert artifact.
    const tmpCert = path.join(os.tmpdir(), `devcert-trust-${randomUUID()}.cer`);
    fs.writeFileSync(tmpCert, certToDer(cert));

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

    try {
      fs.unlinkSync(tmpCert);
    } catch {
      /* ignore */
    }

    if (result.exitCode !== 0) {
      throw new Error(
        `Failed to trust certificate in keychain: ${result.stderr}`
      );
    }
  }

  async removeCertificates(): Promise<void> {
    // Collect SHA-1 thumbprints of every dev cert we have on disk so we
    // can delete keychain entries by hash. Matching on `-c localhost` is
    // too broad — the user may have unrelated `localhost` certs added
    // for other tools and we don't want to nuke those.
    const thumbprints = new Set<string>();
    if (fs.existsSync(this.devCertsDir)) {
      const pfxFiles = fs
        .readdirSync(this.devCertsDir)
        .filter(
          (f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx")
        );
      for (const pfxFile of pfxFiles) {
        try {
          const result = await this.loadPfx(path.join(this.devCertsDir, pfxFile));
          if (result && result.cert.hasExtension(ASPNET_HTTPS_OID)) {
            thumbprints.add(result.thumbprint);
          }
        } catch {
          // Skip unparseable files; they're not ours to delete by hash.
        }
      }
    }

    for (const thumbprint of thumbprints) {
      // delete-certificate exits non-zero once there are no more entries
      // matching the hash; loop with a generous bound to drain any
      // duplicates left by past regenerations.
      for (let i = 0; i < 100; i++) {
        const result = await runProcess("security", [
          "delete-certificate",
          "-Z",
          thumbprint,
          this.keychainPath,
        ]);
        if (result.exitCode !== 0) break;
      }
    }

    // Remove trust settings entries that pointed at any of those certs.
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
    cert: DevCert,
    _thumbprint: string
  ): Promise<boolean> {
    const tmpCert = path.join(os.tmpdir(), `devcert-verify-${randomUUID()}.cer`);
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
