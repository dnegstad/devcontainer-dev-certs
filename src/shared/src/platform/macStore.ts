import { randomUUID } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  BaseCertificateStore,
  extractThumbprintHintFromFilename,
  type UsableDevCert,
} from "./baseStore";
import { runProcess } from "./processUtil";
import { getCertificateVersion, isValidDevCert } from "../cert/validation";
import { certToDer } from "../cert/exporter";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { DevCert, type DevKey } from "../cert/types";

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

  async findExistingDevCert(): Promise<UsableDevCert | null> {
    const context = "macOS login keychain";
    const usable: UsableDevCert[] = [];
    const seenThumbprints = new Set<string>();

    // 1) Walk ~/.aspnet/dev-certs/https/. For each parseable PFX whose cert
    //    passes isValidDevCert, additionally verify a matching cert is
    //    actually present in the login keychain via `security find-
    //    certificate -Z <thumb>` (public-only, no prompt). PFXs whose cert
    //    isn't in the keychain are classified as "orphaned cache file"
    //    skipped entries and excluded from selection.
    if (fs.existsSync(this.devCertsDir)) {
      const pfxFiles = fs
        .readdirSync(this.devCertsDir)
        .filter(
          (f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx")
        );

      for (const pfxFile of pfxFiles) {
        const pfxPath = path.join(this.devCertsDir, pfxFile);
        const loaded = await this.loadPfxLenient(pfxPath);

        if (!loaded) {
          this.classify({
            kind: "parseFailure",
            source: pfxPath,
            thumbprintHint: extractThumbprintHintFromFilename(pfxFile),
          });
          continue;
        }

        const classified = this.classify({
          kind: "loaded",
          source: pfxPath,
          loaded,
        });
        if (classified === null) continue;
        if (classified.kind !== "usable") {
          seenThumbprints.add(loaded.thumbprint);
          continue;
        }

        // Verify keychain presence — no prompt, public-only.
        const inKeychain = await this.isCertInKeychain(classified.thumbprint);
        if (!inKeychain) {
          this.classify({
            kind: "forcedSkip",
            source: pfxPath,
            reason: this.localize(
              "PFX present on disk but matching certificate not in macOS login keychain (orphaned cache file)"
            ),
            metadata: {
              thumbprint: classified.thumbprint,
              subjectCN: classified.cert.subjectCN,
              version: getCertificateVersion(classified.cert),
              notBefore: classified.cert.notBefore,
              notAfter: classified.cert.notAfter,
            },
          });
          seenThumbprints.add(classified.thumbprint);
          continue;
        }

        seenThumbprints.add(classified.thumbprint);
        usable.push(classified);
      }
    }

    // 2) Soft keychain enumeration — emit a warning for keychain-resident
    //    dev certs that lack a matching cache PFX. Public-only read, never
    //    triggers an ACL prompt, low EDR signal.
    const keychainEntries = await this.enumerateKeychainDevCerts();
    for (const entry of keychainEntries) {
      if (seenThumbprints.has(entry.thumbprint)) continue;
      this.classify({
        kind: "forcedSkip",
        source: context,
        reason: this.localize(
          "present in keychain but no matching PFX in {0}",
          `${this.devCertsDir}/aspnetcore-localhost-${entry.thumbprint}.pfx`
        ),
        metadata: {
          thumbprint: entry.thumbprint,
          subjectCN: entry.cert.subjectCN,
          version: getCertificateVersion(entry.cert),
          notBefore: entry.cert.notBefore,
          notAfter: entry.cert.notAfter,
        },
      });
    }

    return this.selectBest(usable, this.devCertsDir);
  }

  /**
   * Returns true if a certificate with the given SHA-1 thumbprint is
   * present in the login keychain. Uses `security find-certificate -Z`
   * which only reads the public certificate — no ACL prompt is raised
   * regardless of the cert's private-key ACL.
   */
  private async isCertInKeychain(thumbprint: string): Promise<boolean> {
    const result = await runProcess("security", [
      "find-certificate",
      "-Z",
      thumbprint,
      this.keychainPath,
    ]);
    return result.exitCode === 0;
  }

  /**
   * Enumerate ASP.NET dev cert candidates that exist in the login keychain.
   * Returns parsed certs whose CN is `localhost`, that bear the ASP.NET
   * custom OID, and whose validity window is current. Public-only, no
   * prompts.
   */
  private async enumerateKeychainDevCerts(): Promise<
    Array<{ cert: DevCert; thumbprint: string }>
  > {
    const result = await runProcess("security", [
      "find-certificate",
      "-a",
      "-p",
      "-Z",
      this.keychainPath,
    ]);
    if (result.exitCode !== 0) return [];

    const out: Array<{ cert: DevCert; thumbprint: string }> = [];
    const pemBlocks = extractPemBlocks(result.stdout);
    for (const pem of pemBlocks) {
      try {
        const cert = new DevCert(pem);
        if (cert.subjectCN !== "localhost") continue;
        if (!cert.hasExtension(ASPNET_HTTPS_OID)) continue;
        if (!isValidDevCert(cert)) continue;
        out.push({ cert, thumbprint: cert.thumbprintSha1 });
      } catch {
        // Skip lines that don't parse as a cert (the -a -p -Z output
        // includes SHA-1 lines interleaved with PEM blocks).
      }
    }
    return out;
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
    // For each PFX we manage on disk, load it, run untrust + delete-from-
    // keychain by thumbprint, then unlink the PFX. Three-step structure
    // because trust settings are stored separately from the cert (in
    // TrustSettings.plist) and reference it by hash — if we delete the
    // cert from the keychain first, the trust settings become orphaned
    // dangling entries that the next `add-trusted-cert` may flag as
    // duplicates.
    //
    // Matching dev certs by filename (`aspnetcore-localhost-*.pfx`) +
    // the dev-cert OID is narrower than matching keychain entries by
    // `-c localhost`: the user may have unrelated `localhost` certs
    // added for other tools, and bulk-untrusting by keychain or by CN
    // would nuke those too.
    if (!fs.existsSync(this.devCertsDir)) return;

    const pfxFiles = fs
      .readdirSync(this.devCertsDir)
      .filter(
        (f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx")
      );

    for (const pfxFile of pfxFiles) {
      const pfxPath = path.join(this.devCertsDir, pfxFile);
      let parsed: Awaited<ReturnType<typeof this.loadPfx>>;
      try {
        parsed = await this.loadPfx(pfxPath);
      } catch {
        // Unparseable — skip the untrust step but still unlink below
        // so we don't leave stale files around.
        parsed = null;
      }

      if (parsed && parsed.cert.hasExtension(ASPNET_HTTPS_OID)) {
        // Step 1: untrust. `security remove-trusted-cert` takes a
        // cert file (DER / PEM) as its positional, NOT a keychain
        // path. Trust settings were added without `-d` (user domain,
        // matching `add-trusted-cert` above), so we remove without
        // `-d` too. Non-zero exit just means there was no trust
        // settings entry to remove — not an error in cleanup.
        const tmpCert = path.join(
          os.tmpdir(),
          `devcert-untrust-${randomUUID()}.cer`
        );
        fs.writeFileSync(tmpCert, certToDer(parsed.cert));
        try {
          await runProcess("security", ["remove-trusted-cert", tmpCert]);
        } finally {
          try {
            fs.unlinkSync(tmpCert);
          } catch {
            /* ignore */
          }
        }

        // Step 2: delete the keychain entries. delete-certificate exits
        // non-zero once there are no more entries matching the hash;
        // loop with a generous bound to drain any duplicates left by
        // past regenerations.
        for (let i = 0; i < 100; i++) {
          const result = await runProcess("security", [
            "delete-certificate",
            "-Z",
            parsed.thumbprint,
            this.keychainPath,
          ]);
          if (result.exitCode !== 0) break;
        }
      }

      // Step 3: unlink the PFX. Done last so a mid-cleanup interruption
      // leaves the file in place and the cleanup is restartable.
      try {
        fs.unlinkSync(pfxPath);
      } catch {
        /* ignore */
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

/**
 * Pull PEM-encoded CERTIFICATE blocks out of `security find-certificate -p`
 * output. The CLI interleaves SHA-1 hash lines (when `-Z` is passed) with
 * the PEM blocks; we just grab the blocks.
 */
function extractPemBlocks(text: string): string[] {
  const blocks: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(text)) !== null) {
    blocks.push(m[0]);
  }
  return blocks;
}
