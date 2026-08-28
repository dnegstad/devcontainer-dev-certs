import * as fs from "fs";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { trustInNss, type NssTrustResult } from "./nssTrust";
import { type LinuxNssTrustReporter, type BaseStoreOptions } from "./types";
import { type DevCert, type DevKey } from "../cert/types";
import { buildPfx } from "../cert/pfx";
import { ensureHashSymlink, hasHashSymlink } from "../cert/rehash";
import {
  getDotNetStorePath,
  getDotNetRootStorePath,
  getOpenSslTrustDir,
  getPemFileName,
} from "../paths";
import { log } from "../logger";

export interface LinuxCertificateStoreOptions extends BaseStoreOptions {
  /**
   * Optional callback invoked once with the result of the best-effort
   * browser-NSS trust step inside `trustCertificate`. Omitting it disables
   * the NSS step entirely (used by integration tests and CLI contexts
   * where browser trust isn't relevant).
   */
  nssTrustReporter?: LinuxNssTrustReporter;
}

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
 * 3. Best-effort import into Linux browser NSS databases, when a reporter
 *    is configured.
 */
export class LinuxCertificateStore extends BaseCertificateStore {
  private readonly nssTrustReporter?: LinuxNssTrustReporter;

  constructor(options: LinuxCertificateStoreOptions = {}) {
    super(options);
    this.nssTrustReporter = options.nssTrustReporter;
  }

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
    this.trustViaOpenSsl(cert);
    await this.trustInNssBrowsers(cert);
  }

  /**
   * Best-effort browser NSS trust. Mirrors the Windows / macOS pattern where
   * `trustCertificate` performs every trust step the platform supports out
   * of the box — on Linux that includes adding the cert to the user's NSS
   * databases for Firefox / Chromium-family browsers. Never throws: NSS
   * tooling or stores are commonly absent and shouldn't break .NET / OpenSSL
   * trust. Results are surfaced via the reporter callback (typically used by
   * the extension host to show a manual-guidance toast on failure).
   */
  private async trustInNssBrowsers(cert: DevCert): Promise<void> {
    if (!this.nssTrustReporter) return;

    const pemPath = path.join(
      getOpenSslTrustDir(),
      getPemFileName(cert.thumbprintSha1)
    );
    if (!fs.existsSync(pemPath)) {
      log(`Linux NSS trust: PEM not found at ${pemPath}, skipping.`);
      return;
    }

    let result: NssTrustResult;
    try {
      result = await trustInNss(pemPath);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      log(`Linux NSS trust threw unexpectedly: ${message}`);
      result = { success: false, message };
    }

    this.nssTrustReporter(result, pemPath);
  }

  protected isTrusted(
    cert: DevCert,
    thumbprint: string
  ): Promise<boolean> {
    // Both authoritative trust surfaces `trustCertificate` writes must be
    // present, or callers (CertManager.trust's recheck, the container-push
    // short-circuit in trustExternalCertificate) would skip the repair of
    // whichever one went missing — e.g. a user clearing
    // ~/.dotnet/corefx/.../root/ while the OpenSSL PEM survives would
    // otherwise leave .NET-side trust broken forever. Verifying only one
    // surface was exactly that bug.
    //
    // NSS is intentionally NOT part of this predicate: it's best-effort
    // (certutil is commonly absent), failures are surfaced through the
    // reporter toast with manual guidance, and requiring it here would
    // flap `checkStatus().isTrusted` to permanently-false on hosts
    // without NSS tooling.
    //
    // The hash symlink is part of the OpenSSL surface, not an extra: without a
    // link OpenSSL resolves, the PEM sitting in the directory establishes
    // nothing. Checking it also repairs hosts trusted before the subject hash
    // was computed canonically — their link is under the WRONG hash, so a
    // PEM-and-PFX-only check would report "trusted", skip `trustCertificate`,
    // and leave the broken link in place forever.
    const trustDir = getOpenSslTrustDir();
    const pemFileName = getPemFileName(thumbprint);
    const pemPath = path.join(trustDir, pemFileName);
    const rootPfxPath = path.join(
      this.dotNetRootStorePath,
      `${thumbprint}.pfx`
    );
    return Promise.resolve(
      fs.existsSync(pemPath) &&
        fs.existsSync(rootPfxPath) &&
        hasHashSymlink(trustDir, pemFileName, cert.pem)
    );
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

  private trustViaOpenSsl(cert: DevCert): void {
    const trustDir = getOpenSslTrustDir();
    fs.mkdirSync(trustDir, { recursive: true });

    const thumbprint = cert.thumbprintSha1;
    const pemFileName = getPemFileName(thumbprint);
    const pemPath = path.join(trustDir, pemFileName);

    // Purely additive: write the new PEM, but do NOT delete other
    // `aspnetcore-localhost-*.pem` files in the trust dir. The previous
    // implementation swept "old rotations" defensively, but that turned
    // every `trustCertificate` call into an implicit revocation of every
    // other dev cert in the trust dir — including the host-generated
    // cert when the container-push reverse-sync flow trusts an
    // additional one, and vice versa. Removing trust from a cert the
    // user (or another flow) explicitly trusted is the cleanup
    // command's job — gated by an explicit user prompt — not
    // trustCertificate's. The cleanup sweep continues to handle
    // legitimately stale artifacts; this method stays additive so the
    // generation flow and the reverse-sync flow can coexist without
    // ping-ponging trust.
    //
    // Writing to the exact same path on a same-thumbprint repeat call
    // is idempotent (overwrites identical content); rehashing afterward
    // is a no-op when nothing changed.
    fs.writeFileSync(pemPath, cert.pem, { mode: 0o644 });

    // Targeted symlink for our PEM only — the same call the workspace
    // extension makes on its side of the sync, so both ends of the trust
    // dir are maintained by one implementation. `ensureHashSymlink` is
    // pure TypeScript: the host needs no `openssl` binary to establish
    // OpenSSL trust, which matters because the host is a developer laptop
    // we don't control, not a container image we build.
    ensureHashSymlink(trustDir, pemFileName, cert.pem);
  }
}
