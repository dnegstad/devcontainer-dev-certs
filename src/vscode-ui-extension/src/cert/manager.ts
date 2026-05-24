import { generateCertificate, type GeneratedCert } from "./generator";
import { exportPfx, exportPem, exportRootPfx } from "./exporter";
import { VALIDITY_DAYS } from "./properties";
import {
  type PlatformCertificateStore,
  type CertificateStatus,
  type LinuxNssTrustReporter,
  createPlatformStore,
} from "../platform/types";
import { log } from "@devcontainer-dev-certs/shared";

export interface CertManagerOptions {
  /**
   * Optional reporter invoked by the Linux platform store after attempting
   * browser-NSS trust as part of `trustCertificate`. No-op on other
   * platforms.
   */
  linuxNssTrustReporter?: LinuxNssTrustReporter;
}

/**
 * Certificate manager that orchestrates generation, trust, export, and status
 * checking using platform-specific stores.
 */
export class CertManager {
  private store: PlatformCertificateStore | null = null;
  private currentCert: GeneratedCert | null = null;

  constructor(private readonly options: CertManagerOptions = {}) {}

  private async getStore(): Promise<PlatformCertificateStore> {
    this.store ??= await createPlatformStore({
      linuxNssTrustReporter: this.options.linuxNssTrustReporter,
    });
    return this.store;
  }

  /**
   * Generate a new dev cert and save it to the platform store.
   * If force is true, removes existing certs first.
   */
  async generate(force: boolean = false): Promise<void> {
    const store = await this.getStore();

    if (force) {
      log("Removing existing certificates...");
      await store.removeCertificates();
    }

    log("Generating new dev certificate...");
    const now = new Date();
    const expiry = new Date(
      now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
    );
    const generated = await generateCertificate(now, expiry);
    this.currentCert = generated;

    log(`Certificate generated. Thumbprint: ${generated.thumbprint}`);
    await store.saveCertificate(
      generated.cert,
      generated.key,
      generated.thumbprint
    );
    log("Certificate saved to platform store.");
  }

  /**
   * Trust an externally-supplied certificate (e.g. one pushed from a Dev
   * Container via the syncContainerCert reverse-sync flow) in the host
   * OS trust store.
   *
   * Delegates directly to `store.trustCertificate(cert)` — the SAME hook
   * the host-generation flow (`trust()`) uses on its final step — so
   * "trusted on the host" means the same thing regardless of whether
   * the cert was generated here or accepted from a container. On Linux
   * that's `.NET Root store + OpenSSL trust dir + NSS browser DBs` (the
   * NSS step uses the same `linuxNssTrustReporter` callback the host
   * generation flow wires up). On macOS, login keychain trust policy.
   * On Windows, CurrentUser/Root via certutil.
   *
   * Public-cert-only: the cert lands in every trust surface listed
   * above but NEVER in CurrentUser/My, the keychain's identity slot, or
   * the .NET store's `my/` directory. Skipping `saveCertificate` is
   * deliberate — the host doesn't need (and shouldn't store) the
   * private key, because Kestrel runs in the container with its own
   * copy of the key. Future changes to this method MUST preserve both
   * properties: (a) trust goes through `store.trustCertificate`; (b)
   * no `saveCertificate` call. `tests/manager.test.ts` pins both.
   *
   * Does NOT update `currentCert`. The host's auto-generation flow
   * (`generate()` / `trust()`) is a separate state machine that the
   * container-push path doesn't feed into; if the user also has
   * `generateDotNetCert: true` and a subsequent `getAllCertMaterial`
   * pull arrives, the host will generate its own (separate) cert as
   * normal.
   */
  async trustExternalCertificate(
    cert: GeneratedCert["cert"]
  ): Promise<void> {
    const store = await this.getStore();

    // Verify on-disk state before invoking the platform trust step.
    // Skipping a redundant call matters on macOS where
    // `security add-trusted-cert` is not a no-op for an already-trusted
    // cert (re-touches the trust-settings record, may re-prompt for
    // the keychain password). The same cache-as-goal-state /
    // verify-on-disk pattern is used by the host-generation flow's
    // `trust()` method, just expressed differently because it goes
    // through `checkStatus()` instead of a direct `isCertTrusted`.
    if (await store.isCertTrusted(cert)) {
      log(
        `Externally-supplied dev certificate ${cert.thumbprintSha1} is already trusted on host; skipping platform trust call.`
      );
      return;
    }

    log(
      `Trusting externally-supplied dev certificate ${cert.thumbprintSha1} (public cert only, via the same platform trust path as host-generated)...`
    );
    await store.trustCertificate(cert);
    log("Externally-supplied certificate trusted.");
  }

  /**
   * Ensure a cert exists and is trusted. Generates one if needed.
   */
  async trust(): Promise<void> {
    const store = await this.getStore();
    const status = await store.checkStatus();

    if (!status.exists) {
      await this.generate();
    }

    // Re-check: load from store if we didn't just generate
    if (!this.currentCert) {
      const found = await store.findExistingDevCert();
      if (!found) {
        throw new Error("Failed to find certificate after generation.");
      }
      this.currentCert = found;
    }

    const recheck = await store.checkStatus();
    if (!recheck.isTrusted) {
      log("Trusting certificate in OS store...");
      await store.trustCertificate(this.currentCert.cert);
      log("Certificate trusted.");
    }
  }

  /**
   * Export the current cert in the specified format.
   */
  async exportCert(
    format: "pfx" | "pem" | "root-pfx",
    outputDir: string,
    password?: string
  ): Promise<void> {
    await this.ensureLoaded();

    if (format === "pfx") {
      await exportPfx(
        this.currentCert!.cert,
        this.currentCert!.key,
        outputDir,
        password
      );
    } else if (format === "root-pfx") {
      await exportRootPfx(this.currentCert!.cert, outputDir);
    } else {
      exportPem(this.currentCert!.cert, this.currentCert!.key, outputDir);
    }
  }

  /**
   * Check the status of the dev certificate.
   */
  async check(): Promise<CertificateStatus> {
    const store = await this.getStore();
    return store.checkStatus();
  }

  /**
   * Remove all dev certificates from the platform store.
   */
  async clean(): Promise<void> {
    const store = await this.getStore();
    await store.removeCertificates();
    this.currentCert = null;
    log("All dev certificates removed.");
  }

  /**
   * Ensure we have a loaded cert (from store or freshly generated).
   */
  private async ensureLoaded(): Promise<void> {
    if (this.currentCert) return;

    const store = await this.getStore();
    const found = await store.findExistingDevCert();
    if (!found) {
      throw new Error("No dev certificate found. Generate one first.");
    }
    this.currentCert = found;
  }
}
