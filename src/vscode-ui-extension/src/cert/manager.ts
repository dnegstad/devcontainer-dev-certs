import * as forge from "node-forge";
import { generateCertificate, GeneratedCert } from "./generator";
import { exportPfx, exportPem } from "./exporter";
import {
  PlatformCertificateStore,
  CertificateStatus,
  createPlatformStore,
} from "../platform/types";
import { log } from "../util/logger";

/**
 * Certificate manager that orchestrates generation, trust, export, and status
 * checking using platform-specific stores.
 *
 * Replaces the AOT binary ToolRunner with pure TypeScript.
 */
export class CertManager {
  private store: PlatformCertificateStore | null = null;
  private currentCert: GeneratedCert | null = null;

  private async getStore(): Promise<PlatformCertificateStore> {
    if (!this.store) {
      this.store = await createPlatformStore();
    }
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
    const generated = generateCertificate();
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
        throw new Error(
          "Failed to find certificate after generation."
        );
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
    format: "pfx" | "pem",
    outputDir: string,
    password?: string
  ): Promise<void> {
    await this.ensureLoaded();

    if (format === "pfx") {
      exportPfx(
        this.currentCert!.cert,
        this.currentCert!.key,
        outputDir,
        password
      );
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
