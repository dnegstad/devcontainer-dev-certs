import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { CertManager } from "./cert/manager";
import { log } from "./util/logger";

export interface CertMaterial {
  thumbprint: string;
  pfxBase64: string;
  pemCertBase64: string;
  pemKeyBase64: string;
}

export class CertProvider {
  private cached: CertMaterial | null = null;

  constructor(private readonly certManager: CertManager) {}

  /**
   * Ensure a valid dev cert exists and is trusted, then return its material as base64.
   * This is called by the workspace extension via cross-host command routing.
   */
  async getCertMaterial(
    autoProvision: boolean
  ): Promise<CertMaterial | null> {
    if (this.cached) {
      // Verify the cached cert is still valid
      const status = await this.certManager.check();
      if (
        status.exists &&
        status.thumbprint === this.cached.thumbprint
      ) {
        return this.cached;
      }
      this.cached = null;
    }

    const status = await this.certManager.check();

    if (!status.exists || !status.isTrusted) {
      if (!autoProvision) {
        log("Certificate not ready and auto-provisioning is disabled.");
        return null;
      }
      log("Ensuring certificate is generated and trusted...");
      await this.certManager.trust();
    }

    // Export to temp dir
    const tmpDir = path.join(
      os.tmpdir(),
      `devcerts-export-${Date.now()}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      await this.certManager.exportCert("pfx", tmpDir);
      await this.certManager.exportCert("pem", tmpDir);

      const pfxPath = path.join(tmpDir, "aspnetcore-dev.pfx");
      const pemCertPath = path.join(tmpDir, "aspnetcore-dev.pem");
      const pemKeyPath = path.join(tmpDir, "aspnetcore-dev.key");

      const updatedStatus = await this.certManager.check();

      const material: CertMaterial = {
        thumbprint: updatedStatus.thumbprint!,
        pfxBase64: fs.readFileSync(pfxPath).toString("base64"),
        pemCertBase64: fs.readFileSync(pemCertPath).toString("base64"),
        pemKeyBase64: fs.readFileSync(pemKeyPath).toString("base64"),
      };

      this.cached = material;
      log(
        `Certificate material ready. Thumbprint: ${material.thumbprint}`
      );
      return material;
    } finally {
      // Clean up temp dir
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  clearCache(): void {
    this.cached = null;
  }
}
