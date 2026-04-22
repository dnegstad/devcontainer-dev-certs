import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { CertManager } from "./cert/manager";
import { exportLoadedCert } from "./cert/exporter";
import { loadPemPair, loadPfx } from "./cert/loader";
import type { LoadedCert } from "./cert/loader";
import { log } from "@devcontainer-dev-certs/shared";
import type {
  CertBundle,
  CertMaterial,
  CertMaterialV2,
} from "@devcontainer-dev-certs/shared";
import { DOTNET_DEV_CERT_NAME } from "@devcontainer-dev-certs/shared";

export interface UserCertificateConfig {
  name: string;
  pfxPath?: string;
  pfxPassword?: string;
  pemCertPath?: string;
  pemKeyPath?: string;
  trustInContainer?: boolean;
}

export interface GetAllCertMaterialArgs {
  includeDotNetDev: boolean;
  includeUserCerts: boolean;
}

export class CertProvider {
  private cachedDotNet: CertMaterialV2 | null = null;
  private cachedUser = new Map<string, CertMaterialV2>();
  private warnedExpiredCerts = new Set<string>();

  constructor(private readonly certManager: CertManager) {}

  /**
   * Legacy single-cert entry point. Returns the dotnet-dev cert material in
   * the original v1 shape, or null if provisioning is disabled / the host
   * setting has the auto-generated dev cert turned off.
   */
  async getCertMaterial(
    autoProvision: boolean
  ): Promise<CertMaterial | null> {
    const hostEnabled = vscode.workspace
      .getConfiguration("devcontainerDevCerts")
      .get<boolean>("generateDotNetCert", true);

    if (!hostEnabled) {
      log(
        "generateDotNetCert is disabled in host settings; skipping dev cert provisioning."
      );
      return null;
    }

    const cert = await this.ensureDotNetDevCert(autoProvision);
    if (!cert) return null;

    return {
      thumbprint: cert.thumbprint,
      pfxBase64: cert.pfxBase64 ?? "",
      pemCertBase64: cert.pemCertBase64,
      pemKeyBase64: cert.pemKeyBase64 ?? "",
      rootPfxBase64: cert.rootPfxBase64 ?? "",
    };
  }

  /**
   * Multi-cert entry point. Returns the bundle of certs requested by the
   * caller, combining the optional auto-generated dotnet dev cert with any
   * user-managed certificates configured in VS Code settings.
   */
  async getAllCertMaterial(
    args: GetAllCertMaterialArgs
  ): Promise<CertBundle> {
    const config = vscode.workspace.getConfiguration("devcontainerDevCerts");
    const hostWantsDotNet = config.get<boolean>("generateDotNetCert", true);

    const certs: CertMaterialV2[] = [];

    if (args.includeDotNetDev && hostWantsDotNet) {
      const dotnet = await this.ensureDotNetDevCert(true);
      if (dotnet) certs.push(dotnet);
    } else {
      log(
        `Skipping dotnet dev cert (caller=${args.includeDotNetDev}, host=${hostWantsDotNet}).`
      );
    }

    if (args.includeUserCerts) {
      const userConfigs = config.get<UserCertificateConfig[]>(
        "userCertificates",
        []
      );
      for (const userConfig of userConfigs) {
        try {
          const mat = await this.loadUserCert(userConfig);
          if (mat) certs.push(mat);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          log(
            `Failed to load user certificate '${userConfig.name}': ${message}`
          );
          void vscode.window.showErrorMessage(
            `Dev Certs: Failed to load user certificate '${userConfig.name}': ${message}`
          );
        }
      }
    }

    return { certs };
  }

  clearCache(): void {
    this.cachedDotNet = null;
    this.cachedUser.clear();
    this.warnedExpiredCerts.clear();
  }

  private async ensureDotNetDevCert(
    autoProvision: boolean
  ): Promise<CertMaterialV2 | null> {
    if (this.cachedDotNet) {
      const status = await this.certManager.check();
      if (status.exists && status.thumbprint === this.cachedDotNet.thumbprint) {
        return this.cachedDotNet;
      }
      this.cachedDotNet = null;
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

    const tmpDir = path.join(
      os.tmpdir(),
      `devcerts-export-${Date.now()}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      await this.certManager.exportCert("pfx", tmpDir);
      await this.certManager.exportCert("pem", tmpDir);
      await this.certManager.exportCert("root-pfx", tmpDir);

      const pfxPath = path.join(tmpDir, "aspnetcore-dev.pfx");
      const pemCertPath = path.join(tmpDir, "aspnetcore-dev.pem");
      const pemKeyPath = path.join(tmpDir, "aspnetcore-dev.key");
      const rootPfxPath = path.join(tmpDir, "aspnetcore-dev-root.pfx");

      const updatedStatus = await this.certManager.check();

      const material: CertMaterialV2 = {
        kind: "dotnet-dev",
        name: DOTNET_DEV_CERT_NAME,
        thumbprint: updatedStatus.thumbprint!,
        pfxBase64: fs.readFileSync(pfxPath).toString("base64"),
        pemCertBase64: fs.readFileSync(pemCertPath).toString("base64"),
        pemKeyBase64: fs.readFileSync(pemKeyPath).toString("base64"),
        rootPfxBase64: fs.readFileSync(rootPfxPath).toString("base64"),
        trustInContainer: true,
      };

      this.cachedDotNet = material;
      log(
        `Dotnet dev cert material ready. Thumbprint: ${material.thumbprint}`
      );
      return material;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  private async loadUserCert(
    config: UserCertificateConfig
  ): Promise<CertMaterialV2 | null> {
    if (!config.name) {
      throw new Error("userCertificates entry is missing a 'name'.");
    }

    const hasPfx = Boolean(config.pfxPath);
    const hasPem = Boolean(config.pemCertPath);
    if (hasPfx === hasPem) {
      throw new Error(
        `userCertificates entry '${config.name}' must specify exactly one of 'pfxPath' or 'pemCertPath'.`
      );
    }

    let loaded: LoadedCert;
    if (hasPfx) {
      loaded = loadPfx(config.pfxPath!, config.pfxPassword);
    } else {
      loaded = loadPemPair(config.pemCertPath!, config.pemKeyPath ?? null);
    }

    const cacheKey = `${config.name}:${loaded.thumbprint}`;
    const cached = this.cachedUser.get(cacheKey);
    if (cached) return cached;

    if (loaded.isExpired) {
      this.warnExpired(config.name, loaded.cert.validity.notAfter);
    }

    const trustInContainer = config.trustInContainer !== false;

    const tmpDir = path.join(
      os.tmpdir(),
      `devcerts-user-export-${Date.now()}-${config.name}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      const exported = exportLoadedCert(loaded, config.name, tmpDir, {
        includeRootPfx: trustInContainer,
      });

      const material: CertMaterialV2 = {
        kind: "user",
        name: config.name,
        thumbprint: loaded.thumbprint,
        pemCertBase64: fs
          .readFileSync(exported.pemCertPath)
          .toString("base64"),
        pemKeyBase64: exported.pemKeyPath
          ? fs.readFileSync(exported.pemKeyPath).toString("base64")
          : undefined,
        pfxBase64: exported.pfxPath
          ? fs.readFileSync(exported.pfxPath).toString("base64")
          : undefined,
        rootPfxBase64: exported.rootPfxPath
          ? fs.readFileSync(exported.rootPfxPath).toString("base64")
          : undefined,
        trustInContainer,
      };

      this.cachedUser.set(cacheKey, material);
      log(
        `User cert '${config.name}' ready. Thumbprint: ${material.thumbprint}`
      );
      return material;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  private warnExpired(name: string, notAfter: Date): void {
    if (this.warnedExpiredCerts.has(name)) return;
    this.warnedExpiredCerts.add(name);
    const iso = notAfter.toISOString();
    const message = `Certificate '${name}' expired on ${iso}; it will still be synced to the container, but TLS clients will reject it.`;
    log(`[warn] ${message}`);
    void vscode.window.showWarningMessage(`Dev Certs: ${message}`);
  }
}
