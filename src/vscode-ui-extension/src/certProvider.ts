import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { type CertManager } from "./cert/manager";
import { exportLoadedCert } from "./cert/exporter";
import { loadPemPair, loadPfx } from "./cert/loader";
import type { LoadedCert } from "./cert/loader";
import { buildPfx } from "./cert/pfx";
import { assertValidCertName, log } from "@devcontainer-dev-certs/shared";
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
  excludeFromDotNetStore?: boolean;
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
      const globalStoreOptIn = config.get<boolean>(
        "installUserCertsToDotNetStore",
        false
      );
      for (const userConfig of userConfigs) {
        try {
          const mat = await this.loadUserCert(userConfig, globalStoreOptIn);
          if (mat) certs.push(mat);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          log(
            `Failed to load user certificate '${userConfig.name}': ${message}`
          );
          void vscode.window.showErrorMessage(
            vscode.l10n.t(
              "Dev Certs: Failed to load user certificate '{0}': {1}",
              userConfig.name,
              message
            )
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

    // mkdtempSync gives us a unique 0o700 dir in tmpdir. Combined with
    // 0o600 modes on the key/PFX writes themselves, the unencrypted key
    // material is never readable by other local users while it's on disk.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-export-"));

    try {
      await this.certManager.exportCert("pfx", tmpDir);
      await this.certManager.exportCert("pem", tmpDir);
      await this.certManager.exportCert("root-pfx", tmpDir);

      const pfxPath = path.join(tmpDir, "aspnetcore-dev.pfx");
      const pemCertPath = path.join(tmpDir, "aspnetcore-dev.pem");
      const pemKeyPath = path.join(tmpDir, "aspnetcore-dev.key");
      const rootPfxPath = path.join(tmpDir, "aspnetcore-dev-root.pfx");

      const updatedStatus = await this.certManager.check();

      // The dotnet-dev cert is intrinsically passwordless and its canonical
      // home is the .NET store, so `pfxBase64` and `dotNetStorePfxBase64`
      // share the same bytes — there's no consent decision to make here.
      const pfxBase64 = fs.readFileSync(pfxPath).toString("base64");
      const material: CertMaterialV2 = {
        kind: "dotnet-dev",
        name: DOTNET_DEV_CERT_NAME,
        thumbprint: updatedStatus.thumbprint!,
        pfxBase64,
        pemCertBase64: fs.readFileSync(pemCertPath).toString("base64"),
        pemKeyBase64: fs.readFileSync(pemKeyPath).toString("base64"),
        rootPfxBase64: fs.readFileSync(rootPfxPath).toString("base64"),
        trustInContainer: true,
        installToDotNetStore: true,
        dotNetStorePfxBase64: pfxBase64,
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
    config: UserCertificateConfig,
    globalStoreOptIn: boolean
  ): Promise<CertMaterialV2 | null> {
    // Enforced before any filesystem operation — the name is used directly
    // as a filename stem in the temp export dir, the container trust PEM,
    // and each extra destination. Reject anything that could path-traverse.
    assertValidCertName(config.name);

    const hasPfx = Boolean(config.pfxPath);
    const hasPem = Boolean(config.pemCertPath);
    if (hasPfx === hasPem) {
      throw new Error(
        `userCertificates entry '${config.name}' must specify exactly one of 'pfxPath' or 'pemCertPath'.`
      );
    }

    let loaded: LoadedCert;
    if (hasPfx) {
      loaded = await loadPfx(config.pfxPath!, config.pfxPassword);
    } else {
      loaded = loadPemPair(config.pemCertPath!, config.pemKeyPath ?? null);
    }

    const installToDotNetStore =
      globalStoreOptIn && !config.excludeFromDotNetStore;

    // The cache key includes the resolved store opt-in so toggling the
    // global setting (or excludeFromDotNetStore on a single cert) rebuilds
    // the material with the right dotNetStorePfxBase64 presence rather
    // than serving a stale entry from before the toggle.
    const cacheKey = `${config.name}:${loaded.thumbprint}:${
      installToDotNetStore ? "store" : "nostore"
    }`;
    const cached = this.cachedUser.get(cacheKey);
    if (cached) return cached;

    if (loaded.isExpired) {
      this.warnExpired(config.name, loaded.cert.notAfter);
    }

    const trustInContainer = config.trustInContainer !== false;

    // Per-cert isolated 0o700 temp dir; name embedded for debuggability.
    const tmpDir = fs.mkdtempSync(
      path.join(os.tmpdir(), `devcerts-user-export-${config.name}-`)
    );

    try {
      const exported = await exportLoadedCert(loaded, config.name, tmpDir, {
        includeRootPfx: trustInContainer,
      });

      const pfxBase64 = await this.buildUserPfxBase64(loaded, config);
      const dotNetStorePfxBase64 = installToDotNetStore
        ? await this.buildPasswordlessStorePfxBase64(loaded, config)
        : undefined;

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
        pfxBase64,
        rootPfxBase64: exported.rootPfxPath
          ? fs.readFileSync(exported.rootPfxPath).toString("base64")
          : undefined,
        trustInContainer,
        installToDotNetStore,
        dotNetStorePfxBase64,
      };

      this.cachedUser.set(cacheKey, material);
      log(
        `User cert '${config.name}' ready. Thumbprint: ${material.thumbprint}; ` +
          `installToDotNetStore=${installToDotNetStore}`
      );
      return material;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  /**
   * Build the password-preserving PFX bytes for a user cert. PFX-sourced
   * entries pass through their original file bytes verbatim — no decrypt /
   * re-encrypt round-trip, so the user's password survives untouched (this
   * is the consent contract: we never strip a password the user supplied).
   * PEM-sourced entries get a fresh PFX built around their existing PEM
   * material. If `pfxPassword` is set we use it as the encryption password;
   * if it's unset we encode with an empty password, which matches the on-
   * disk security posture of the source PEM key file (unencrypted either
   * way — nothing to strip).
   */
  private async buildUserPfxBase64(
    loaded: LoadedCert,
    config: UserCertificateConfig
  ): Promise<string | undefined> {
    if (config.pfxPath) {
      return fs.readFileSync(config.pfxPath).toString("base64");
    }
    if (!loaded.key) return undefined;
    const bytes = await buildPfx({
      cert: loaded.cert,
      key: loaded.key,
      password: config.pfxPassword ?? "",
    });
    return bytes.toString("base64");
  }

  /**
   * Build the passwordless PFX bytes that get written to the .NET X509Store.
   * `StoreName.My` enumeration on Linux opens each file with a null password,
   * so the store copy *must* be passwordless — this is the consented strip
   * the user opted into via `installUserCertsToDotNetStore`. We never write
   * these bytes anywhere else (`pfxBase64` carries the password-preserving
   * payload for everything else).
   */
  private async buildPasswordlessStorePfxBase64(
    loaded: LoadedCert,
    config: UserCertificateConfig
  ): Promise<string | undefined> {
    if (!loaded.key) {
      log(
        `User cert '${config.name}' has no private key; skipping X509Store install.`
      );
      return undefined;
    }
    const bytes = await buildPfx({ cert: loaded.cert, key: loaded.key });
    return bytes.toString("base64");
  }

  private warnExpired(name: string, notAfter: Date): void {
    if (this.warnedExpiredCerts.has(name)) return;
    this.warnedExpiredCerts.add(name);
    const iso = notAfter.toISOString();
    log(
      `[warn] Certificate '${name}' expired on ${iso}; it will still be synced to the container, but TLS clients will reject it.`
    );
    void vscode.window.showWarningMessage(
      vscode.l10n.t(
        "Dev Certs: Certificate '{0}' expired on {1}; it will still be synced to the container, but TLS clients will reject it.",
        name,
        iso
      )
    );
  }
}
