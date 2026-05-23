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
  CertBundleV3,
  CertMaterial,
  CertMaterialV2,
  CertMaterialV3,
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

/**
 * Cached cert payload. Holds both wire shapes side-by-side so the V2 and
 * V3 endpoints can both serve from the cache without recomputing — and so
 * repeated V2 calls return object-identical entries (callers depend on
 * cache hits skipping work, not on per-call snapshots).
 */
interface CachedCert {
  v3: CertMaterialV3;
  v2: CertMaterialV2;
}

export class CertProvider {
  private cachedDotNet: CachedCert | null = null;
  private cachedUser = new Map<string, CachedCert>();
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
      thumbprint: cert.v2.thumbprint,
      pfxBase64: cert.v2.pfxBase64 ?? "",
      pemCertBase64: cert.v2.pemCertBase64,
      pemKeyBase64: cert.v2.pemKeyBase64 ?? "",
      rootPfxBase64: cert.v2.rootPfxBase64 ?? "",
    };
  }

  /**
   * V2 entry point — kept for backward compatibility with workspace
   * extensions pinned to the V2 wire contract (passwordless `pfxBase64`,
   * no `installToDotNetStore` flag). New code paths should call
   * `getAllCertMaterialV3` instead.
   *
   * Downmap rules:
   * - dotnet-dev: drop V3-only fields. `pfxBase64` is intrinsically
   *   passwordless either way.
   * - user certs: replace V3's password-preserving `pfxBase64` with the
   *   cached passwordless variant. V2 consumers wrote `pfxBase64`
   *   directly to the .NET X509Store, which requires passwordless; the
   *   user's password is therefore stripped on the V2 wire as it was
   *   before this change. Upgrading the workspace extension to V3
   *   restores password preservation.
   */
  async getAllCertMaterial(
    args: GetAllCertMaterialArgs
  ): Promise<CertBundle> {
    const certs = await this.collect(args);
    return { certs: certs.map((c) => c.v2) };
  }

  /**
   * V3 entry point. Returns the multi-cert bundle with the new password-
   * preserving `pfxBase64`, the per-cert `installToDotNetStore` flag, and
   * the (separate) passwordless `dotNetStorePfxBase64` payload when the
   * cert opted into the store install.
   *
   * Also splices in `pfxPassword` (from the user's `userCertificates`
   * config) and `isDefaultKestrelCert` (from
   * `devcontainerDevCerts.defaultKestrelCertificate`) on a per-call
   * basis. Both are derived from settings, not from cert material, so
   * they live outside the cache and can change without invalidating it.
   */
  async getAllCertMaterialV3(
    args: GetAllCertMaterialArgs
  ): Promise<CertBundleV3> {
    const certs = await this.collect(args);
    const config = vscode.workspace.getConfiguration("devcontainerDevCerts");
    const userConfigs = config.get<UserCertificateConfig[]>(
      "userCertificates",
      []
    );
    const configByName = new Map(userConfigs.map((u) => [u.name, u]));

    const v3Certs: CertMaterialV3[] = certs.map((c) => {
      if (c.v3.kind !== "user") return c.v3;
      const source = configByName.get(c.v3.name);
      if (!source?.pfxPassword) return c.v3;
      return { ...c.v3, pfxPassword: source.pfxPassword };
    });

    const defaultName = resolveDefaultKestrelCertName(v3Certs);
    if (defaultName) {
      const idx = v3Certs.findIndex((c) => c.name === defaultName);
      if (idx >= 0) {
        v3Certs[idx] = { ...v3Certs[idx], isDefaultKestrelCert: true };
      }
    }

    return { certs: v3Certs };
  }

  clearCache(): void {
    this.cachedDotNet = null;
    this.cachedUser.clear();
    this.warnedExpiredCerts.clear();
  }

  private async collect(
    args: GetAllCertMaterialArgs
  ): Promise<CachedCert[]> {
    const config = vscode.workspace.getConfiguration("devcontainerDevCerts");
    const hostWantsDotNet = config.get<boolean>("generateDotNetCert", true);

    const certs: CachedCert[] = [];

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
          const entry = await this.loadUserCert(userConfig, globalStoreOptIn);
          if (entry) certs.push(entry);
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

    return certs;
  }

  private async ensureDotNetDevCert(
    autoProvision: boolean
  ): Promise<CachedCert | null> {
    if (this.cachedDotNet) {
      const status = await this.certManager.check();
      if (
        status.exists &&
        status.thumbprint === this.cachedDotNet.v3.thumbprint
      ) {
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
      const pemCertBase64 = fs.readFileSync(pemCertPath).toString("base64");
      const pemKeyBase64 = fs.readFileSync(pemKeyPath).toString("base64");
      const rootPfxBase64 = fs.readFileSync(rootPfxPath).toString("base64");
      const thumbprint = updatedStatus.thumbprint!;
      const v3: CertMaterialV3 = {
        kind: "dotnet-dev",
        name: DOTNET_DEV_CERT_NAME,
        thumbprint,
        pfxBase64,
        pemCertBase64,
        pemKeyBase64,
        rootPfxBase64,
        trustInContainer: true,
        installToDotNetStore: true,
        dotNetStorePfxBase64: pfxBase64,
      };
      const v2: CertMaterialV2 = {
        kind: "dotnet-dev",
        name: DOTNET_DEV_CERT_NAME,
        thumbprint,
        pfxBase64,
        pemCertBase64,
        pemKeyBase64,
        rootPfxBase64,
        trustInContainer: true,
      };
      const entry: CachedCert = { v3, v2 };

      this.cachedDotNet = entry;
      log(`Dotnet dev cert material ready. Thumbprint: ${thumbprint}`);
      return entry;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  private async loadUserCert(
    config: UserCertificateConfig,
    globalStoreOptIn: boolean
  ): Promise<CachedCert | null> {
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
      // Always compute the passwordless variant when a key is available.
      // V3 ships it on the wire only when installToDotNetStore is true,
      // but the V2 downmap needs it unconditionally to keep V2 wire-compat
      // (passwordless `pfxBase64` always).
      const passwordlessPfxBase64 = loaded.key
        ? (await buildPfx({ cert: loaded.cert, key: loaded.key })).toString(
            "base64"
          )
        : undefined;
      const dotNetStorePfxBase64 = installToDotNetStore
        ? passwordlessPfxBase64
        : undefined;

      const pemCertBase64 = fs
        .readFileSync(exported.pemCertPath)
        .toString("base64");
      const pemKeyBase64 = exported.pemKeyPath
        ? fs.readFileSync(exported.pemKeyPath).toString("base64")
        : undefined;
      const rootPfxBase64 = exported.rootPfxPath
        ? fs.readFileSync(exported.rootPfxPath).toString("base64")
        : undefined;

      const v3: CertMaterialV3 = {
        kind: "user",
        name: config.name,
        thumbprint: loaded.thumbprint,
        pemCertBase64,
        pemKeyBase64,
        pfxBase64,
        rootPfxBase64,
        trustInContainer,
        installToDotNetStore,
        dotNetStorePfxBase64,
      };

      const v2: CertMaterialV2 = {
        kind: "user",
        name: config.name,
        thumbprint: loaded.thumbprint,
        pemCertBase64,
        pemKeyBase64,
        // The V2 wire contract is "passwordless pfxBase64 always" — V2
        // consumers wrote these bytes directly to the .NET store, which
        // requires passwordless. The user's password (when supplied) is
        // therefore stripped on the V2 wire; V3 consumers get the
        // password-preserving copy via `v3.pfxBase64` instead.
        pfxBase64: passwordlessPfxBase64,
        rootPfxBase64,
        trustInContainer,
      };

      const entry: CachedCert = { v3, v2 };
      this.cachedUser.set(cacheKey, entry);
      log(
        `User cert '${config.name}' ready. Thumbprint: ${v3.thumbprint}; ` +
          `installToDotNetStore=${installToDotNetStore}`
      );
      return entry;
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

/**
 * Resolve `devcontainerDevCerts.defaultKestrelCertificate` against the
 * actual bundle we're about to ship. Validates that:
 *   - the setting is a non-empty string,
 *   - it names a user-managed cert currently in the bundle (the
 *     dotnet-dev cert is excluded — Kestrel already auto-discovers it
 *     via X509Store; the setting exists for custom user certs),
 *   - that cert carries a private key (a CA-only entry can't terminate
 *     TLS, so it can't be Kestrel's default).
 *
 * Mismatches log a warning + surface a notification once per resolution
 * so a typo in the setting doesn't silently no-op. The actual password
 * isn't returned here — it travels on the cert material itself as
 * `pfxPassword`, so it stays a single source of truth (the user's
 * `userCertificates[].pfxPassword`).
 */
function resolveDefaultKestrelCertName(
  certs: CertMaterialV3[]
): string | undefined {
  const requested = vscode.workspace
    .getConfiguration("devcontainerDevCerts")
    .get<string>("defaultKestrelCertificate", "")
    .trim();
  if (!requested) return undefined;

  const match = certs.find((c) => c.kind === "user" && c.name === requested);
  if (!match) {
    const message = vscode.l10n.t(
      "Dev Certs: defaultKestrelCertificate is set to '{0}', but no userCertificates entry with that name was synced. The Kestrel default environment variables will not be applied.",
      requested
    );
    log(`[warn] ${message}`);
    void vscode.window.showWarningMessage(message);
    return undefined;
  }
  // `pemKeyBase64` is the canonical "loader found a private key" signal
  // for both PFX-source and PEM-source entries — `pfxBase64` alone can be
  // present for a CA-only PFX (we ship its original bytes verbatim).
  if (!match.pemKeyBase64 || !match.pfxBase64) {
    const message = vscode.l10n.t(
      "Dev Certs: defaultKestrelCertificate '{0}' has no private key (CA-only entry); it cannot serve as Kestrel's default certificate.",
      requested
    );
    log(`[warn] ${message}`);
    void vscode.window.showWarningMessage(message);
    return undefined;
  }
  return match.name;
}
