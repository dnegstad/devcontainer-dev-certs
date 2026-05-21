import * as vscode from "vscode";
import {
  installDotNetDevCert,
  installUserCert,
  isCertInstalled,
  rehashExtraDestinations,
  writeExtraDestination,
} from "./certInstaller";
import {
  buildManagedMyStoreThumbprints,
  bundleHasManagedDevCert,
  cleanupStaleDevCerts,
  findStaleDevCerts,
  type ArtifactLocation,
  type StaleDevCert,
} from "./cleanupCerts";
import { parseExtraCertDestinations } from "./util/destinations";
import { ensureSslCertDir } from "./util/sslCertDir";
import { upmapV1ToV3, upmapV2ToV3 } from "./util/upmap";
import { initLogger, log } from "@devcontainer-dev-certs/shared";
import type {
  CertBundle,
  CertBundleV3,
  CertMaterial,
} from "@devcontainer-dev-certs/shared";

const UI_EXTENSION_ID = "dnegstad.devcontainer-dev-certs-host";
const GET_CERT_COMMAND = "devcontainer-dev-certs.getCertMaterial";
const GET_BUNDLE_COMMAND = "devcontainer-dev-certs.getAllCertMaterial";
const GET_BUNDLE_V3_COMMAND = "devcontainer-dev-certs.getAllCertMaterialV3";
const CLEANUP_COMMAND = "devcontainer-dev-certs.cleanupStaleDevCerts";
const WARN_STALE_CONFIG_KEY = "warnOnStaleDevCerts";

function isTruthyEnv(val: string | undefined, defaultVal: boolean): boolean {
  if (val === undefined || val === "") return defaultVal;
  return /^(1|true|yes|on)$/i.test(val.trim());
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(initLogger("Dev Container Dev Certs (Remote)"));

  log(`Workspace extension activated. remoteName=${vscode.env.remoteName}`);

  if (!vscode.env.remoteName) {
    log("Not running in a remote context, extension will no-op.");
    return;
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("devcontainer-dev-certs.injectCert", () =>
      injectCertificate()
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(CLEANUP_COMMAND, () =>
      cleanupCommand()
    )
  );

  const config = vscode.workspace.getConfiguration("devcontainer-dev-certs");

  if (config.get<boolean>("ensureSslCertDir", true)) {
    const sslCertDirs = config.get<string>(
      "sslCertDirs",
      "/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl"
    );
    ensureSslCertDir(sslCertDirs);
    log(`SSL_CERT_DIR ensured with system dirs: ${sslCertDirs}`);
  }

  if (config.get<boolean>("autoInject", true)) {
    log("Auto-inject enabled, requesting certificate material...");
    void injectCertificate();
  }
}

async function injectCertificate(): Promise<void> {
  const includeDotNetDev = isTruthyEnv(
    process.env["DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET"],
    true
  );
  const includeUserCerts = isTruthyEnv(
    process.env["DEVCONTAINER_DEV_CERTS_SYNC_USER"],
    true
  );
  const extraDestsRaw =
    process.env["DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS"] ?? "";

  const parsed = parseExtraCertDestinations(extraDestsRaw);
  for (const err of parsed.errors) {
    log(`extraCertDestinations: ${err}`);
  }

  const bundle = await tryGetBundle(includeDotNetDev, includeUserCerts);
  if (!bundle) return;

  if (bundle.certs.length === 0) {
    log("No certs returned from host extension.");
    return;
  }

  const rehashDirs = new Set<string>();
  const newInstalls: string[] = [];
  const alreadyInstalled: string[] = [];
  const failures: string[] = [];

  for (const material of bundle.certs) {
    try {
      if (isCertInstalled(material)) {
        log(
          `Cert '${material.name}' (${material.thumbprint}) already installed, skipping canonical install.`
        );
        alreadyInstalled.push(material.name);
      } else if (material.kind === "dotnet-dev") {
        log(`Installing dotnet dev cert (${material.thumbprint})...`);
        installDotNetDevCert(material);
        newInstalls.push(material.name);
      } else {
        log(
          `Installing user cert '${material.name}' (${material.thumbprint})...`
        );
        installUserCert(material);
        newInstalls.push(material.name);
      }

      for (const dest of parsed.destinations) {
        const result = writeExtraDestination(dest, material);
        for (const err of result.errors) log(err);
        if (result.rehashDir) rehashDirs.add(result.rehashDir);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      failures.push(material.name);
      log(`Error installing cert '${material.name}': ${message}`);
      vscode.window.showErrorMessage(
        vscode.l10n.t(
          "Dev Certs: Failed to install certificate '{0}'. {1}",
          material.name,
          message
        )
      );
    }
  }

  rehashExtraDestinations(rehashDirs);

  const processed = newInstalls.length + alreadyInstalled.length;
  if (processed > 0) {
    log(
      `Synced ${processed} certificate(s): ${newInstalls.length} new, ` +
        `${alreadyInstalled.length} already present` +
        (failures.length ? `, ${failures.length} failed` : "")
    );
  }

  // Only surface a toast when we actually planted something new. Activation
  // on every window reload shouldn't keep nagging the user about the same
  // certs that are already in place.
  if (newInstalls.length > 0) {
    vscode.window.showInformationMessage(
      vscode.l10n.t(
        "Dev certificates installed ({0}): {1}",
        newInstalls.length,
        newInstalls.join(", ")
      )
    );

    void detectStaleAndPromptCleanup(bundle);
  }
}

async function detectStaleAndPromptCleanup(
  bundle: CertBundleV3
): Promise<void> {
  const config = vscode.workspace.getConfiguration("devcontainer-dev-certs");
  if (!config.get<boolean>(WARN_STALE_CONFIG_KEY, true)) return;

  // Nothing is "other" when nothing is "ours" — silently skip the toast
  // when the extension isn't managing a dev cert (generation disabled or
  // host didn't supply one). Surfacing a cleanup prompt in that state
  // would offer to delete every dev cert in the container.
  if (!bundleHasManagedDevCert(bundle)) return;

  const stale = findStaleDevCerts(buildManagedMyStoreThumbprints(bundle));
  if (stale.length === 0) return;

  log(
    `Multiple dev certs detected alongside the extension-managed cert in ` +
      `container's CurrentUser\\My store: ${stale.length}`
  );

  const cleanup = vscode.l10n.t("Clean Up");
  const dismiss = vscode.l10n.t("Don't Show Again");
  const choice = await vscode.window.showWarningMessage(
    vscode.l10n.t(
      "Dev Certs: Detected {0} other dev certificate(s) alongside the extension-managed certificate in this Dev Container. Cleaning them up preserves the extension-managed certificate so .NET/Aspire reliably pick it for TLS.",
      stale.length
    ),
    cleanup,
    dismiss
  );

  if (choice === cleanup) {
    await vscode.commands.executeCommand(CLEANUP_COMMAND);
  } else if (choice === dismiss) {
    await config.update(
      WARN_STALE_CONFIG_KEY,
      false,
      vscode.ConfigurationTarget.Global
    );
  }
}

async function cleanupCommand(): Promise<void> {
  const includeDotNetDev = isTruthyEnv(
    process.env["DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET"],
    true
  );
  const includeUserCerts = isTruthyEnv(
    process.env["DEVCONTAINER_DEV_CERTS_SYNC_USER"],
    true
  );

  // Refuse to run blind: without the live bundle we can't tell stale from
  // legitimately-installed and would risk deleting in-use artifacts.
  const bundle = await tryGetBundle(includeDotNetDev, includeUserCerts);
  if (!bundle) {
    vscode.window.showWarningMessage(
      vscode.l10n.t(
        "Dev Certs: Unable to determine the managed certificate set — aborting cleanup."
      )
    );
    return;
  }

  // The cleanup is built around preserving the extension-managed dev cert.
  // If the user has disabled dev-cert generation (or the host couldn't
  // supply one), there's no "managed" cert to preserve and every dev cert
  // on disk would otherwise be removed — refuse with an explanation
  // instead.
  if (!bundleHasManagedDevCert(bundle)) {
    vscode.window.showWarningMessage(
      vscode.l10n.t(
        "Dev Certs: This Dev Container isn't managing a dev certificate (generation disabled via DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET, or the host extension didn't provide one). The cleanup command preserves the extension-managed certificate and won't run when none exists."
      )
    );
    return;
  }

  const stale = findStaleDevCerts(buildManagedMyStoreThumbprints(bundle));
  if (stale.length === 0) {
    vscode.window.showInformationMessage(
      vscode.l10n.t(
        "Dev Certs: Only the extension-managed dev certificate is present in this Dev Container — nothing to clean up."
      )
    );
    return;
  }

  // Log the full per-cert/per-file candidate list before prompting — the
  // dialog speaks in certificates (one row per thumbprint), but the output
  // channel keeps every underlying file for engineering audit.
  const totalFiles = stale.reduce((n, c) => n + c.artifacts.length, 0);
  log(
    `Cleanup: ${stale.length} other dev cert(s) in CurrentUser\\My; ` +
      `${totalFiles} associated file(s) to remove:`
  );
  for (const s of stale) {
    for (const a of s.artifacts) {
      log(`  ${s.thumbprint} ${logLocationLabel(a.location)}: ${a.fullPath}`);
    }
  }

  const remove = vscode.l10n.t("Remove");
  const detail = formatStaleDetail(stale);
  const confirm = await vscode.window.showWarningMessage(
    vscode.l10n.t(
      "Dev Certs: Remove {0} other dev certificate(s) from this Dev Container, preserving the extension-managed certificate?",
      stale.length
    ),
    { modal: true, detail },
    remove
  );
  if (confirm !== remove) return;

  const result = cleanupStaleDevCerts(stale);

  for (const cert of result.removedCerts) {
    for (const a of cert.artifacts) {
      log(
        `Cleanup: removed ${cert.thumbprint} ${logLocationLabel(a.location)}: ${a.fullPath}`
      );
    }
  }
  for (const f of result.failed) {
    log(
      `Cleanup: failed to remove ${logLocationLabel(f.artifact.location)} ` +
        `${f.artifact.identifier} (${f.artifact.fullPath}): ${f.error}`
    );
  }

  const summary = vscode.l10n.t(
    "Dev Certs: Removed {0} other dev certificate(s) from this Dev Container, preserving the extension-managed certificate{1}{2}.",
    result.removedCerts.length,
    result.failed.length
      ? vscode.l10n.t(" ({0} file(s) failed)", result.failed.length)
      : "",
    result.rehashedTrustDir
      ? vscode.l10n.t(", container trust directory rehashed")
      : ""
  );
  if (result.failed.length > 0) {
    vscode.window.showWarningMessage(summary);
  } else {
    vscode.window.showInformationMessage(summary);
  }
}

// Output-channel labels keep per-location detail (the engineering audit
// trail), with the trust-dir disambiguated from generic OpenSSL trust
// directories. The internal `ArtifactLocation` strings stay unchanged.
function logLocationLabel(loc: ArtifactLocation): string {
  switch (loc) {
    case "my-store":
      return "my-store";
    case "root-store":
      return "root-store";
    case "trust-dir":
      return "aspnet-dev-certs-trust";
  }
}

// Cap the modal at a flat list of thumbprints. Pathological My stores
// (dozens of accumulated dev certs) get an "+N more" footer pointing at
// the output channel for the full enumeration.
const MAX_MODAL_ROWS = 12;

function formatStaleDetail(stale: readonly StaleDevCert[]): string {
  const thumbs = stale.map((s) => s.thumbprint).sort();
  const shown = thumbs.slice(0, MAX_MODAL_ROWS);
  const lines = shown.map((t) => `  ${t}`);
  if (thumbs.length > shown.length) {
    lines.push(
      vscode.l10n.t(
        "  …and {0} more (see the Dev Container Dev Certs output for the full list)",
        thumbs.length - shown.length
      )
    );
  }
  return lines.join("\n");
}

async function tryGetBundle(
  includeDotNetDev: boolean,
  includeUserCerts: boolean
): Promise<CertBundleV3 | null> {
  // Prefer V3. Older host extensions don't know this command; on
  // "command not found" we fall through to V2 (which they do speak).
  try {
    log("Calling getAllCertMaterialV3 on UI extension...");
    const bundle = await vscode.commands.executeCommand<CertBundleV3>(
      GET_BUNDLE_V3_COMMAND,
      { includeDotNetDev, includeUserCerts }
    );
    if (bundle) return bundle;
    log(
      "getAllCertMaterialV3 returned no bundle; falling back to V2 command."
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes(`command '${GET_BUNDLE_V3_COMMAND}' not found`)) {
      log(
        "getAllCertMaterialV3 not available; falling back to V2 command."
      );
    } else {
      log(`Error retrieving cert bundle (V3) from host: ${message}`);
      vscode.window.showErrorMessage(
        vscode.l10n.t(
          "Dev Certs: Failed to obtain certificates from the host machine. Check the Dev Container Dev Certs output on the host for details."
        )
      );
      return null;
    }
  }

  // V2 fallback: passwordless pfxBase64, no installToDotNetStore flag.
  // The host runs this when it's pinned to a pre-V3 version. We upmap each
  // cert to V3 with conservative defaults — always install to the .NET
  // store, since that was the V2 wire contract's implicit behavior.
  try {
    log("Calling getAllCertMaterial (V2) on UI extension...");
    const bundle = await vscode.commands.executeCommand<CertBundle>(
      GET_BUNDLE_COMMAND,
      { includeDotNetDev, includeUserCerts }
    );
    if (bundle) {
      return { certs: bundle.certs.map(upmapV2ToV3) };
    }
    log(
      "getAllCertMaterial returned no bundle; falling back to legacy command."
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes(`command '${GET_BUNDLE_COMMAND}' not found`)) {
      log(
        "getAllCertMaterial not available; falling back to legacy single-cert command."
      );
    } else {
      log(`Error retrieving cert bundle (V2) from host: ${message}`);
      vscode.window.showErrorMessage(
        vscode.l10n.t(
          "Dev Certs: Failed to obtain certificates from the host machine. Check the Dev Container Dev Certs output on the host for details."
        )
      );
      return null;
    }
  }

  // Legacy fallback: single dotnet-dev cert.
  if (!includeDotNetDev) {
    log(
      "Legacy host extension does not provide user certs; includeDotNetDev is false, nothing to sync."
    );
    return { certs: [] };
  }

  let legacy: CertMaterial | null;
  try {
    legacy = await vscode.commands.executeCommand<CertMaterial>(
      GET_CERT_COMMAND
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Error retrieving certificate from host: ${message}`);
    if (message.includes(`command '${GET_CERT_COMMAND}' not found`)) {
      log(`UI extension ${UI_EXTENSION_ID} not installed.`);
      await promptInstallUiExtension();
    } else {
      vscode.window.showErrorMessage(
        vscode.l10n.t(
          "Dev Certs: Failed to generate or trust the certificate on the host machine. Check the Dev Container Dev Certs output on the host for details."
        )
      );
    }
    return null;
  }

  if (!legacy) {
    log("getCertMaterial returned null.");
    vscode.window.showWarningMessage(
      vscode.l10n.t(
        "Dev Certs: The host extension could not provide certificate material. Check the host extension output for details."
      )
    );
    return null;
  }

  return { certs: [upmapV1ToV3(legacy)] };
}

async function promptInstallUiExtension(): Promise<void> {
  const install = vscode.l10n.t("Install Host Extension");
  const choice = await vscode.window.showWarningMessage(
    vscode.l10n.t(
      "Dev Certs: The host companion extension is not installed on your local machine. It is required to generate and share development certificates."
    ),
    install
  );

  if (choice === install) {
    await vscode.commands.executeCommand(
      "workbench.extensions.installExtension",
      UI_EXTENSION_ID
    );
    const reload = vscode.l10n.t("Reload");
    vscode.window
      .showInformationMessage(
        vscode.l10n.t(
          "Dev Certs: Host extension installed. Reload the window to complete setup."
        ),
        reload
      )
      .then((action) => {
        if (action === reload) {
          vscode.commands.executeCommand("workbench.action.reloadWindow");
        }
      });
  }
}

export function deactivate(): void {
  // Nothing to clean up
}
