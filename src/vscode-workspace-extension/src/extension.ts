import * as vscode from "vscode";
import {
  installDotNetDevCert,
  installUserCert,
  isCertInstalled,
  rehashExtraDestinations,
  writeExtraDestination,
} from "./certInstaller";
import {
  ARTIFACT_LOCATION_LOG_LABEL,
  buildManagedMyStoreThumbprints,
  bundleHasManagedDevCert,
  cleanupStaleDevCerts,
  findStaleDevCerts,
  type CleanupResult,
  type StaleDevCert,
} from "./cleanupCerts";
import { parseExtraCertDestinations } from "./util/destinations";
import { ensureSslCertDir } from "./util/sslCertDir";
import { upmapV1ToV3, upmapV2ToV3 } from "./util/upmap";
import { initLogger, log, revealLogger } from "@devcontainer-dev-certs/shared";
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

/** Post-install detection path. Single prompt; "Clean Up" runs the
 *  sweep immediately. */
async function detectStaleAndPromptCleanup(
  bundle: CertBundleV3
): Promise<void> {
  const config = vscode.workspace.getConfiguration("devcontainer-dev-certs");
  if (!config.get<boolean>(WARN_STALE_CONFIG_KEY, true)) return;

  // Skip when we have no managed cert to preserve — see cleanupCommand.
  if (!bundleHasManagedDevCert(bundle)) return;

  const stale = findStaleDevCerts(buildManagedMyStoreThumbprints(bundle));
  if (stale.length === 0) return;

  logStaleCandidates(stale);
  revealLogger();

  const cleanup = vscode.l10n.t("Clean Up");
  const dismiss = vscode.l10n.t("Don't Show Again");
  const choice = await vscode.window.showWarningMessage(
    vscode.l10n.t(
      "Dev Certs: Detected {0} other dev certificate(s) alongside the extension-managed certificate in this Dev Container. Cleaning them up preserves the extension-managed certificate so .NET/Aspire reliably pick it for TLS. See the Dev Container Dev Certs output for thumbprint details.",
      stale.length
    ),
    cleanup,
    dismiss
  );

  if (choice === cleanup) {
    performCleanup(stale);
  } else if (choice === dismiss) {
    await config.update(
      WARN_STALE_CONFIG_KEY,
      false,
      vscode.ConfigurationTarget.Global
    );
  }
}

/** Command-palette entry. Re-resolves the bundle so a stale snapshot
 *  can't drive deletion, then runs the same prompt + sweep as detection. */
async function cleanupCommand(): Promise<void> {
  const includeDotNetDev = isTruthyEnv(
    process.env["DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET"],
    true
  );
  const includeUserCerts = isTruthyEnv(
    process.env["DEVCONTAINER_DEV_CERTS_SYNC_USER"],
    true
  );

  // Without the live bundle we can't distinguish stale from managed.
  const bundle = await tryGetBundle(includeDotNetDev, includeUserCerts);
  if (!bundle) {
    vscode.window.showWarningMessage(
      vscode.l10n.t(
        "Dev Certs: Unable to determine the managed certificate set — aborting cleanup."
      )
    );
    return;
  }

  // No managed cert → nothing to preserve, so the sweep would delete
  // every dev cert on disk. Refuse with an explanation.
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

  logStaleCandidates(stale);
  revealLogger();

  const remove = vscode.l10n.t("Remove");
  const choice = await vscode.window.showWarningMessage(
    vscode.l10n.t(
      "Dev Certs: Remove {0} other dev certificate(s) from this Dev Container, preserving the extension-managed certificate? See the Dev Container Dev Certs output for thumbprint details.",
      stale.length
    ),
    remove
  );
  if (choice !== remove) return;

  performCleanup(stale);
}

/** Run the sweep, log per-file outcomes, surface a summary toast.
 *  Caller is responsible for logging the candidate list beforehand. */
function performCleanup(stale: readonly StaleDevCert[]): void {
  const result = cleanupStaleDevCerts(stale);

  log(
    `Cleanup: removed ${result.removedCerts.length} of ${stale.length} dev cert(s)` +
      (result.failed.length ? `, ${result.failed.length} file(s) failed` : "")
  );
  // Per-file failure detail — actionable, kept terse (location + error).
  for (const f of result.failed) {
    log(
      `  failed: ${f.thumbprint} ${ARTIFACT_LOCATION_LOG_LABEL[f.artifact.location]} (${f.error})`
    );
  }

  const summary = formatCleanupSummary(result);
  if (result.failed.length > 0) {
    vscode.window.showWarningMessage(summary);
  } else {
    vscode.window.showInformationMessage(summary);
  }

  // Re-reveal the output channel so per-file outcomes are visible.
  if (result.removed.length > 0 || result.failed.length > 0) {
    revealLogger();
  }
}

function logStaleCandidates(stale: readonly StaleDevCert[]): void {
  log(`Cleanup: ${stale.length} other dev cert(s) detected:`);
  for (const s of stale) log(`  ${s.thumbprint}`);
}

/** User-visible summary line for a completed cleanup. */
export function formatCleanupSummary(result: CleanupResult): string {
  return vscode.l10n.t(
    "Dev Certs: Removed {0} other dev certificate(s) from this Dev Container, preserving the extension-managed certificate{1}{2}.",
    result.removedCerts.length,
    result.failed.length
      ? vscode.l10n.t(" ({0} file(s) failed)", result.failed.length)
      : "",
    result.rehashedTrustDir
      ? vscode.l10n.t(", container trust directory rehashed")
      : ""
  );
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
