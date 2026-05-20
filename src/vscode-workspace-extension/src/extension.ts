import * as vscode from "vscode";
import {
  installDotNetDevCert,
  installUserCert,
  isCertInstalled,
  rehashExtraDestinations,
  writeExtraDestination,
} from "./certInstaller";
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
  }
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
