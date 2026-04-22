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
import { initLogger, log } from "@devcontainer-dev-certs/shared";
import type {
  CertBundle,
  CertMaterial,
  CertMaterialV2,
} from "@devcontainer-dev-certs/shared";

const UI_EXTENSION_ID = "dnegstad.devcontainer-dev-certs-host";
const GET_CERT_COMMAND = "devcontainer-dev-certs.getCertMaterial";
const GET_BUNDLE_COMMAND = "devcontainer-dev-certs.getAllCertMaterial";

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
    injectCertificate();
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

  if (
    parsed.destinations.some((d) => d.kind === "file-single") &&
    bundle.certs.length > 1
  ) {
    vscode.window.showErrorMessage(
      "Dev Certs: extraCertDestinations contains a single-file path but the " +
        "bundle has multiple certs. Use a directory target (trailing /) or " +
        "a ${name} template to disambiguate."
    );
    log(
      "Aborting install: ambiguous single-file destination with multi-cert bundle."
    );
    return;
  }

  const rehashDirs = new Set<string>();
  let successes = 0;

  for (const material of bundle.certs) {
    try {
      if (isCertInstalled(material)) {
        log(
          `Cert '${material.name}' (${material.thumbprint}) already installed, skipping canonical install.`
        );
      } else if (material.kind === "dotnet-dev") {
        log(`Installing dotnet dev cert (${material.thumbprint})...`);
        installDotNetDevCert(material);
      } else {
        log(
          `Installing user cert '${material.name}' (${material.thumbprint})...`
        );
        installUserCert(material);
      }

      for (const dest of parsed.destinations) {
        const result = writeExtraDestination(dest, material);
        for (const err of result.errors) log(err);
        if (result.rehashDir) rehashDirs.add(result.rehashDir);
      }
      successes++;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      log(`Error installing cert '${material.name}': ${message}`);
      vscode.window.showErrorMessage(
        `Dev Certs: Failed to install certificate '${material.name}'. ${message}`
      );
    }
  }

  rehashExtraDestinations(rehashDirs);

  if (successes > 0) {
    const names = bundle.certs.map((c) => c.name).join(", ");
    log(`Installed ${successes} certificate(s): ${names}`);
    vscode.window.showInformationMessage(
      `Dev certificates installed (${successes}): ${names}`
    );
  }
}

async function tryGetBundle(
  includeDotNetDev: boolean,
  includeUserCerts: boolean
): Promise<CertBundle | null> {
  // Prefer the v2 multi-cert command.
  try {
    log("Calling getAllCertMaterial on UI extension...");
    const bundle = (await vscode.commands.executeCommand(GET_BUNDLE_COMMAND, {
      includeDotNetDev,
      includeUserCerts,
    })) as CertBundle | undefined;
    if (bundle) return bundle;
    log("getAllCertMaterial returned no bundle; falling back to legacy command.");
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes(`command '${GET_BUNDLE_COMMAND}' not found`)) {
      log(
        "UI extension does not support getAllCertMaterial; falling back to legacy single-cert command."
      );
    } else {
      log(`Error retrieving cert bundle from host: ${message}`);
      if (
        err instanceof Error &&
        message.includes(`command '${GET_CERT_COMMAND}' not found`)
      ) {
        await promptInstallUiExtension();
        return null;
      }
      vscode.window.showErrorMessage(
        "Dev Certs: Failed to obtain certificates from the host machine. " +
          "Check the Dev Container Dev Certs output on the host for details."
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
    legacy = (await vscode.commands.executeCommand(
      GET_CERT_COMMAND
    )) as CertMaterial | null;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Error retrieving certificate from host: ${message}`);
    if (message.includes(`command '${GET_CERT_COMMAND}' not found`)) {
      log(`UI extension ${UI_EXTENSION_ID} not installed.`);
      await promptInstallUiExtension();
    } else {
      vscode.window.showErrorMessage(
        "Dev Certs: Failed to generate or trust the certificate on the host machine. " +
          "Check the Dev Container Dev Certs output on the host for details."
      );
    }
    return null;
  }

  if (!legacy) {
    log("getCertMaterial returned null.");
    vscode.window.showWarningMessage(
      "Dev Certs: The host extension could not provide certificate material. " +
        "Check the host extension output for details."
    );
    return null;
  }

  const v2: CertMaterialV2 = {
    kind: "dotnet-dev",
    name: "aspnetcore-dev",
    thumbprint: legacy.thumbprint,
    pfxBase64: legacy.pfxBase64,
    pemCertBase64: legacy.pemCertBase64,
    pemKeyBase64: legacy.pemKeyBase64,
    rootPfxBase64: legacy.rootPfxBase64,
    trustInContainer: true,
  };
  return { certs: [v2] };
}

async function promptInstallUiExtension(): Promise<void> {
  const install = "Install Host Extension";
  const choice = await vscode.window.showWarningMessage(
    "Dev Certs: The host companion extension is not installed on your local machine. " +
      "It is required to generate and share development certificates.",
    install
  );

  if (choice === install) {
    await vscode.commands.executeCommand(
      "workbench.extensions.installExtension",
      UI_EXTENSION_ID
    );
    vscode.window
      .showInformationMessage(
        "Dev Certs: Host extension installed. Reload the window to complete setup.",
        "Reload"
      )
      .then((action) => {
        if (action === "Reload") {
          vscode.commands.executeCommand("workbench.action.reloadWindow");
        }
      });
  }
}

export function deactivate(): void {
  // Nothing to clean up
}
