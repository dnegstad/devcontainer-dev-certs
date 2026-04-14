import * as vscode from "vscode";
import { installCert, isCertInstalled } from "./certInstaller";
import { ensureSslCertDir } from "./util/sslCertDir";
import { initLogger, log } from "@devcontainer-dev-certs/shared";
import type { CertMaterial } from "@devcontainer-dev-certs/shared";

const UI_EXTENSION_ID = "dnegstad.devcontainer-dev-certs-host";
const GET_CERT_COMMAND = "dotnet-dev-certs.getCertMaterial";

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(initLogger("Dev Container Dev Certs (Remote)"));

  log(`Workspace extension activated. remoteName=${vscode.env.remoteName}`);

  // This extension only operates in remote contexts (devcontainer, SSH, WSL).
  // No-op when running locally to avoid unnecessary work and user confusion.
  if (!vscode.env.remoteName) {
    log("Not running in a remote context, extension will no-op.");
    return;
  }

  // Register the manual inject command
  context.subscriptions.push(
    vscode.commands.registerCommand("dotnet-dev-certs.injectCert", () =>
      injectCertificate()
    )
  );

  const config = vscode.workspace.getConfiguration("dotnet-dev-certs");

  // Ensure SSL_CERT_DIR is configured — covers SSH remoting, WSL, and other
  // non-devcontainer scenarios where the devcontainer feature isn't present.
  if (config.get<boolean>("ensureSslCertDir", true)) {
    const sslCertDirs = config.get<string>(
      "sslCertDirs",
      "/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl"
    );
    ensureSslCertDir(sslCertDirs);
    log(`SSL_CERT_DIR ensured with system dirs: ${sslCertDirs}`);
  }

  // Auto-inject if configured.
  // The UI extension is guaranteed to be activated before us because
  // we declare it in extensionDependencies and it declares "api": "none",
  // which gives VS Code a hard cross-host activation ordering guarantee.
  if (config.get<boolean>("autoInject", true)) {
    log("Auto-inject enabled, requesting certificate material...");
    injectCertificate();
  }
}

async function injectCertificate(): Promise<void> {
  // Verify the command is available — if not, the UI extension isn't installed
  const commands = await vscode.commands.getCommands(true);
  if (!commands.includes(GET_CERT_COMMAND)) {
    log(`Command ${GET_CERT_COMMAND} not found — UI extension not available.`);
    await promptInstallUiExtension();
    return;
  }

  try {
    log("Calling getCertMaterial on UI extension...");
    const material = (await vscode.commands.executeCommand(
      GET_CERT_COMMAND
    )) as CertMaterial | null;

    if (!material) {
      log("getCertMaterial returned null.");
      vscode.window.showWarningMessage(
        "Dev Certs: The host extension could not provide certificate material. " +
          "Check the host extension output for details."
      );
      return;
    }

    log(`Received cert material. Thumbprint: ${material.thumbprint}`);

    // Idempotent — skip if already installed
    if (isCertInstalled(material.thumbprint)) {
      log("Certificate already installed, skipping.");
      return;
    }

    log("Installing certificate files...");
    installCert(material);
    log("Certificate installed successfully.");

    vscode.window.showInformationMessage(
      `Dev certificate installed. Thumbprint: ${material.thumbprint}`
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Error during injection: ${message}`);
    vscode.window.showErrorMessage(
      `Dev Certs: Failed to get certificate from host: ${message}`
    );
  }
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
    vscode.window.showInformationMessage(
      "Dev Certs: Host extension installed. Reload the window to complete setup.",
      "Reload"
    ).then((action) => {
      if (action === "Reload") {
        vscode.commands.executeCommand("workbench.action.reloadWindow");
      }
    });
  }
}

export function deactivate(): void {
  // Nothing to clean up
}
