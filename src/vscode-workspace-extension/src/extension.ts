import * as vscode from "vscode";
import { installCert, isCertInstalled } from "./certInstaller";
import { ensureSslCertDir } from "./util/sslCertDir";
import { initLogger, log } from "@devcontainer-dev-certs/shared";
import type { CertMaterial } from "@devcontainer-dev-certs/shared";

const UI_EXTENSION_ID = "dnegstad.devcontainer-dev-certs-host";
const GET_CERT_COMMAND = "devcontainer-dev-certs.getCertMaterial";

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
    vscode.commands.registerCommand("devcontainer-dev-certs.injectCert", () =>
      injectCertificate()
    )
  );

  const config = vscode.workspace.getConfiguration("devcontainer-dev-certs");

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
  if (config.get<boolean>("autoInject", true)) {
    log("Auto-inject enabled, requesting certificate material...");
    injectCertificate();
  }
}

async function injectCertificate(): Promise<void> {
  // Check whether the UI extension is installed on the host.
  // We intentionally do not use extensionDependencies because that
  // prevents activation entirely when the host extension is missing,
  // which blocks us from showing a helpful install prompt.
  const uiExtension = vscode.extensions.getExtension(UI_EXTENSION_ID);
  if (!uiExtension) {
    log(`UI extension ${UI_EXTENSION_ID} not installed.`);
    await promptInstallUiExtension();
    return;
  }

  // Without extensionDependencies there is no cross-host activation
  // ordering guarantee — the UI extension may still be activating.
  // Wait for its command to appear before proceeding.
  if (!(await waitForCommand(GET_CERT_COMMAND))) {
    log(
      `Command ${GET_CERT_COMMAND} not available after waiting — UI extension may have failed to activate.`
    );
    vscode.window.showErrorMessage(
      "Dev Certs: The host extension is installed but did not activate. " +
        "Try reloading the window."
    );
    return;
  }

  // Retrieve certificate material from the host UI extension
  let material: CertMaterial | null;
  try {
    log("Calling getCertMaterial on UI extension...");
    material = (await vscode.commands.executeCommand(
      GET_CERT_COMMAND
    )) as CertMaterial | null;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Error retrieving certificate from host: ${message}`);
    vscode.window.showErrorMessage(
      "Dev Certs: Failed to generate or trust the certificate on the host machine. " +
        "Check the Dev Container Dev Certs output on the host for details."
    );
    return;
  }

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

  // Install certificate into the remote environment
  try {
    log("Installing certificate files...");
    installCert(material);
    log("Certificate installed successfully.");

    vscode.window.showInformationMessage(
      `Dev certificate installed. Thumbprint: ${material.thumbprint}`
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`Error installing certificate in remote: ${message}`);
    vscode.window.showErrorMessage(
      "Dev Certs: Failed to install the certificate in the remote environment. " +
        message
    );
  }
}

/**
 * Poll `vscode.commands.getCommands()` until the given command appears
 * or the timeout expires. Handles the activation race when the UI
 * extension is installed but hasn't registered its command yet.
 */
async function waitForCommand(
  commandId: string,
  timeoutMs = 10_000,
  intervalMs = 500
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const commands = await vscode.commands.getCommands(true);
    if (commands.includes(commandId)) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
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
