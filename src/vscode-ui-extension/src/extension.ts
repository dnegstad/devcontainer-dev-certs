import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { CertManager } from "./cert/manager";
import { CertProvider } from "./certProvider";
import { trustInNss } from "./platform/nssTrust";
import {
  initLogger,
  log,
  getOpenSslTrustDir,
  getPemFileName,
} from "@devcontainer-dev-certs/shared";

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(initLogger("Dev Container Dev Certs"));

  const certManager = new CertManager();
  const certProvider = new CertProvider(certManager);

  log("UI extension activated (managed certificate provider).");

  // Serve certificate material to the workspace extension
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "dotnet-dev-certs.getCertMaterial",
      async () => {
        const config = vscode.workspace.getConfiguration("dotnet-dev-certs");
        const autoProvision = config.get<boolean>("autoProvision", true);
        const material = await certProvider.getCertMaterial(autoProvision);

        if (material) {
          ensureTerminalSslCertDir(context);
          showLinuxTrustGuidance(context);
        }

        return material;
      }
    )
  );

  // Trust the dev certificate in browser NSS databases (Linux)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "dotnet-dev-certs.trustInBrowsers",
      async () => {
        if (process.platform !== "linux") {
          vscode.window.showInformationMessage(
            "Dev Certs: Browser trust is handled automatically by the OS on this platform."
          );
          return;
        }

        const status = await certManager.check();
        if (!status.exists || !status.thumbprint) {
          vscode.window.showWarningMessage(
            "Dev Certs: No dev certificate found. Open a Dev Container to generate one."
          );
          return;
        }

        const trustDir = getOpenSslTrustDir();
        const pemPath = path.join(trustDir, getPemFileName(status.thumbprint));
        if (!fs.existsSync(pemPath)) {
          vscode.window.showWarningMessage(
            "Dev Certs: Certificate PEM not found at expected location."
          );
          return;
        }

        const result = await trustInNss(pemPath);
        if (result.success) {
          vscode.window.showInformationMessage(
            `Dev Certs: Browser trust updated. ${result.message}`
          );
        } else {
          const copyPath = "Copy Certificate Path";
          const choice = await vscode.window.showWarningMessage(
            `Dev Certs: Could not automatically trust in browsers (${result.message}). ` +
              "To trust manually in Firefox: Settings \u2192 Privacy & Security \u2192 Certificates \u2192 " +
              "View Certificates \u2192 Authorities \u2192 Import, then select the certificate file.",
            copyPath
          );
          if (choice === copyPath) {
            await vscode.env.clipboard.writeText(pemPath);
            vscode.window.showInformationMessage(
              `Dev Certs: Certificate path copied: ${pemPath}`
            );
          }
        }
      }
    )
  );
}

/**
 * On Linux, prepend the dev cert trust directory to SSL_CERT_DIR in VS Code
 * integrated terminal sessions so that curl, wget, and other OpenSSL-based
 * tools trust the dev certificate without manual configuration.
 */
function ensureTerminalSslCertDir(context: vscode.ExtensionContext): void {
  if (process.platform !== "linux") return;

  const trustDir = getOpenSslTrustDir();
  if (!fs.existsSync(trustDir)) return;

  const envCollection = context.environmentVariableCollection;
  envCollection.description =
    "Includes the dev certificate trust directory in SSL_CERT_DIR";
  envCollection.prepend("SSL_CERT_DIR", trustDir + ":");

  log(`SSL_CERT_DIR prepended with ${trustDir} for integrated terminals`);
}

/**
 * Show a one-time informational message on Linux after the first successful
 * cert provision, offering to trust the certificate in browsers.
 */
async function showLinuxTrustGuidance(
  context: vscode.ExtensionContext
): Promise<void> {
  if (process.platform !== "linux") return;
  if (context.globalState.get<boolean>("linuxTrustGuidanceShown")) return;

  const trustBrowsers = "Trust in Browsers";
  const choice = await vscode.window.showInformationMessage(
    "Dev Certs: Certificate is trusted for CLI tools (curl, wget) in VS Code terminals. " +
      "For Firefox and Chromium, additional browser trust setup is needed.",
    trustBrowsers
  );

  await context.globalState.update("linuxTrustGuidanceShown", true);

  if (choice === trustBrowsers) {
    vscode.commands.executeCommand("dotnet-dev-certs.trustInBrowsers");
  }
}

export function deactivate(): void {
  // Nothing to clean up
}
