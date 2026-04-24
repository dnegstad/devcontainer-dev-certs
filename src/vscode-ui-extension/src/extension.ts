import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { CertManager } from "./cert/manager";
import { CertProvider } from "./certProvider";
import type { GetAllCertMaterialArgs } from "./certProvider";
import { trustInNss } from "./platform/nssTrust";
import {
  initLogger,
  log,
  getOpenSslTrustDir,
  getPemFileName,
} from "@devcontainer-dev-certs/shared";
import type { CertBundle } from "@devcontainer-dev-certs/shared";

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(initLogger("Dev Container Dev Certs"));

  const certManager = new CertManager();
  const certProvider = new CertProvider(certManager);

  log("UI extension activated (managed certificate provider).");

  // Legacy single-cert command. Kept for backward-compatibility with older
  // pinned workspace extensions.
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "devcontainer-dev-certs.getCertMaterial",
      async () => {
        try {
          const config = vscode.workspace.getConfiguration("devcontainer-dev-certs");
          const autoProvision = config.get<boolean>("autoProvision", true);

          // Consent check only applies when auto-provisioning is enabled AND
          // the host has not disabled dotnet cert generation.
          const hostCfg = vscode.workspace.getConfiguration("devcontainerDevCerts");
          const hostWantsDotNet = hostCfg.get<boolean>("generateDotNetCert", true);

          if (!autoProvision || !hostWantsDotNet) {
            return await certProvider.getCertMaterial(false);
          }

          const status = await certManager.check();
          if (!status.exists || !status.isTrusted) {
            const consented = context.globalState.get<boolean>("certProvisionConsented");
            if (!consented) {
              const userConsented = await promptForCertConsent();
              if (!userConsented) {
                log("User declined certificate provisioning.");
                return null;
              }
              await context.globalState.update("certProvisionConsented", true);
            }
          }

          const material = await certProvider.getCertMaterial(true);

          if (material) {
            ensureTerminalSslCertDir(context);
            showLinuxTrustGuidance(context);
          }

          return material;
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          log(`Error providing certificate material: ${message}`);
          throw err;
        }
      }
    )
  );

  // Multi-cert command: supports dotnet-dev opt-out and user-managed certs.
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "devcontainer-dev-certs.getAllCertMaterial",
      async (args: GetAllCertMaterialArgs | undefined): Promise<CertBundle> => {
        try {
          const effectiveArgs: GetAllCertMaterialArgs = {
            includeDotNetDev: args?.includeDotNetDev !== false,
            includeUserCerts: args?.includeUserCerts !== false,
          };

          const autoProvisionCfg = vscode.workspace
            .getConfiguration("devcontainer-dev-certs")
            .get<boolean>("autoProvision", true);
          const hostWantsDotNet = vscode.workspace
            .getConfiguration("devcontainerDevCerts")
            .get<boolean>("generateDotNetCert", true);

          const dotnetWillGenerate =
            effectiveArgs.includeDotNetDev && hostWantsDotNet && autoProvisionCfg;

          if (dotnetWillGenerate) {
            const status = await certManager.check();
            if (!status.exists || !status.isTrusted) {
              const consented = context.globalState.get<boolean>(
                "certProvisionConsented"
              );
              if (!consented) {
                const userConsented = await promptForCertConsent();
                if (!userConsented) {
                  log(
                    "User declined dotnet dev cert provisioning; returning bundle without it."
                  );
                  return await certProvider.getAllCertMaterial({
                    ...effectiveArgs,
                    includeDotNetDev: false,
                  });
                }
                await context.globalState.update(
                  "certProvisionConsented",
                  true
                );
              }
            }
          }

          const bundle = await certProvider.getAllCertMaterial({
            includeDotNetDev: dotnetWillGenerate,
            includeUserCerts: effectiveArgs.includeUserCerts,
          });

          if (bundle.certs.some((c) => c.kind === "dotnet-dev")) {
            ensureTerminalSslCertDir(context);
            showLinuxTrustGuidance(context);
          }

          return bundle;
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          log(`Error providing certificate bundle: ${message}`);
          throw err;
        }
      }
    )
  );

  // Trust the dev certificate in browser NSS databases (Linux)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "devcontainer-dev-certs.trustInBrowsers",
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
              "To trust manually in Firefox: Settings → Privacy & Security → Certificates → " +
              "View Certificates → Authorities → Import, then select the certificate file.",
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
 * Show a modal consent dialog before first-time certificate provisioning.
 * Explains what the extension does and includes platform-specific details
 * about any OS-level prompts the user will see.
 */
async function promptForCertConsent(): Promise<boolean> {
  const enable = "Enable";
  const platformDetail =
    process.platform === "darwin"
      ? "macOS will prompt you for your login keychain password to complete the trust step."
      : process.platform === "win32"
        ? "Windows will ask you to confirm adding the certificate to your user certificate store."
        : "The certificate will be added to your local trust store.";

  const choice = await vscode.window.showInformationMessage(
    "Dev Certs: This extension generates and trusts an HTTPS development certificate " +
      "so Dev Containers can serve over HTTPS without browser warnings. " +
      platformDetail,
    { modal: true },
    enable
  );
  return choice === enable;
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
    vscode.commands.executeCommand("devcontainer-dev-certs.trustInBrowsers");
  }
}

export function deactivate(): void {
  // Nothing to clean up
}
