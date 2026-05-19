import "reflect-metadata";
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
            void showLinuxTrustGuidance(context);
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
          const autoProvisionCfg = vscode.workspace
            .getConfiguration("devcontainer-dev-certs")
            .get<boolean>("autoProvision", true);
          const hostWantsDotNet = vscode.workspace
            .getConfiguration("devcontainerDevCerts")
            .get<boolean>("generateDotNetCert", true);

          const decision = await resolveDotnetProvisioning({
            args,
            hostWantsDotNet,
            autoProvision: autoProvisionCfg,
            checkCert: () => certManager.check(),
            hasPriorConsent: () =>
              context.globalState.get<boolean>("certProvisionConsented") ===
              true,
            recordConsent: () =>
              context.globalState.update("certProvisionConsented", true),
            promptUser: promptForCertConsent,
          });

          const bundle = await certProvider.getAllCertMaterial({
            includeDotNetDev: decision.includeDotNetDev,
            includeUserCerts: decision.effectiveArgs.includeUserCerts,
          });

          if (bundle.certs.some((c) => c.kind === "dotnet-dev")) {
            ensureTerminalSslCertDir(context);
            void showLinuxTrustGuidance(context);
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
 * Show a modal consent dialog before first-time provisioning of the
 * auto-generated ASP.NET Core / Aspire dev certificate. Scoped narrowly to
 * that one cert — declining does NOT disable the extension, and any
 * user-managed certs configured via `devcontainerDevCerts.userCertificates`
 * are still synced into the container.
 */
async function promptForCertConsent(): Promise<boolean> {
  const generate = "Generate & Trust";
  const platformDetail =
    process.platform === "darwin"
      ? "macOS will prompt you for your login keychain password to complete the trust step."
      : process.platform === "win32"
        ? "Windows will ask you to confirm adding the certificate to your user certificate store."
        : "The certificate will be added to your local trust store.";

  const choice = await vscode.window.showInformationMessage(
    "Dev Certs: Generate and trust the ASP.NET Core / Aspire HTTPS development " +
      "certificate on this host so Dev Containers can serve over HTTPS without " +
      "browser warnings? " +
      platformDetail +
      " Declining only skips this cert — user-managed certificates configured " +
      "in devcontainerDevCerts.userCertificates will still sync. To suppress this " +
      "prompt permanently, set devcontainerDevCerts.generateDotNetCert to false.",
    { modal: true },
    generate
  );
  return choice === generate;
}

export interface ResolveDotnetProvisioningDeps {
  args: GetAllCertMaterialArgs | undefined;
  hostWantsDotNet: boolean;
  autoProvision: boolean;
  checkCert: () => Promise<{ exists: boolean; isTrusted: boolean }>;
  hasPriorConsent: () => boolean;
  recordConsent: () => Promise<void> | Thenable<void>;
  promptUser: () => Promise<boolean>;
}

export interface DotnetProvisioningDecision {
  effectiveArgs: GetAllCertMaterialArgs;
  includeDotNetDev: boolean;
}

/**
 * Decide whether to provision the dotnet dev cert for an incoming
 * `getAllCertMaterial` call. Gates on the caller's `includeDotNetDev`, the
 * host's `generateDotNetCert` setting, and `autoProvision`. Only consults
 * `certManager.check()` and shows the consent prompt when all three are on —
 * keeping the OS trust store untouched (and the modal silent) for users who
 * have opted out of the auto-generated cert.
 */
export async function resolveDotnetProvisioning(
  deps: ResolveDotnetProvisioningDeps
): Promise<DotnetProvisioningDecision> {
  const effectiveArgs: GetAllCertMaterialArgs = {
    includeDotNetDev: deps.args?.includeDotNetDev !== false,
    includeUserCerts: deps.args?.includeUserCerts !== false,
  };

  const dotnetWillGenerate =
    effectiveArgs.includeDotNetDev &&
    deps.hostWantsDotNet &&
    deps.autoProvision;

  if (!dotnetWillGenerate) {
    return { effectiveArgs, includeDotNetDev: false };
  }

  const status = await deps.checkCert();
  if (status.exists && status.isTrusted) {
    return { effectiveArgs, includeDotNetDev: true };
  }

  if (deps.hasPriorConsent()) {
    return { effectiveArgs, includeDotNetDev: true };
  }

  const consented = await deps.promptUser();
  if (!consented) {
    log(
      "User declined dotnet dev cert provisioning; returning bundle without it."
    );
    return { effectiveArgs, includeDotNetDev: false };
  }
  await deps.recordConsent();
  return { effectiveArgs, includeDotNetDev: true };
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
