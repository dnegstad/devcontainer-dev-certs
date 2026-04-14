import * as vscode from "vscode";
import { CertManager } from "./cert/manager";
import { CertProvider } from "./certProvider";
import { initLogger, log } from "@devcontainer-dev-certs/shared";

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(initLogger("Dev Container Dev Certs"));

  const certManager = new CertManager();
  const certProvider = new CertProvider(certManager);

  log("UI extension activated (managed certificate provider).");

  context.subscriptions.push(
    vscode.commands.registerCommand(
      "dotnet-dev-certs.getCertMaterial",
      async () => {
        const config = vscode.workspace.getConfiguration("dotnet-dev-certs");
        const autoProvision = config.get<boolean>("autoProvision", true);
        return certProvider.getCertMaterial(autoProvision);
      }
    )
  );
}

export function deactivate(): void {
  // Nothing to clean up
}
