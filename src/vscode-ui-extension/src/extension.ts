import * as vscode from "vscode";
import { CertManager } from "./cert/manager";
import { CertProvider } from "./certProvider";
import { log } from "./util/logger";

export function activate(context: vscode.ExtensionContext): void {
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
