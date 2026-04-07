import * as vscode from "vscode";
import { ToolRunner } from "./aotTool/toolRunner";
import { CertProvider } from "./certProvider";
import { getToolPath } from "./util/platform";
import { log } from "./util/logger";

export function activate(context: vscode.ExtensionContext): void {
  const toolPath = getToolPath(context.extensionPath);
  const toolRunner = new ToolRunner(toolPath);
  const certProvider = new CertProvider(toolRunner);

  log(`UI extension activated. Tool path: ${toolPath}`);

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
