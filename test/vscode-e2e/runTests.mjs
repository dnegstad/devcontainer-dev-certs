#!/usr/bin/env node
/**
 * Launcher for the VS Code E2E suite.
 *
 * Runs in plain Node (not in VS Code): downloads a VS Code build via
 * `@vscode/test-electron`, builds a throwaway sandbox, and starts VS Code with
 * BOTH extensions loaded into one window plus `--extensionTestsPath` pointing
 * at the bundled suite.
 *
 * Usage (from the repo root):
 *   npm run build -w src/vscode-ui-extension
 *   npm run build -w src/vscode-workspace-extension
 *   npm run build:e2e
 *   npm run test:e2e            # on Linux: xvfb-run -a npm run test:e2e
 *
 * The sandbox is a `mkdtemp` directory used as `$HOME`, so everything the
 * workspace extension installs (`~/.dotnet/corefx/...`, `~/.aspnet/...`) lands
 * there instead of in the runner's real home. It is removed on success and
 * deliberately left behind on failure so the artifacts can be inspected.
 */
import { runTests } from "@vscode/test-electron";
import { rmSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  FIXTURE_PEM,
  USER_CERT_NAME,
  buildSandbox,
  ensureFixture,
  repoRoot,
  requireBuilt,
} from "./launcherCommon.mjs";

async function main() {
  ensureFixture();

  const uiExtension = resolve(repoRoot, "src", "vscode-ui-extension");
  const workspaceExtension = resolve(repoRoot, "src", "vscode-workspace-extension");
  requireBuilt("UI extension bundle", join(uiExtension, "dist", "extension.js"));
  requireBuilt(
    "workspace extension bundle",
    join(workspaceExtension, "dist", "extension.js")
  );
  const extensionTestsPath = requireBuilt(
    "E2E suite bundle",
    resolve(repoRoot, ".out", "vscode-e2e", "suite.cjs")
  );

  const sandbox = buildSandbox();
  console.log(`Sandbox: ${sandbox.root}`);

  let exitCode = 0;
  try {
    await runTests({
      version: process.env.DEVCERTS_E2E_VSCODE_VERSION ?? "stable",
      // Both extensions into ONE window. In a local window VS Code ignores
      // `extensionKind`, so the "ui" and "workspace" extensions share an
      // extension host — which is what makes the cross-host commands
      // reachable at all, and also what the serialization guard exists to
      // compensate for.
      extensionDevelopmentPath: [uiExtension, workspaceExtension],
      extensionTestsPath,
      launchArgs: [
        sandbox.workspaceDir,
        "--user-data-dir",
        sandbox.userDataDir,
        "--extensions-dir",
        sandbox.extensionsDir,
        // Installed extensions off; --extensionDevelopmentPath ones still load.
        "--disable-extensions",
        "--disable-gpu",
        "--disable-workspace-trust",
        "--skip-welcome",
        "--skip-release-notes",
        "--no-sandbox",
      ],
      extensionTestsEnv: {
        // Redirects getDotNetStorePath / getDotNetRootStorePath /
        // getKestrelDefaultCertPath, which are all os.homedir()-relative.
        // BOTH are required: Node's os.homedir() reads $HOME on POSIX and
        // %USERPROFILE% on Windows. Setting only HOME leaves a Windows run
        // writing the Root-store PFX into the developer's real profile.
        HOME: sandbox.home,
        USERPROFILE: sandbox.home,
        DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY: sandbox.trustDir,
        // The remote-gate seam. Only honored outside ExtensionMode.Production
        // — see isRemoteContext in the workspace extension.
        DEVCONTAINER_DEV_CERTS_TEST_REMOTE: "1",
        DEVCERTS_E2E_HOME: sandbox.home,
        DEVCERTS_E2E_TRUST_DIR: sandbox.trustDir,
        DEVCERTS_E2E_USER_CERT_NAME: USER_CERT_NAME,
        DEVCERTS_E2E_USER_CERT_PEM: FIXTURE_PEM,
      },
    });
  } catch (err) {
    exitCode = 1;
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
  }

  if (exitCode === 0) {
    rmSync(sandbox.root, { recursive: true, force: true });
  } else {
    console.error(`Sandbox left in place for inspection: ${sandbox.root}`);
  }
  // Setting exitCode and returning, rather than process.exit(), so Node drains
  // stdout/stderr before exiting. process.exit() truncates pending writes on a
  // pipe — which is exactly what CI gives us, and exactly when the stack trace
  // and the sandbox path above are the only things worth having.
  process.exitCode = exitCode;
}

await main();
