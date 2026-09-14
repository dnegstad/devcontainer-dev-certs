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
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");

const USER_CERT_NAME = "e2e-user-cert";
const FIXTURE_DIR = join(repoRoot, ".out", "test-fixtures");
const FIXTURE_PEM = join(FIXTURE_DIR, "corp-wildcard.pem");
const FIXTURE_KEY = join(FIXTURE_DIR, "corp-wildcard.key");

/** The fixture generator is cheap and deterministic; just run it if needed. */
function ensureFixture() {
  if (existsSync(FIXTURE_PEM) && existsSync(FIXTURE_KEY)) return;
  console.log("Generating test certificate fixture...");
  const result = spawnSync(
    process.execPath,
    [join(repoRoot, "test", "generate-test-cert.mjs")],
    { cwd: repoRoot, stdio: "inherit" }
  );
  if (result.status !== 0) {
    throw new Error("test/generate-test-cert.mjs failed");
  }
}

function requireBuilt(label, path) {
  if (!existsSync(path)) {
    throw new Error(
      `${label} is missing (${path}). Build it first — see the usage note in ` +
        "test/vscode-e2e/runTests.mjs."
    );
  }
  return path;
}

function buildSandbox() {
  const root = mkdtempSync(join(tmpdir(), "devcerts-e2e-"));
  const home = join(root, "home");
  const userDataDir = join(root, "user-data");
  const extensionsDir = join(root, "extensions");
  const workspaceDir = join(root, "workspace");
  const trustDir = join(home, ".aspnet", "dev-certs", "trust");

  for (const dir of [home, userDataDir, extensionsDir, workspaceDir, trustDir]) {
    mkdirSync(dir, { recursive: true });
  }

  // Machine/user settings for the run. `userCertificates` is what makes the
  // host serve a certificate at all; the rest keeps the window quiet and the
  // flow deterministic:
  //   - generateDotNetCert/autoProvision off  → the dev-cert branch (and its
  //     modal consent prompt, and the OS trust-store write) never runs.
  //   - autoInject off → the suite drives the pull explicitly instead of
  //     racing extension activation.
  //   - warnOnStaleDevCerts off → no post-install warning dialog.
  mkdirSync(join(userDataDir, "User"), { recursive: true });
  writeFileSync(
    join(userDataDir, "User", "settings.json"),
    JSON.stringify(
      {
        "devcontainerDevCerts.generateDotNetCert": false,
        "devcontainerDevCerts.autoProvision": false,
        "devcontainerDevCerts.autoInject": false,
        "devcontainerDevCerts.warnOnStaleDevCerts": false,
        "devcontainerDevCerts.installUserCertsToDotNetStore": false,
        "devcontainerDevCerts.userCertificates": [
          {
            name: USER_CERT_NAME,
            pemCertPath: FIXTURE_PEM,
            pemKeyPath: FIXTURE_KEY,
            trustInContainer: true,
          },
        ],
        "security.workspace.trust.enabled": false,
        "telemetry.telemetryLevel": "off",
        "update.mode": "none",
        "extensions.autoUpdate": false,
        "extensions.autoCheckUpdates": false,
        "workbench.startupEditor": "none",
      },
      null,
      2
    )
  );

  return { root, home, userDataDir, extensionsDir, workspaceDir, trustDir };
}

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
        HOME: sandbox.home,
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
  process.exit(exitCode);
}

await main();
