/**
 * Pieces shared by both E2E launchers: `runTests.mjs` (one local window, the
 * remote-gate seam) and `runDevcontainer.mjs` (a real remote extension host
 * inside a dev container). Plain Node, never loaded into VS Code.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const here = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(here, "..", "..");

export const USER_CERT_NAME = "e2e-user-cert";
export const FIXTURE_DIR = join(repoRoot, ".out", "test-fixtures");
export const FIXTURE_PEM = join(FIXTURE_DIR, "corp-wildcard.pem");
export const FIXTURE_KEY = join(FIXTURE_DIR, "corp-wildcard.key");

/** The fixture generator is cheap and deterministic; just run it if needed. */
export function ensureFixture() {
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

export function requireBuilt(label, path) {
  if (!existsSync(path)) {
    throw new Error(
      `${label} is missing (${path}). Build it first — see the usage note in ` +
        "test/vscode-e2e/runTests.mjs."
    );
  }
  return path;
}

export function buildSandbox() {
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
