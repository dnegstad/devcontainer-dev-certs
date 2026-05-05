/**
 * Validate the devcontainer feature metadata and check for internal consistency
 * across the feature JSON, install script, and companion extension package.json files.
 *
 * Run from the repository root: node test/validate-feature.mjs
 */
import { readFileSync } from "fs";
import semver from "semver";

const FEATURE_JSON_PATH =
  "src/devcontainer-feature/src/devcontainer-dev-certs/devcontainer-feature.json";
const INSTALL_SH_PATH =
  "src/devcontainer-feature/src/devcontainer-dev-certs/install.sh";
const UI_PKG_PATH = "src/vscode-ui-extension/package.json";
const WORKSPACE_PKG_PATH = "src/vscode-workspace-extension/package.json";
let failures = 0;

function check(label, ok, detail) {
  if (ok) {
    console.log(`  ✓ ${label}`);
  } else {
    console.log(`  ✗ ${label}: ${detail}`);
    failures++;
  }
}

// --- Load files ---

const feature = JSON.parse(readFileSync(FEATURE_JSON_PATH, "utf8"));
const installSh = readFileSync(INSTALL_SH_PATH, "utf8");
const uiPkg = JSON.parse(readFileSync(UI_PKG_PATH, "utf8"));
const workspacePkg = JSON.parse(readFileSync(WORKSPACE_PKG_PATH, "utf8"));

// --- Required fields (devcontainer feature spec) ---

console.log("Feature metadata (required fields):");
check("id", typeof feature.id === "string" && feature.id.length > 0, "missing or empty");
check("version", typeof feature.version === "string" && semver.parse(feature.version, {}, false) != null, `invalid semver: ${feature.version}`);
check("name", typeof feature.name === "string" && feature.name.length > 0, "missing or empty");
check("description", typeof feature.description === "string" && feature.description.length > 0, "missing or empty");

// --- Extension IDs match actual packages ---

console.log("\nExtension ID consistency:");
const declaredExts = feature.customizations?.vscode?.extensions ?? [];
const uiExtId = `${uiPkg.publisher}.${uiPkg.name}`;
const wsExtId = `${workspacePkg.publisher}.${workspacePkg.name}`;

check(
  "UI extension ID in feature matches package.json",
  declaredExts.includes(uiExtId),
  `feature declares ${JSON.stringify(declaredExts)} but UI extension is "${uiExtId}"`
);
check(
  "Workspace extension ID in feature matches package.json",
  declaredExts.includes(wsExtId),
  `feature declares ${JSON.stringify(declaredExts)} but workspace extension is "${wsExtId}"`
);

// --- SSL_CERT_DIR consistency ---

console.log("\nSSL_CERT_DIR consistency:");
const defaultSslDirs = feature.options?.sslCertDirs?.default;

// install.sh writes the trust dir + SSL_CERT_DIRS to /etc/profile.d (login
// shells, $HOME-expanded) and /etc/environment (PAM, REMOTE_USER_HOME-expanded).
check(
  "install.sh writes SSL_CERT_DIR to /etc/profile.d/devcontainer-dev-certs.sh",
  installSh.includes("/etc/profile.d/devcontainer-dev-certs.sh") &&
    installSh.includes(
      'export SSL_CERT_DIR=\\"\\$HOME/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}\\"'
    ),
  "expected install.sh to write `export SSL_CERT_DIR=\"$HOME/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}\"` to /etc/profile.d/devcontainer-dev-certs.sh"
);
check(
  "install.sh appends SSL_CERT_DIR to /etc/environment with REMOTE_USER_HOME",
  installSh.includes(
    'append_env "SSL_CERT_DIR" "${SSL_CERT_DIR_RESOLVED}"'
  ) &&
    installSh.includes(
      'SSL_CERT_DIR_RESOLVED="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}"'
    ),
  "expected install.sh to compute SSL_CERT_DIR_RESOLVED from REMOTE_USER_HOME and append it via append_env"
);

// install.sh SSLCERTDIRS fallback should match the feature option default
const fallbackMatch = installSh.match(
  /SSL_CERT_DIRS="\$\{SSLCERTDIRS:-([^}]+)\}"/
);
check(
  "install.sh SSLCERTDIRS fallback matches feature option default",
  fallbackMatch && fallbackMatch[1] === defaultSslDirs,
  `install.sh fallback has "${fallbackMatch?.[1]}" but feature default is "${defaultSslDirs}"`
);

// --- Option names map to uppercased env vars in install.sh ---

console.log("\nFeature options referenced in install.sh:");
for (const [optName, _optDef] of Object.entries(feature.options ?? {})) {
  const envName = optName.toUpperCase();
  const referenced = installSh.includes(envName);
  check(
    `option "${optName}" (env: ${envName}) referenced in install.sh`,
    referenced,
    "not found in install.sh"
  );
}

// --- Summary ---

console.log();
if (failures > 0) {
  console.log(`FAILED: ${failures} check(s) failed.`);
  process.exit(1);
} else {
  console.log("All checks passed.");
}
