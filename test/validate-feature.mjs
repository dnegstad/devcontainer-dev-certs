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
// The profile.d write is sourced by every login shell, so the user-supplied
// SSL_CERT_DIRS must be embedded in a form that's inert under bash expansion
// (no $(...), no backticks, no $VAR substitution). Assert the secure shape:
//   1. SSL_CERT_DIRS_SQ is built via `shell_single_quote "${SSL_CERT_DIRS}"`.
//   2. The profile.d line concatenates a double-quoted segment carrying
//      "$HOME/.aspnet/dev-certs/trust:" with that single-quoted segment, so
//      $HOME expands per-user at login while the user value stays literal.
check(
  "install.sh writes SSL_CERT_DIR to /etc/profile.d/devcontainer-dev-certs.sh",
  installSh.includes("/etc/profile.d/devcontainer-dev-certs.sh"),
  "expected install.sh to reference /etc/profile.d/devcontainer-dev-certs.sh"
);
check(
  "install.sh builds SSL_CERT_DIRS_SQ via shell_single_quote (defense-in-depth)",
  installSh.includes(
    'SSL_CERT_DIRS_SQ="$(shell_single_quote "${SSL_CERT_DIRS}")"'
  ),
  "expected install.sh to wrap ${SSL_CERT_DIRS} via shell_single_quote so $(...) / backticks / $VAR in a malicious feature option can't execute when the profile.d file is sourced"
);
check(
  "install.sh emits the SSL_CERT_DIR profile.d line in the secure concatenated shape",
  installSh.includes(
    'echo "export SSL_CERT_DIR=\\"\\$HOME/.aspnet/dev-certs/trust:\\"${SSL_CERT_DIRS_SQ}"'
  ),
  "expected install.sh to emit `export SSL_CERT_DIR=\"$HOME/.aspnet/dev-certs/trust:\"${SSL_CERT_DIRS_SQ}` (double-quoted $HOME segment + single-quoted user portion)"
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

// --- profile.d writes must go through the secure helpers ---
//
// Every value the user can set in devcontainer.json eventually lands in
// /etc/profile.d/devcontainer-dev-certs.sh, which is sourced by every login
// shell. If any of those writes drops back to a raw `echo "export X=\"$VAL\""`
// double-quoted form, a malicious feature-option value containing `$(...)` /
// backticks / `$VAR` will execute at login. The two safe paths are:
//   - `append_profile "KEY" "${VALUE}"` — wraps VALUE in single quotes via
//     shell_single_quote.
//   - The inline SSL_CERT_DIR line, which uses `${SSL_CERT_DIRS_SQ}`
//     (already independently checked above).
// Anything else gets flagged here.
console.log("\nprofile.d writes route through shell_single_quote:");
const PROFILE_OPTIONS = [
  "GENERATE_DOTNET_CERT",
  "SYNC_USER_CERTIFICATES",
  "SYNC_CONTAINER_CERT",
  "EXTRA_CERT_DESTINATIONS",
];
for (const envName of PROFILE_OPTIONS) {
  const usesAppendProfile = installSh.includes(
    `append_profile "DEVCONTAINER_DEV_CERTS_${
      envName === "GENERATE_DOTNET_CERT"
        ? "GENERATE_DOTNET"
        : envName === "SYNC_USER_CERTIFICATES"
          ? "SYNC_USER"
          : envName === "SYNC_CONTAINER_CERT"
            ? "SYNC_FROM_CONTAINER"
            : "EXTRA_DESTINATIONS"
    }" "\${${envName}}"`
  );
  check(
    `${envName} is written via append_profile (not raw echo)`,
    usesAppendProfile,
    `expected an \`append_profile "DEVCONTAINER_DEV_CERTS_..." "\${${envName}}"\` call; without it a feature option containing \`$(rm -rf /)\` would execute at login`
  );
}
check(
  "install.sh defines shell_single_quote (used by append_profile + SSL_CERT_DIR)",
  /shell_single_quote\s*\(\s*\)\s*\{/.test(installSh),
  "expected a `shell_single_quote()` helper that single-quote-wraps untrusted values for safe embedding in /etc/profile.d/*.sh"
);
check(
  "append_profile delegates to shell_single_quote",
  /append_profile\s*\(\s*\)\s*\{[\s\S]*?shell_single_quote/.test(installSh),
  "expected append_profile to route the value through shell_single_quote — double-quoted emission would re-introduce the command-injection risk"
);

// --- DOTNET_GENERATE_ASPNET_CERTIFICATE suppression (gated) ---
//
// dotnet auto-generates an HTTPS dev cert on first `dotnet run` /
// `dotnet new webapi` / `dotnet build` of an HTTPS-enabled project. When
// the HOST is the dev cert source (default: generateDotNetCert=true,
// syncContainerCert=false), that implicit auto-gen races our workspace
// install of the host-generated cert — leaving a partially-trusted cert
// combo. install.sh suppresses the auto-gen by writing
// DOTNET_GENERATE_ASPNET_CERTIFICATE=false, but ONLY when the host is
// the source: when syncContainerCert is on, the container's own pipeline
// (possibly dotnet's auto-gen itself) is the source and suppressing it
// would break the source.
console.log("\nDOTNET_GENERATE_ASPNET_CERTIFICATE suppression (gated):");
check(
  "install.sh writes DOTNET_GENERATE_ASPNET_CERTIFICATE=false to /etc/profile.d when host-source conditions hold",
  installSh.includes(
    'append_profile "DOTNET_GENERATE_ASPNET_CERTIFICATE" "false"'
  ),
  "expected an `append_profile \"DOTNET_GENERATE_ASPNET_CERTIFICATE\" \"false\"` call — without it, dotnet's first-run implicit cert generation races our host-managed install"
);
check(
  "install.sh writes DOTNET_GENERATE_ASPNET_CERTIFICATE=false to /etc/environment when host-source conditions hold",
  installSh.includes(
    'append_env "DOTNET_GENERATE_ASPNET_CERTIFICATE" "false"'
  ),
  "expected an `append_env \"DOTNET_GENERATE_ASPNET_CERTIFICATE\" \"false\"` call — PAM-based sessions (sshd, console) need the same suppression as the login-shell path"
);
check(
  "install.sh gates the DOTNET_GENERATE_ASPNET_CERTIFICATE writes on SYNC_CONTAINER_CERT != true AND GENERATE_DOTNET_CERT = true",
  /SUPPRESS_DOTNET_AUTOGEN="false"\s*\nif \[ "\$\{SYNC_CONTAINER_CERT\}" != "true" \] && \[ "\$\{GENERATE_DOTNET_CERT\}" = "true" \]; then\s*\n\s*SUPPRESS_DOTNET_AUTOGEN="true"\s*\n\s*append_profile "DOTNET_GENERATE_ASPNET_CERTIFICATE" "false"/.test(
    installSh
  ),
  "expected the profile.d write to be guarded by a conditional that flips SUPPRESS_DOTNET_AUTOGEN to true only when the host is the dev cert source (syncContainerCert != true && generateDotNetCert = true)"
);
check(
  "install.sh's /etc/environment write reuses the SUPPRESS_DOTNET_AUTOGEN gate",
  /if \[ "\$\{SUPPRESS_DOTNET_AUTOGEN\}" = "true" \]; then\s*\n\s*append_env "DOTNET_GENERATE_ASPNET_CERTIFICATE" "false"/.test(
    installSh
  ),
  "expected the /etc/environment write to be guarded by the same SUPPRESS_DOTNET_AUTOGEN flag so both sinks stay in lockstep"
);

// --- Summary ---

console.log();
if (failures > 0) {
  console.log(`FAILED: ${failures} check(s) failed.`);
  process.exit(1);
} else {
  console.log("All checks passed.");
}
