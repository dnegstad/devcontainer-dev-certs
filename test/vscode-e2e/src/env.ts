/**
 * The contract between `runTests.mjs` (which builds the sandbox and launches
 * VS Code) and the suites (which run inside the extension host and have to
 * find that sandbox again).
 */

export const UI_EXTENSION_ID = "dnegstad.devcontainer-dev-certs-host";
export const WORKSPACE_EXTENSION_ID = "dnegstad.devcontainer-dev-certs-remote";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is not set. The suite must be launched via test/vscode-e2e/runTests.mjs, ` +
        "which builds the sandbox and passes it down through extensionTestsEnv."
    );
  }
  return value;
}

export interface Sandbox {
  /** Fake HOME. Everything the workspace extension installs lands under here. */
  home: string;
  /** `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY` for this run. */
  trustDir: string;
  /** `devcontainerDevCerts.userCertificates[0].name`. */
  userCertName: string;
  /** Host-side source PEM the user cert entry points at. */
  userCertPemPath: string;
}

export function sandbox(): Sandbox {
  return {
    home: required("DEVCERTS_E2E_HOME"),
    trustDir: required("DEVCERTS_E2E_TRUST_DIR"),
    userCertName: required("DEVCERTS_E2E_USER_CERT_NAME"),
    userCertPemPath: required("DEVCERTS_E2E_USER_CERT_PEM"),
  };
}
