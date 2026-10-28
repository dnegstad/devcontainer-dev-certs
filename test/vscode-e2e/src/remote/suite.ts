/**
 * The devcontainer level: the same user-cert vertical slice as
 * `../suites/certFlow.ts`, but with the workspace extension and this suite
 * running in a real remote extension host inside a container built from the
 * feature in this checkout, and the UI extension in the local window.
 *
 * What this closes relative to the local level:
 *   - The host↔remote hop is real. `getAllCertMaterialV3` crosses VS Code's
 *     RPC, so the payload is genuinely serialized; `wireGuard.ts` is a
 *     stand-in for this, not a substitute.
 *   - The remote gate opens on a real `vscode.env.remoteName`, not the
 *     DEVCONTAINER_DEV_CERTS_TEST_REMOTE seam.
 *   - The feature's `install.sh` ran for real, and its environment sinks have
 *     to reach the extension host the way they would for a user.
 *   - The install lands in the container user's real `$HOME`, under the
 *     container's real users and permissions — no sandbox redirect.
 *
 * What it still does not cover: the Dev Containers extension itself (the
 * launcher starts the VS Code server with `devcontainer exec`, which applies
 * the same userEnvProbe but is not the same code), and the dotnet dev-cert /
 * reverse-sync paths, which write the host's real OS trust store.
 */
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import {
  getDotNetRootStorePath,
  getPemFileNameForUser,
  getPfxFileName,
} from "@devcontainer-dev-certs/shared";
import type { CertBundleV3, CertMaterialV3 } from "@devcontainer-dev-certs/shared";
import { assert, assertEqual, test } from "../runner";
import { WORKSPACE_EXTENSION_ID } from "../env";
import { pemBody } from "../suites/certFlow";

const AUTHORITY = "devcerts-e2e";
const TRUST_DIR = path.join(os.homedir(), ".aspnet", "dev-certs", "trust");

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is not set. The devcontainer suite must be launched via ` +
        "test/vscode-e2e/runDevcontainer.mjs, which passes it to the VS Code " +
        "server with `devcontainer exec --remote-env`."
    );
  }
  return value;
}

async function fetchBundle(): Promise<CertBundleV3> {
  const bundle = await vscode.commands.executeCommand<CertBundleV3>(
    "devcontainer-dev-certs.getAllCertMaterialV3",
    { includeDotNetDev: false, includeUserCerts: true }
  );
  assert(bundle !== undefined && bundle !== null, "host returned no bundle");
  return bundle;
}

function userCert(bundle: CertBundleV3, name: string): CertMaterialV3 {
  const material = bundle.certs.find((c) => c.name === name);
  assert(
    material !== undefined,
    `bundle should carry the configured user cert '${name}' ` +
      `(got: ${bundle.certs.map((c) => c.name).join(", ") || "nothing"})`
  );
  return material;
}

export function registerDevcontainerTests(): void {
  const userCertName = required("DEVCERTS_E2E_USER_CERT_NAME");
  // The host-side fixture, staged into the container by the launcher.
  const expectedPemPath = required("DEVCERTS_E2E_EXPECTED_PEM");

  test("this extension host is a real remote, not the test seam", () => {
    assertEqual(vscode.env.remoteName, AUTHORITY, "vscode.env.remoteName");
    assertEqual(
      process.env.DEVCONTAINER_DEV_CERTS_TEST_REMOTE,
      undefined,
      "the seam variable must not be set at this level, or a green run " +
        "would prove nothing about the real gate"
    );
    assertEqual(process.platform, "linux", "the remote should be the container");
  });

  test("workspace extension runs here and passes the real remote gate", async () => {
    const ext = vscode.extensions.getExtension(WORKSPACE_EXTENSION_ID);
    assert(ext !== undefined, `${WORKSPACE_EXTENSION_ID} should load in the remote host`);
    assertEqual(
      ext.extensionKind,
      vscode.ExtensionKind.Workspace,
      "workspace extension should run in the remote extension host"
    );
    await ext.activate();
    const registered = new Set(await vscode.commands.getCommands(true));
    assert(
      registered.has("devcontainer-dev-certs.injectCert"),
      "injectCert should be registered — its absence means the remote gate closed"
    );
  });

  test("the feature's environment reaches the extension host", () => {
    // install.sh writes SSL_CERT_DIR to profile.d / /etc/environment / the
    // bashrc bridge. None of that is visible to a process unless whatever
    // launched it went through a shell that read one of them — which is the
    // property this asserts, end to end.
    const sslCertDir = process.env.SSL_CERT_DIR ?? "";
    assert(
      sslCertDir.split(":").includes(TRUST_DIR),
      `SSL_CERT_DIR should include ${TRUST_DIR} (got: '${sslCertDir}')`
    );
    assertEqual(
      process.env.DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET,
      "true",
      "feature options should be exported to the extension host"
    );
  });

  test("user cert crosses the real host↔remote RPC intact", async () => {
    const material = userCert(await fetchBundle(), userCertName);
    assertEqual(material.kind, "user", "cert kind");
    assertEqual(
      pemBody(Buffer.from(material.pemCertBase64, "base64").toString("utf-8")),
      pemBody(fs.readFileSync(expectedPemPath, "utf-8")),
      "the certificate on the wire should be the one configured on the host"
    );
  });

  test("injectCert installs into the container and OpenSSL trusts it", async () => {
    const material = userCert(await fetchBundle(), userCertName);

    await vscode.commands.executeCommand("devcontainer-dev-certs.injectCert");

    const pemPath = path.join(TRUST_DIR, getPemFileNameForUser(userCertName));
    assert(fs.existsSync(pemPath), `${pemPath} should exist after inject`);

    const rootPfx = path.join(
      getDotNetRootStorePath(),
      getPfxFileName(material.thumbprint)
    );
    assert(fs.existsSync(rootPfx), `${rootPfx} should exist`);

    // The real consumer check. No -CApath: openssl falls back to its default
    // lookup, which reads SSL_CERT_DIR from the environment — the one this
    // extension host inherited from the feature. So this passes only if
    // install.sh's sinks, the extension's install, and the pure-TS c_rehash
    // all line up inside a real container.
    const verify = spawnSync("openssl", ["verify", pemPath], {
      encoding: "utf-8",
      env: process.env,
    });
    assertEqual(
      verify.status,
      0,
      `openssl verify via SSL_CERT_DIR should succeed\n${verify.stdout}${verify.stderr}`
    );
  });
}
