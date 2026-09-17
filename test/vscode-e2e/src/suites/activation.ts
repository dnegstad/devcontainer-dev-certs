/**
 * Plain activation assertions for both extensions.
 *
 * These are cheap and they replace a Node harness that had to stub
 * `require("vscode")` by hand to answer the same questions. Here the answers
 * come from a real extension host.
 *
 * On output channels: VS Code exposes no API to enumerate them, so "the
 * channel exists" cannot be asserted directly. What the activation assertion
 * *does* cover is that `initLogger(...)` — which calls
 * `vscode.window.createOutputChannel` and is the first statement of both
 * `activate()` functions — ran without throwing. A green `isActive` is
 * therefore a real signal about the channel, just an indirect one.
 */
import * as vscode from "vscode";
import { assert, assertEqual, test } from "../runner";
import { UI_EXTENSION_ID, WORKSPACE_EXTENSION_ID } from "../env";

/** Registered by the UI extension, which runs on the host. */
const UI_COMMANDS = [
  "devcontainer-dev-certs.getCertMaterial",
  "devcontainer-dev-certs.getAllCertMaterial",
  "devcontainer-dev-certs.getAllCertMaterialV3",
  "devcontainer-dev-certs.acceptContainerDevCert",
  "devcontainer-dev-certs.trustInBrowsers",
  "devcontainer-dev-certs.resetContainerCertConsent",
];

/**
 * Registered by the workspace extension — but only past the remote gate.
 * Their presence is what proves the `DEVCONTAINER_DEV_CERTS_TEST_REMOTE` seam
 * actually opened; without it `activate()` returns before registering these
 * and every one of them is missing.
 */
const WORKSPACE_COMMANDS = [
  "devcontainer-dev-certs.injectCert",
  "devcontainer-dev-certs.cleanupStaleDevCerts",
];

export async function activateBoth(): Promise<void> {
  for (const id of [UI_EXTENSION_ID, WORKSPACE_EXTENSION_ID]) {
    const ext = vscode.extensions.getExtension(id);
    if (!ext) throw new Error(`extension ${id} was not loaded`);
    await ext.activate();
  }
}

export function registerActivationTests(): void {
  test("both extensions are loaded into the same window", () => {
    for (const id of [UI_EXTENSION_ID, WORKSPACE_EXTENSION_ID]) {
      assert(
        vscode.extensions.getExtension(id) !== undefined,
        `extension ${id} should be loaded via --extensionDevelopmentPath`
      );
    }
  });

  test("activate() does not throw for either extension", async () => {
    await activateBoth();
    for (const id of [UI_EXTENSION_ID, WORKSPACE_EXTENSION_ID]) {
      assertEqual(
        vscode.extensions.getExtension(id)?.isActive,
        true,
        `${id} should be active after activate()`
      );
    }
  });

  test("UI extension registers its cross-host commands", async () => {
    await activateBoth();
    const registered = new Set(await vscode.commands.getCommands(true));
    for (const command of UI_COMMANDS) {
      assert(registered.has(command), `${command} should be registered`);
    }
  });

  test("workspace extension registers its commands past the remote gate", async () => {
    await activateBoth();
    const registered = new Set(await vscode.commands.getCommands(true));
    for (const command of WORKSPACE_COMMANDS) {
      assert(
        registered.has(command),
        `${command} should be registered — its absence means the remote gate ` +
          "closed and activate() returned early"
      );
    }
  });
}
