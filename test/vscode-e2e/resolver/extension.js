// Test-only remote authority resolver for the devcontainer E2E level.
//
// It does exactly one thing: tell VS Code that the `devcerts-e2e` authority
// lives at the VS Code server `runDevcontainer.mjs` started inside the dev
// container. Everything after that is stock VS Code: the server runs the
// workspace extension and the suite in a REAL remote extension host, so
// `vscode.env.remoteName` is set for real (no DEVCONTAINER_DEV_CERTS_TEST_REMOTE
// seam), and every cross-host executeCommand payload is genuinely serialized
// over VS Code's RPC rather than passed by reference.
//
// `registerRemoteAuthorityResolver` is a proposed API (`resolvers`). It is
// unlocked by `enabledApiProposals` in package.json plus
// `--enable-proposed-api dnegstad.devcerts-e2e-resolver` on the command line,
// which the launcher passes. Proposed APIs can change between VS Code
// releases; if this file breaks on a new stable, compare against
// src/vscode-dts/vscode.proposed.resolvers.d.ts in microsoft/vscode.
//
// Plain JS on purpose: there is nothing here worth a build step, and the
// proposed .d.ts isn't in @types/vscode.
"use strict";
const vscode = require("vscode");

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is not set; this resolver only works under test/vscode-e2e/runDevcontainer.mjs`
    );
  }
  return value;
}

exports.activate = function activate(context) {
  context.subscriptions.push(
    vscode.workspace.registerRemoteAuthorityResolver("devcerts-e2e", {
      resolve(_authority) {
        const host = required("DEVCERTS_E2E_SERVER_HOST");
        const port = Number(required("DEVCERTS_E2E_SERVER_PORT"));
        const token = required("DEVCERTS_E2E_SERVER_TOKEN");
        return new vscode.ResolvedAuthority(host, port, token);
      },
    })
  );
};

exports.deactivate = function deactivate() {};
