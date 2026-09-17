#!/usr/bin/env node
/**
 * Fast smoke check: can the extension host actually `require()` the built
 * suite bundle?
 *
 * This exists because it already caught a real failure. The suite bundles the
 * shared package, which pulls in @peculiar/x509 -> tsyringe, and tsyringe
 * binds its @injectable decorators to `Reflect.metadata` at module-init time.
 * A missing `import "reflect-metadata"` in the entry point throws while VS
 * Code is requiring --extensionTestsPath — before a single test runs — and the
 * only way to find out was a full CI job: npm ci, two extension builds, a
 * ~110MB VS Code download, an Electron launch. Roughly two minutes to learn
 * something reproducible in 200ms.
 *
 * So: stub `vscode` (the one module the host injects and node_modules can't
 * resolve) and require the bundle. Module-level initialization is exactly what
 * this class of bug happens in, and it needs no VS Code at all.
 *
 * Deliberately NOT a substitute for the real run — it proves the bundle loads,
 * not that anything works. Run it first because it's ~200ms and turns the
 * cheapest failure into the earliest one.
 *
 *   node test/vscode-e2e/loadCheck.cjs     (or: npm run check:e2e-load)
 */
const Module = require("node:module");
const path = require("node:path");
const fs = require("node:fs");

const BUNDLE = path.resolve(__dirname, "..", "..", ".out", "vscode-e2e", "suite.cjs");

if (!fs.existsSync(BUNDLE)) {
  console.error(`Suite bundle is missing (${BUNDLE}). Run: npm run build:e2e`);
  process.exit(1);
}

/**
 * Minimal `vscode` stand-in. Only needs to satisfy module-level evaluation —
 * every real API call happens inside a test function, which never runs here.
 */
const vscodeStub = {
  extensions: { getExtension: () => undefined },
  commands: {
    getCommands: () => Promise.resolve([]),
    executeCommand: () => Promise.resolve(undefined),
    registerCommand: () => ({ dispose() {} }),
  },
  window: {
    createOutputChannel: () => ({ appendLine() {}, show() {}, dispose() {} }),
    showInformationMessage: () => Promise.resolve(undefined),
    showWarningMessage: () => Promise.resolve(undefined),
    showErrorMessage: () => Promise.resolve(undefined),
  },
  workspace: {
    getConfiguration: () => ({ get: (_key, fallback) => fallback, inspect: () => undefined }),
  },
  env: { remoteName: undefined },
  ExtensionMode: { Production: 1, Development: 2, Test: 3 },
  ConfigurationTarget: { Global: 1, Workspace: 2, WorkspaceFolder: 3 },
  l10n: { t: (message) => message },
  debug: { registerDebugConfigurationProvider: () => ({ dispose() {} }) },
};

const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === "vscode") return "vscode";
  return originalResolve.call(this, request, ...rest);
};
require.cache["vscode"] = {
  id: "vscode",
  filename: "vscode",
  loaded: true,
  exports: vscodeStub,
};

try {
  const suite = require(BUNDLE);
  if (typeof suite.run !== "function") {
    console.error(
      "Suite bundle loaded but does not export run(). VS Code's " +
        "--extensionTestsPath contract requires it."
    );
    process.exit(1);
  }
  console.log("E2E suite bundle loads cleanly and exports run().");
} catch (err) {
  console.error("Suite bundle threw during module initialization:");
  console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
  console.error(
    "\nThis would fail identically inside the extension host, after the " +
      "VS Code download. Fix it here."
  );
  process.exit(1);
}
