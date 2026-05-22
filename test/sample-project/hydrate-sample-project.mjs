#!/usr/bin/env node
// Hydrates the sample-project test template into a runnable project.
//
// Usage: npm run hydrate:sample-project   (from repo root)
//
// Output: <repo-root>/.out/test-project/
//   - Copies test/sample-project/ as the base (excluding this script)
//   - Copies the devcontainer feature into .devcontainer/devcontainer-dev-certs/
//
// The "stage-test-vsix" VSCode task handles building and placing
// the VSIX directly into the hydrated .devcontainer/ folder.
//
// This can be invoked from:
//   - VSCode tasks (F5 flow)
//   - CLI for manual testing
//   - CI for automated testing

import { cpSync, rmSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join, resolve, dirname } from "path";
import { fileURLToPath } from "url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..");
const featureDir = join(repoRoot, "src", "devcontainer-feature", "src", "devcontainer-dev-certs");
const outDir = join(repoRoot, ".out", "test-project");

// Clean and recreate output
try {
  rmSync(outDir, { recursive: true, force: true });
} catch {
  console.warn(`Warning: Could not fully clean ${outDir} — files may be locked. Overwriting in place.`);
}
mkdirSync(outDir, { recursive: true });

// Copy template (this directory), excluding this script itself
cpSync(scriptDir, outDir, {
  recursive: true,
  filter: (src) => !src.endsWith("hydrate-sample-project.mjs"),
});

// Copy feature into .devcontainer/
const stagedFeatureDir = join(outDir, ".devcontainer", "devcontainer-dev-certs");
cpSync(featureDir, stagedFeatureDir, { recursive: true });

// Strip the marketplace-pinned dev-cert extension IDs from the staged
// feature so the local VSIX (workspace) and Extension Development Host
// (UI) aren't shadowed by the published stable versions.
const featureManifestPath = join(stagedFeatureDir, "devcontainer-feature.json");
const featureManifest = JSON.parse(readFileSync(featureManifestPath, "utf-8"));
const vscodeCustomizations = featureManifest.customizations?.vscode;
if (Array.isArray(vscodeCustomizations?.extensions)) {
  vscodeCustomizations.extensions = vscodeCustomizations.extensions.filter(
    (id) => !id.startsWith("dnegstad.devcontainer-dev-certs-")
  );
  if (vscodeCustomizations.extensions.length === 0) {
    delete vscodeCustomizations.extensions;
  }
}
writeFileSync(
  featureManifestPath,
  JSON.stringify(featureManifest, null, 2) + "\n"
);

console.log(`Test project hydrated at: ${outDir}`);
