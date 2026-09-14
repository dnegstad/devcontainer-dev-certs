import * as esbuild from "esbuild";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");

// CJS, because VS Code `require()`s the --extensionTestsPath module in the
// extension host. `vscode` stays external for the same reason it does in the
// extensions' own bundles: it's injected by the host, not resolvable from
// node_modules. Everything else — including the shared package, which is
// published as TypeScript source — is bundled in, so the suite is a single
// self-contained file with no resolution surprises at runtime.
await esbuild.build({
  entryPoints: [resolve(here, "src", "index.ts")],
  bundle: true,
  outfile: resolve(repoRoot, ".out", "vscode-e2e", "suite.cjs"),
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node20",
  sourcemap: true,
  logLevel: "info",
});
