import * as esbuild from "esbuild";

const production = process.argv.includes("--production");

await esbuild.build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  outfile: "dist/dcdc.js",
  // `vscode` is a build-time stub used only by the shared package's
  // `loggerVscode.ts` helper, which the CLI never imports. Marking it
  // external prevents esbuild from trying to resolve a module that
  // doesn't exist outside the VS Code extension host.
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node18",
  sourcemap: !production,
  minify: production,
  banner: {
    js: "#!/usr/bin/env node\n",
  },
});
