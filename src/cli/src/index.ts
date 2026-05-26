import "reflect-metadata";
import { Command, Option } from "commander";
import { runBundle } from "./commands/bundle";
import { runDoctor } from "./commands/doctor";
import { runGenerate } from "./commands/generate";
import { runInspect } from "./commands/inspect";
import { runTrust } from "./commands/trust";
import type { BackendMode } from "@devcontainer-dev-certs/shared";

const program = new Command();

program
  .name("ddc")
  .description(
    "Host-side dev-cert toolkit. Generates, inspects, trusts, and bundles " +
      "ASP.NET-compatible HTTPS dev certs for use with dev containers — without VS Code."
  );

program
  .command("generate")
  .description("Generate a dev cert, optionally trust it, and emit a bundle.json.")
  .option("-o, --out-dir <path>", "Directory to write artifacts to (default ~/.dev-certs).")
  .addOption(
    new Option("-b, --backend <mode>", "Backend selection.")
      .choices(["auto", "native", "dotnet", "aspire"])
      .default("auto")
  )
  .option("--no-trust", "Skip the host trust step (PFX / PEM are still emitted).")
  .option(
    "--container-mount <path>",
    "Container-side mount target for the out-dir, recorded into bundle.json.",
    "/host-dev-certs"
  )
  .option("--no-bundle", "Skip emitting bundle.json.")
  .option("-v, --verbose", "Stream shared-layer log lines to stderr.")
  .action(
    async (opts: {
      outDir?: string;
      backend: BackendMode;
      trust: boolean;
      containerMount: string;
      bundle: boolean;
      verbose?: boolean;
    }) => {
      await runGenerate({
        outDir: opts.outDir,
        backend: opts.backend,
        // commander inverts `--no-trust` into `opts.trust = false`.
        noTrust: !opts.trust,
        containerMount: opts.containerMount,
        noBundle: !opts.bundle,
        verbose: opts.verbose,
      });
    }
  );

program
  .command("inspect <cert-path>")
  .description("Print details about a PFX or PEM certificate.")
  .option("--json", "Emit machine-readable JSON instead of human-readable text.")
  .action(async (certPath: string, opts: { json?: boolean }) => {
    await runInspect(certPath, { json: opts.json });
  });

program
  .command("bundle <cert-path>")
  .description("Emit a bundle.json referencing an already-existing cert file.")
  .option(
    "-o, --out-dir <path>",
    "Directory to write bundle.json to (default: directory of cert-path)."
  )
  .option(
    "--container-mount <path>",
    "Container-side mount target for the out-dir.",
    "/host-dev-certs"
  )
  .option(
    "--name <stem>",
    "Filename stem to use in bundle.json (default: cert-path's basename without extension)."
  )
  .addOption(
    new Option("--kind <kind>", "Bundle entry kind.")
      .choices(["dotnet-dev", "user"])
      .default("user")
  )
  .option(
    "--no-trust-in-container",
    "Mark trustInContainer=false (cert is served only, not added to trust stores)."
  )
  .action(
    async (
      certPath: string,
      opts: {
        outDir?: string;
        containerMount: string;
        name?: string;
        kind: "dotnet-dev" | "user";
        trustInContainer: boolean;
      }
    ) => {
      await runBundle(certPath, {
        outDir: opts.outDir,
        containerMount: opts.containerMount,
        name: opts.name,
        kind: opts.kind,
        noTrustInContainer: !opts.trustInContainer,
      });
    }
  );

program
  .command("trust <cert-path>")
  .description("Add an existing PFX or PEM cert to the host's OS trust store.")
  .option("-v, --verbose", "Stream shared-layer log lines to stderr.")
  .action(async (certPath: string, opts: { verbose?: boolean }) => {
    await runTrust(certPath, { verbose: opts.verbose });
  });

program
  .command("doctor")
  .description("Read-only diagnostics: backend availability + host trust state.")
  .option("-o, --out-dir <path>", "Out-dir to inspect (default ~/.dev-certs).")
  .option("-v, --verbose", "Stream shared-layer log lines to stderr.")
  .action(async (opts: { outDir?: string; verbose?: boolean }) => {
    await runDoctor({ outDir: opts.outDir, verbose: opts.verbose });
  });

// Run.
program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`ddc: ${message}\n`);
  process.exit(1);
});
