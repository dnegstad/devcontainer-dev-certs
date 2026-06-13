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
  .name("dcdc")
  .description(
    "Host-side dev-cert toolkit. Generates, inspects, trusts, and bundles " +
      "ASP.NET-compatible HTTPS dev certs for use with dev containers — without " +
      "VS Code.\n\n" +
      "Typical workflows:\n" +
      "  dcdc generate                  Ensure the host dev cert exists and is\n" +
      "                                 trusted; emit files + bundle.json.\n" +
      "  dcdc inspect ./cert.pfx        Read a cert file (subject, thumbprint,\n" +
      "                                 SANs, validity).\n" +
      "  dcdc bundle  ./cert.pfx        Wrap an existing cert file in a\n" +
      "                                 bundle.json for the in-container installer.\n" +
      "  dcdc trust   ./cert.pem        Add an existing cert to the host's OS\n" +
      "                                 trust store ONLY (does not import to the\n" +
      "                                 .NET dev cert store — see notes below).\n" +
      "  dcdc doctor                    Read-only diagnostics.\n\n" +
      "Mapping to `dotnet dev-certs https` (for reference):\n" +
      "  dotnet dev-certs https --trust                ≈ dcdc generate\n" +
      "  dotnet dev-certs https                        ≈ dcdc generate --no-trust\n" +
      "  dotnet dev-certs https --check                ≈ dcdc doctor\n" +
      "  dotnet dev-certs https --import F --trust     no exact equivalent — `dcdc\n" +
      "                                                trust F` does the OS trust\n" +
      "                                                step only, NOT the .NET store\n" +
      "                                                import. Use the dotnet CLI\n" +
      "                                                directly if you need both.\n" +
      "  dotnet dev-certs https --export-path F        ≈ dcdc generate --out-dir <dir>\n" +
      "                                                  --no-trust"
  );

program
  .command("generate")
  .description(
    "Ensure the host dev cert exists and is trusted, then write its files " +
      "(PFX/PEM/key) + bundle.json. Reuses an existing trusted cert in the host " +
      "platform store when one is present (no re-prompt, no fresh key generation). " +
      "Roughly equivalent to `dotnet dev-certs https --trust` plus our bundle.json " +
      "write."
  )
  .option("-o, --out-dir <path>", "Directory to write artifacts to (default ~/.dev-certs).")
  .addOption(
    new Option("-b, --backend <mode>", "Backend selection.")
      .choices(["auto", "native", "dotnet"])
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
  .description(
    "Print details about a PFX or PEM certificate (subject CN, thumbprints, " +
      "validity, SANs, dev-cert OID + version byte, warnings). Read-only — " +
      "doesn't touch the platform store, doesn't add trust."
  )
  .option("--json", "Emit machine-readable JSON instead of human-readable text.")
  .action(async (certPath: string, opts: { json?: boolean }) => {
    await runInspect(certPath, { json: opts.json });
  });

program
  .command("bundle <cert-path>")
  .description(
    "Wrap an already-existing cert file in a bundle.json that the in-container " +
      "installer reads. Auto-discovers sibling `.pem` / `.key` / `.pfx` files by " +
      "naming convention. Doesn't touch the cert or the platform store — only " +
      "emits the JSON manifest."
  )
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
  .description(
    "Add an existing PFX or PEM cert to the host's OS trust store (macOS " +
      "keychain / Windows CurrentUser\\Root / Linux OpenSSL trust dir + NSS DBs). " +
      "ONLY adds trust — does NOT register the cert as the host .NET dev cert " +
      "(that's what `dotnet dev-certs --import` does; if you need both, run the " +
      "dotnet CLI). Short-circuits if the cert is already trusted."
  )
  .option("-v, --verbose", "Stream shared-layer log lines to stderr.")
  .action(async (certPath: string, opts: { verbose?: boolean }) => {
    await runTrust(certPath, { verbose: opts.verbose });
  });

program
  .command("doctor")
  .description(
    "Read-only diagnostics: which backends are available (and which `--backend " +
      "auto` would pick), out-dir / bundle.json presence, host platform-store " +
      "cert state (present? trusted? thumbprint?), and per-OS tool presence " +
      "(openssl/certutil on Linux, security on macOS, pwsh/powershell + " +
      "certutil.exe on Windows). Doesn't modify anything."
  )
  .option("-o, --out-dir <path>", "Out-dir to inspect (default ~/.dev-certs).")
  .option("-v, --verbose", "Stream shared-layer log lines to stderr.")
  .action(async (opts: { outDir?: string; verbose?: boolean }) => {
    await runDoctor({ outDir: opts.outDir, verbose: opts.verbose });
  });

// Run.
program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`dcdc: ${message}\n`);
  process.exit(1);
});
