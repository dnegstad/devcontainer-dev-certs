import * as os from "os";
import * as path from "path";
import {
  selectBackend,
  type BackendMode,
} from "@devcontainer-dev-certs/shared";
import { writeBundle, type BundleCertEntry } from "../bundle/writer";
import { installCliLogger } from "../logger";
import { stderrNssTrustReporter } from "../nssReporter";

export interface GenerateCommandOptions {
  outDir?: string;
  backend?: BackendMode;
  noTrust?: boolean;
  containerMount?: string;
  noBundle?: boolean;
  verbose?: boolean;
}

const DEFAULT_OUT_DIR = path.join(os.homedir(), ".dev-certs");
const DEFAULT_CONTAINER_MOUNT = "/host-dev-certs";

/**
 * `dcdc generate` — produce a fresh dev cert + bundle.json. Picks a backend
 * (native by default, dotnet pass-through on macOS when available, with
 * `--backend` to override) and runs the host trust step unless `--no-trust`
 * is passed.
 */
export async function runGenerate(
  options: GenerateCommandOptions
): Promise<void> {
  installCliLogger(Boolean(options.verbose));

  const outDir = path.resolve(options.outDir ?? DEFAULT_OUT_DIR);
  const backend = await selectBackend(options.backend ?? "auto");
  const containerMount = options.containerMount ?? DEFAULT_CONTAINER_MOUNT;
  const noTrust = Boolean(options.noTrust);

  process.stderr.write(`Backend: ${backend.kind}\n`);
  process.stderr.write(`Out dir: ${outDir}\n`);

  const result = await backend.generate({
    outDir,
    noTrust,
    // Surface NSS trust outcomes (Linux only) on stderr so the user
    // isn't left thinking browser trust succeeded when it silently
    // didn't. No-op on macOS / Windows.
    linuxNssTrustReporter: stderrNssTrustReporter,
  });

  process.stderr.write(
    `Thumbprint: ${result.thumbprint}\n` +
      `PFX: ${result.pfxPath}\n` +
      `PEM: ${result.pemPath}\n` +
      (result.pemKeyPath ? `Key: ${result.pemKeyPath}\n` : "") +
      `Trusted on host: ${result.trusted ? "yes" : "no (skipped via --no-trust)"}\n`
  );

  if (!options.noBundle) {
    const entry: BundleCertEntry = {
      name: "aspnetcore-dev",
      kind: "dotnet-dev",
      thumbprint: result.thumbprint,
      hostPfxPath: result.pfxPath,
      hostPemPath: result.pemPath,
      hostPemKeyPath: result.pemKeyPath,
      // Mirror the host-trust opt-out: if the user passed `--no-trust`,
      // they want files-only on both sides of the host/container
      // boundary. Forcing `trustInContainer: true` here would honor the
      // host opt-out and silently reverse it inside the container — an
      // asymmetry that bites anyone who commits the bundle to a repo.
      trustInContainer: !noTrust,
    };
    const bundlePath = writeBundle({
      hostOutDir: outDir,
      containerMount,
      entries: [entry],
    });
    process.stderr.write(`Bundle: ${bundlePath}\n`);
  }
}
