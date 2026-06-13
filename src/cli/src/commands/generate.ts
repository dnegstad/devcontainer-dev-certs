import * as path from "path";
import {
  createPlatformStore,
  selectBackend,
  type BackendMode,
} from "@devcontainer-dev-certs/shared";
import { writeBundle, type BundleCertEntry } from "../bundle/writer";
import { DEFAULT_CONTAINER_MOUNT, DEFAULT_OUT_DIR } from "../defaults";
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

/**
 * `dcdc generate` — ensure a dev cert exists on the host and emit its
 * artifacts + a `bundle.json` for the in-container installer. If the
 * host platform store already has a valid trusted dev cert, the backend
 * reuses it (no fresh generation, no re-trust prompt) and we say so on
 * stderr so the user knows what happened. With `--no-trust`, the native
 * backend bypasses the platform store entirely and always produces a
 * fresh in-memory cert.
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

  // Snapshot the platform store BEFORE the backend runs so we can
  // tell the user whether the backend reused an existing cert or
  // generated a fresh one. Best-effort: if the store check throws
  // (corrupt state, permission issue), we skip the diagnostic rather
  // than fail the generate. Skipped entirely for `--no-trust` since
  // the native backend doesn't touch the store on that path.
  const preExistingThumbprint = noTrust
    ? null
    : await safelyReadStoreThumbprint();

  const result = await backend.generate({
    outDir,
    noTrust,
    // Surface NSS trust outcomes (Linux only) on stderr so the user
    // isn't left thinking browser trust succeeded when it silently
    // didn't. No-op on macOS / Windows.
    linuxNssTrustReporter: stderrNssTrustReporter,
  });

  const reused =
    preExistingThumbprint !== null &&
    preExistingThumbprint === result.thumbprint;

  process.stderr.write(
    `Cert source: ${certSourceLabel(reused, noTrust)}\n` +
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

async function safelyReadStoreThumbprint(): Promise<string | null> {
  try {
    const store = await createPlatformStore();
    const status = await store.checkStatus();
    return status.exists ? status.thumbprint : null;
  } catch {
    // Store reads aren't load-bearing for the generate flow — we're
    // only using them to decorate the output. Don't block.
    return null;
  }
}

function certSourceLabel(reused: boolean, noTrust: boolean): string {
  if (reused) {
    return "reused (existing trusted cert already in the host platform store)";
  }
  if (noTrust) {
    return "newly generated (in memory; --no-trust skips platform-store write)";
  }
  return "newly generated (added to the host platform store)";
}
