import * as fs from "fs";
import * as path from "path";
import { exportPem, exportPfx } from "../cert/exporter";
import { getOpenSslTrustDir, getPemFileName } from "../paths";
import { trustInNss } from "../platform/nssTrust";
import { runProcess } from "../platform/processUtil";
import {
  createPlatformStore,
  type LinuxNssTrustReporter,
} from "../platform/types";
import type { Backend, GenerateOptions, GenerateResult } from "./types";

/**
 * Dotnet backend: shells out to `dotnet dev-certs https` for the
 * generate-and-trust step on macOS — where the dotnet binary is
 * Apple-notarized and produces a cleaner keychain prompt than our
 * `security add-trusted-cert` invocation does — and then re-exports
 * the resulting cert from the platform store using our own primitives.
 *
 * Why we don't use dotnet's `--export-path`:
 *
 * - `--no-password` is PEM-only in every currently-shipping .NET SDK
 *   (6/7/8/9). PFX export requires a password, which we'd then have
 *   to strip locally to match our passwordless convention — at which
 *   point we're already loading and re-exporting, so we may as well
 *   skip the broken flag combination.
 * - `--format PEM --export-path foo.pem` writes `foo.pem` + `foo.pem.key`,
 *   not `foo.pem` + `foo.key`. The latter is what our `bundle.ts` /
 *   `inspect.ts` sibling-discovery probes for, what the in-container
 *   installer expects, and what the native backend produces. Going
 *   through our own exporters keeps naming uniform across backends.
 *
 * So the flow is:
 *   1. `dotnet dev-certs https [--trust]` — generates (if absent) and
 *      trusts. No file export.
 *   2. `findExistingDevCert()` against the platform store — same path
 *      the rest of the codebase uses to discover dotnet-installed certs.
 *   3. `exportPfx` + `exportPem` — write the files to outDir under our
 *      conventional names with our conventional permissions.
 *
 * On Linux, `dotnet dev-certs --trust` only populates the OpenSSL trust
 * dir and the .NET Root store; it doesn't touch the NSS DBs that
 * Firefox / Chromium read. We supplement that with our own `trustInNss`
 * step so the dotnet backend's trust outcome matches the native
 * backend's on Linux.
 */
export class DotnetBackend implements Backend {
  readonly kind = "dotnet" as const;

  async isAvailable(): Promise<boolean> {
    const result = await runProcess("dotnet", ["--version"], 5000);
    return result.exitCode === 0;
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    fs.mkdirSync(options.outDir, { recursive: true });

    const args = ["dev-certs", "https"];
    if (!options.noTrust) args.push("--trust");

    const result = await runProcess("dotnet", args, 60_000);
    if (result.exitCode !== 0) {
      throw new Error(
        `dotnet dev-certs failed (exit ${result.exitCode}): ${result.stderr || result.stdout}`
      );
    }

    const store = await createPlatformStore();
    const found = await store.findExistingDevCert();
    if (!found) {
      throw new Error(
        "dotnet dev-certs completed but no dev cert was found in the platform store afterwards."
      );
    }

    const pfxPath = await exportPfx(found.cert, found.key, options.outDir);
    const { certPath: pemPath, keyPath: pemKeyPath } = exportPem(
      found.cert,
      found.key,
      options.outDir
    );

    if (!options.noTrust && process.platform === "linux") {
      await runNssTrust(
        found.thumbprint,
        pemPath,
        options.linuxNssTrustReporter
      );
    }

    return {
      pfxPath,
      pemPath,
      pemKeyPath,
      thumbprint: found.thumbprint,
      trusted: !options.noTrust,
      backendUsed: "dotnet",
    };
  }
}

async function runNssTrust(
  thumbprint: string,
  exportedPemPath: string,
  reporter: LinuxNssTrustReporter | undefined
): Promise<void> {
  // Anchor the NSS import — and, crucially, the path handed to the
  // reporter — on the PERSISTENT OpenSSL trust-dir PEM, never on the
  // exported copy in the caller's outDir. Callers routinely provision
  // into a temp dir they delete as soon as generate() returns, while
  // the reporter's failure guidance (the VS Code toast's "Copy
  // Certificate Path" action) outlives that cleanup — a tmp-dir path
  // would be dangling by the time the user pastes it.
  //
  // `dotnet dev-certs --trust` writes this PEM itself on SDKs that
  // manage the Linux OpenSSL trust dir; on older SDKs the file may be
  // absent, so place a copy there ourselves before importing.
  const persistentPemPath = path.join(
    getOpenSslTrustDir(),
    getPemFileName(thumbprint)
  );
  if (!fs.existsSync(persistentPemPath)) {
    fs.mkdirSync(path.dirname(persistentPemPath), { recursive: true });
    fs.copyFileSync(exportedPemPath, persistentPemPath);
  }
  const result = await trustInNss(persistentPemPath);
  reporter?.(result, persistentPemPath);
}
