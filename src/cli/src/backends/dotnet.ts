import * as fs from "fs";
import * as path from "path";
import {
  loadPfx,
  runProcess,
} from "@devcontainer-dev-certs/shared";
import type { Backend, GenerateOptions, GenerateResult } from "./types";

/**
 * Dotnet backend: shells out to `dotnet dev-certs https`. On macOS this is
 * the canonical way to get a signed-binary-attributed keychain trust prompt
 * — the host extension's `security add-trusted-cert` flow works but has a
 * less polished UX because the calling binary isn't a notarized Apple
 * cert-management tool. On Windows / Linux the dotnet backend is equivalent
 * to the native backend modulo cert format differences.
 *
 * Two-pass: one invocation exports PFX, a second exports PEM. We pass
 * `--trust` only on the first invocation (the second pass would re-trust
 * the same cert and add nothing).
 */
export class DotnetBackend implements Backend {
  readonly kind = "dotnet" as const;

  async isAvailable(): Promise<boolean> {
    const result = await runProcess("dotnet", ["--version"], 5000);
    return result.exitCode === 0;
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    fs.mkdirSync(options.outDir, { recursive: true });

    const pfxPath = path.join(options.outDir, "aspnetcore-dev.pfx");
    const pemPath = path.join(options.outDir, "aspnetcore-dev.pem");
    // dotnet dev-certs --format PEM writes both `<file>` (cert) and
    // `<file>.key` (key) when invoked without --no-password and without
    // `-ep`. We rely on that companion key file to populate pemKeyPath.
    const pemKeyPath = path.join(options.outDir, "aspnetcore-dev.pem.key");

    // First pass: export PFX, trust (unless --no-trust).
    const pfxArgs = ["dev-certs", "https"];
    if (!options.noTrust) pfxArgs.push("--trust");
    pfxArgs.push("--format", "Pfx", "--no-password", "--export-path", pfxPath);

    const pfxResult = await runProcess("dotnet", pfxArgs, 60_000);
    if (pfxResult.exitCode !== 0) {
      throw new Error(
        `dotnet dev-certs (PFX pass) failed (exit ${pfxResult.exitCode}): ${pfxResult.stderr || pfxResult.stdout}`
      );
    }

    // Second pass: export PEM. No --trust here — already done above.
    const pemResult = await runProcess(
      "dotnet",
      [
        "dev-certs",
        "https",
        "--format",
        "PEM",
        "--no-password",
        "--export-path",
        pemPath,
      ],
      60_000
    );
    if (pemResult.exitCode !== 0) {
      throw new Error(
        `dotnet dev-certs (PEM pass) failed (exit ${pemResult.exitCode}): ${pemResult.stderr || pemResult.stdout}`
      );
    }

    // Recover the thumbprint from the PFX we just wrote.
    const loaded = await loadPfx(pfxPath);
    if (!loaded || !loaded.cert) {
      throw new Error(
        `dotnet wrote ${pfxPath} but the resulting PFX could not be parsed.`
      );
    }

    return {
      pfxPath,
      pemPath,
      pemKeyPath: fs.existsSync(pemKeyPath) ? pemKeyPath : null,
      thumbprint: loaded.cert.thumbprintSha1,
      trusted: !options.noTrust,
      backendUsed: "dotnet",
    };
  }
}
