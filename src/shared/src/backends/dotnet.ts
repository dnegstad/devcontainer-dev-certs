import * as fs from "fs";
import * as path from "path";
import { loadPfx } from "../cert/loader";
import { runProcess } from "../platform/processUtil";
import type { Backend, GenerateOptions, GenerateResult } from "./types";

/**
 * Dotnet backend: shells out to `dotnet dev-certs https`. On macOS this
 * is the canonical way to get a signed-binary-attributed keychain trust
 * prompt — the native backend's `security add-trusted-cert` invocation
 * works but has a less polished UX because the calling binary isn't a
 * notarized Apple cert-management tool. On Windows / Linux the two
 * backends end up writing to the same platform store, so the choice is
 * mostly stylistic.
 *
 * Two-pass: one invocation to write the PFX (with `--trust` unless
 * `noTrust` is set), a second to write the PEM. We can't combine them —
 * `dotnet dev-certs --format ...` only accepts one format per call, and
 * `--trust` only does anything on the first invocation anyway (it's
 * idempotent w.r.t. the OS trust store).
 *
 * `noTrust` only suppresses the OS-trust step here; it does NOT
 * suppress the .NET store side effect. `dotnet dev-certs https`
 * always persists the generated cert into the .NET X509Store
 * regardless of `--trust`. If a caller needs strict isolation —
 * cert files in `outDir` and nothing else — they should use the
 * native backend, which honors `noTrust` by skipping the store
 * entirely. We can't paper over this here without re-implementing
 * what `dotnet dev-certs` does, which is the entire point of using
 * the dotnet backend in the first place.
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
    // `dotnet dev-certs --format PEM` writes both `<file>` (cert) and
    // `<file>.key` (private key in PEM PKCS#8).
    const pemKeyPath = path.join(options.outDir, "aspnetcore-dev.pem.key");

    const pfxArgs = ["dev-certs", "https"];
    if (!options.noTrust) pfxArgs.push("--trust");
    pfxArgs.push("--format", "Pfx", "--no-password", "--export-path", pfxPath);

    const pfxResult = await runProcess("dotnet", pfxArgs, 60_000);
    if (pfxResult.exitCode !== 0) {
      throw new Error(
        `dotnet dev-certs (PFX pass) failed (exit ${pfxResult.exitCode}): ${pfxResult.stderr || pfxResult.stdout}`
      );
    }

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

    const loaded = await loadPfx(pfxPath);
    if (!loaded.cert) {
      throw new Error(
        `dotnet wrote ${pfxPath} but the resulting PFX could not be parsed for thumbprint recovery.`
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
