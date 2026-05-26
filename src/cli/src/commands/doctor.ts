import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  createPlatformStore,
  describeAutoBackend,
  DotnetBackend,
  runProcess,
} from "@devcontainer-dev-certs/shared";
import { installCliLogger } from "../logger";

export interface DoctorCommandOptions {
  outDir?: string;
  verbose?: boolean;
}

const DEFAULT_OUT_DIR = path.join(os.homedir(), ".dev-certs");

interface Check {
  label: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

/**
 * `ddc doctor` — read-only diagnostics: which backends are available, what
 * `--backend auto` would pick, host trust-store state for the cert (if any)
 * in the out-dir. Mirrors the in-container `devcontainer-dev-certs-install
 * --doctor` ergonomics: every check produces an `[ok]` / `[warn]` / `[fail]`
 * line.
 */
export async function runDoctor(
  options: DoctorCommandOptions
): Promise<void> {
  installCliLogger(Boolean(options.verbose));

  const outDir = path.resolve(options.outDir ?? DEFAULT_OUT_DIR);
  const checks: Check[] = [];

  // Backend availability.
  const dotnetAvailable = await new DotnetBackend().isAvailable();
  checks.push({
    label: "dotnet CLI on PATH",
    status: dotnetAvailable ? "ok" : "warn",
    detail: dotnetAvailable
      ? "found"
      : "not found (the 'dotnet' backend is unavailable; native backend will be used)",
  });

  const auto = await describeAutoBackend();
  checks.push({
    label: "--backend auto would pick",
    status: "ok",
    detail: auto,
  });

  // Out-dir presence.
  if (fs.existsSync(outDir)) {
    checks.push({
      label: `out-dir ${outDir}`,
      status: "ok",
      detail: "exists",
    });
  } else {
    checks.push({
      label: `out-dir ${outDir}`,
      status: "warn",
      detail: "does not exist (run `ddc generate` to create it)",
    });
  }

  // Bundle.json presence.
  const bundlePath = path.join(outDir, "bundle.json");
  if (fs.existsSync(bundlePath)) {
    checks.push({
      label: `bundle.json at ${bundlePath}`,
      status: "ok",
      detail: "found",
    });
  } else {
    checks.push({
      label: `bundle.json at ${bundlePath}`,
      status: "warn",
      detail: "not found",
    });
  }

  // Platform store state.
  try {
    const store = await createPlatformStore();
    const status = await store.checkStatus();
    if (status.exists) {
      checks.push({
        label: "Host platform store has a valid dev cert",
        status: status.isTrusted ? "ok" : "warn",
        detail: status.isTrusted
          ? `trusted (thumbprint ${status.thumbprint}, expires ${status.notAfter})`
          : `present but NOT trusted (thumbprint ${status.thumbprint}, expires ${status.notAfter})`,
      });
    } else {
      checks.push({
        label: "Host platform store has a valid dev cert",
        status: "warn",
        detail: "no dev cert found in host platform store",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    checks.push({
      label: "Host platform store check",
      status: "fail",
      detail: message,
    });
  }

  // Required tools for the native backend on Linux.
  if (process.platform === "linux") {
    const openssl = await runProcess("which", ["openssl"]);
    checks.push({
      label: "openssl on PATH (Linux native trust)",
      status: openssl.exitCode === 0 ? "ok" : "warn",
      detail: openssl.exitCode === 0 ? openssl.stdout.trim() : "not found",
    });
    const certutil = await runProcess("which", ["certutil"]);
    checks.push({
      label: "certutil on PATH (Linux NSS browser trust)",
      status: certutil.exitCode === 0 ? "ok" : "warn",
      detail:
        certutil.exitCode === 0
          ? certutil.stdout.trim()
          : "not found (Chromium/Firefox won't auto-trust; install libnss3-tools / nss-tools)",
    });
  }

  // Print summary.
  let failures = 0;
  let warnings = 0;
  for (const c of checks) {
    process.stdout.write(`[${c.status}] ${c.label}: ${c.detail}\n`);
    if (c.status === "fail") failures++;
    else if (c.status === "warn") warnings++;
  }
  process.stdout.write(
    `\n${checks.length} check(s) total — ${failures} fail, ${warnings} warn.\n`
  );

  if (failures > 0) {
    process.exitCode = 1;
  }
}
