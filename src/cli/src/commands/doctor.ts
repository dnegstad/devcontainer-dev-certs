import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  createPlatformStore,
  describeAutoBackend,
  DotnetBackend,
  resolveSafeExecPath,
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
 * `dcdc doctor` — read-only diagnostics: which backends are available, what
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
      detail: "does not exist (run `dcdc generate` to create it)",
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

  for (const c of await checkPlatformTools()) checks.push(c);

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

/**
 * Per-OS tool presence checks. Each backend / trust path depends on a
 * different set of external commands, so the checks branch by
 * `process.platform`. Linux has the most fan-out (separate tools for
 * the OpenSSL trust dir and the NSS browser DB); macOS and Windows
 * each have a small canonical set.
 *
 * On Windows we resolve via `resolveSafeExecPath` rather than shelling
 * to `where.exe` — same lookup as `runProcess`, no spawn overhead, no
 * risk of `where.exe` itself being hijacked.
 */
async function checkPlatformTools(): Promise<Check[]> {
  if (process.platform === "linux") return checkLinuxTools();
  if (process.platform === "darwin") return checkMacosTools();
  if (process.platform === "win32") return checkWindowsTools();
  return [];
}

async function checkLinuxTools(): Promise<Check[]> {
  const checks: Check[] = [];

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

  return checks;
}

async function checkMacosTools(): Promise<Check[]> {
  const checks: Check[] = [];

  // `security` is the keychain CLI. macStore uses it for trust and
  // enumeration; without it the native backend can't run on macOS.
  // It's part of the base OS install at /usr/bin/security, so a
  // missing entry usually means PATH has been pruned aggressively.
  const security = await runProcess("which", ["security"]);
  checks.push({
    label: "security on PATH (macOS keychain trust)",
    status: security.exitCode === 0 ? "ok" : "warn",
    detail:
      security.exitCode === 0
        ? security.stdout.trim()
        : "not found (native backend cannot drive the keychain — usually means PATH was stripped)",
  });

  return checks;
}

function checkWindowsTools(): Check[] {
  const checks: Check[] = [];

  // windowsStore prefers `pwsh` (PowerShell 7+) but falls back to
  // `powershell` (PowerShell 5.1). At least one must be findable.
  const pwsh = resolveSafeExecPath("pwsh");
  const powershell = resolveSafeExecPath("powershell");
  const psFound = pwsh ?? powershell;
  checks.push({
    label: "pwsh or powershell on PATH (Windows store enumeration)",
    status: psFound !== null ? "ok" : "warn",
    detail:
      psFound !== null
        ? `${psFound}${pwsh === null ? " (PowerShell 5.1; pwsh 7+ preferred but not required)" : ""}`
        : "not found (Windows store enumeration / cleanup will fail)",
  });

  const certutilExe = resolveSafeExecPath("certutil.exe");
  checks.push({
    label: "certutil.exe on PATH (Windows trust store)",
    status: certutilExe !== null ? "ok" : "warn",
    detail:
      certutilExe ??
      "not found (native trust step will fail — usually means PATH was stripped)",
  });

  return checks;
}
