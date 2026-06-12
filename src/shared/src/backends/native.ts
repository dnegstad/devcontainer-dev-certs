import * as fs from "fs";
import * as path from "path";
import { exportPem, exportPfx } from "../cert/exporter";
import { generateCertificate } from "../cert/generator";
import { CertManager } from "../cert/manager";
import { VALIDITY_DAYS } from "../cert/properties";
import type { LinuxNssTrustReporter } from "../platform/types";
import type { Backend, GenerateOptions, GenerateResult } from "./types";

/**
 * Native backend: uses the in-tree cert primitives directly — no
 * shelling out to other tools, no `dotnet` runtime required.
 *
 * Two code paths, picked by `noTrust`:
 *
 * - `noTrust: false` (default): drive `CertManager` end-to-end. The
 *   generated cert lands in the host's OS platform store
 *   (`~/.dotnet/corefx/cryptography/x509stores/my/` on Linux/macOS,
 *   `CurrentUser\My` on Windows) and is added to the OS trust store.
 *   Living in the .NET store is part of the host-trust contract — it's
 *   where `dotnet dev-certs --check`, host-running Kestrel, and the
 *   VS Code host extension all look — so writing there is the point of
 *   the operation, not a side effect.
 *
 * - `noTrust: true`: generate purely in memory and write only to
 *   `outDir`. The platform store is NOT touched. The typical caller
 *   here is `dcdc generate --no-trust` for "give me cert files to
 *   bind-mount into a container" — that user has explicitly opted out
 *   of host-side cert installation, so we honor it by keeping our
 *   side effects bounded to `outDir`.
 */
export class NativeBackend implements Backend {
  readonly kind = "native" as const;

  isAvailable(): Promise<boolean> {
    // Always available — the shared layer ships implementations for all
    // three supported platforms and the cert primitives themselves have
    // no external runtime dependencies.
    return Promise.resolve(true);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    fs.mkdirSync(options.outDir, { recursive: true });

    if (options.noTrust) {
      return generateFilesOnly(options.outDir);
    }
    return generateAndTrust(options.outDir, options.linuxNssTrustReporter);
  }
}

async function generateFilesOnly(outDir: string): Promise<GenerateResult> {
  const now = new Date();
  const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400_000);
  const { cert, key, thumbprint } = await generateCertificate(now, expiry);

  const pfxPath = await exportPfx(cert, key, outDir);
  const { certPath: pemPath, keyPath: pemKeyPath } = exportPem(
    cert,
    key,
    outDir
  );

  return {
    pfxPath,
    pemPath,
    pemKeyPath,
    thumbprint,
    trusted: false,
    backendUsed: "native",
  };
}

async function generateAndTrust(
  outDir: string,
  linuxNssTrustReporter: LinuxNssTrustReporter | undefined
): Promise<GenerateResult> {
  // Without a reporter the Linux NSS trust step would still run but its
  // outcome would be discarded. The CLI's `dcdc generate` always wires a
  // stderr-logging reporter; CertProvider in the host extension wires its
  // toast reporter. Both surfaces are responsible for telling the user
  // when NSS trust didn't take.
  const manager = new CertManager({ linuxNssTrustReporter });
  await manager.trust();
  await manager.exportCert("pfx", outDir);
  await manager.exportCert("pem", outDir);

  // `manager.trust()` guarantees the cert is present in the platform
  // store, so a follow-up `check()` reads the thumbprint without
  // touching disk again. (Previously this re-parsed the exported PFX —
  // a holdover from when the dotnet backend did the same dance; the
  // dotnet rework no longer reparses, so this can read its own state.)
  const status = await manager.check();
  if (!status.thumbprint) {
    throw new Error(
      "Native backend trust() succeeded but check() reports no thumbprint."
    );
  }

  return {
    pfxPath: path.join(outDir, "aspnetcore-dev.pfx"),
    pemPath: path.join(outDir, "aspnetcore-dev.pem"),
    pemKeyPath: path.join(outDir, "aspnetcore-dev.key"),
    thumbprint: status.thumbprint,
    trusted: true,
    backendUsed: "native",
  };
}
