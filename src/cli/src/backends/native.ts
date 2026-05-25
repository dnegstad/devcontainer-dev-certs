import * as fs from "fs";
import * as path from "path";
import {
  CertManager,
  VALIDITY_DAYS,
  generateCertificate,
  exportPfx,
  exportPem,
  loadPfx,
  buildPfx,
  type DevCert,
  type DevKey,
} from "@devcontainer-dev-certs/shared";
import type { Backend, GenerateOptions, GenerateResult } from "./types";

/**
 * Native backend: uses the shared `CertManager` directly. Same code path
 * the VS Code host extension uses for generation, host trust, and
 * platform-store I/O — no shelling out to other tools.
 */
export class NativeBackend implements Backend {
  readonly kind = "native" as const;

  isAvailable(): Promise<boolean> {
    // The native backend is always available — the shared layer ships
    // implementations for all three supported platforms (Linux/macOS/Windows)
    // and the cert primitives themselves have no external runtime
    // dependencies.
    return Promise.resolve(true);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    fs.mkdirSync(options.outDir, { recursive: true });

    const manager = new CertManager();

    // Drive the manager through the same generate+trust flow the host
    // extension uses, then export the live cert to the out-dir. Trust is
    // skipped when --no-trust is passed.
    if (options.noTrust) {
      // Generate-only: produce a cert, save it to the platform store, but
      // don't trust. The manager exposes `generate()` separately for this.
      await manager.generate(false);
    } else {
      await manager.trust();
    }

    // Export current cert. The manager doesn't expose the live cert/key
    // directly; export it through the manager's `exportCert` which writes
    // the canonical filenames. We follow up by reading the PFX back to
    // recover the thumbprint — the manager will have loaded the same cert
    // from the platform store so the bytes match.
    await manager.exportCert("pfx", options.outDir);
    await manager.exportCert("pem", options.outDir);

    const pfxPath = path.join(options.outDir, "aspnetcore-dev.pfx");
    const pemPath = path.join(options.outDir, "aspnetcore-dev.pem");
    const pemKeyPath = path.join(options.outDir, "aspnetcore-dev.key");

    const loaded = await loadPfx(pfxPath);
    if (!loaded || !loaded.cert) {
      throw new Error(
        `Native backend export wrote ${pfxPath} but it could not be reparsed for thumbprint recovery.`
      );
    }

    return {
      pfxPath,
      pemPath,
      pemKeyPath,
      thumbprint: loaded.cert.thumbprintSha1,
      trusted: !options.noTrust,
      backendUsed: "native",
    };
  }
}

/**
 * Generate a brand-new cert in memory (no platform-store interaction) and
 * write it to the given out-dir. Used by `ddc generate` when the user opts
 * out of the manager flow and just wants files on disk; also useful as a
 * lower-level building block for tests.
 *
 * Exposed alongside `NativeBackend` because some flows (e.g. a future
 * `ddc bundle --regen`) want the artifacts without trust as a side effect.
 */
export async function generateAndWriteFiles(
  outDir: string
): Promise<{
  cert: DevCert;
  key: DevKey;
  thumbprint: string;
  pfxPath: string;
  pemPath: string;
  pemKeyPath: string;
  rootPfxPath: string;
}> {
  fs.mkdirSync(outDir, { recursive: true });

  const now = new Date();
  const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400_000);
  const { cert, key, thumbprint } = await generateCertificate(now, expiry);

  const pfxPath = await exportPfx(cert, key, outDir);
  const { certPath: pemPath, keyPath: pemKeyPath } = exportPem(cert, key, outDir);

  const rootPfxPath = path.join(outDir, "aspnetcore-dev-root.pfx");
  fs.writeFileSync(rootPfxPath, await buildPfx({ cert }), { mode: 0o644 });

  return { cert, key, thumbprint, pfxPath, pemPath, pemKeyPath, rootPfxPath };
}
