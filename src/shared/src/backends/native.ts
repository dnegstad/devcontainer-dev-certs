import * as fs from "fs";
import * as path from "path";
import { CertManager } from "../cert/manager";
import { loadPfx } from "../cert/loader";
import type { Backend, GenerateOptions, GenerateResult } from "./types";

/**
 * Native backend: uses the in-tree `CertManager` directly. Same code path
 * the VS Code host extension uses for generation, host trust, and
 * platform-store I/O — no shelling out to other tools, no `dotnet` runtime
 * required.
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

    const manager = new CertManager();
    if (options.noTrust) {
      // Generate-only: produce a cert, save it to the platform store, but
      // don't run the OS trust-prompt path.
      await manager.generate(false);
    } else {
      await manager.trust();
    }

    await manager.exportCert("pfx", options.outDir);
    await manager.exportCert("pem", options.outDir);

    const pfxPath = path.join(options.outDir, "aspnetcore-dev.pfx");
    const pemPath = path.join(options.outDir, "aspnetcore-dev.pem");
    const pemKeyPath = path.join(options.outDir, "aspnetcore-dev.key");

    // Recover the thumbprint by re-reading the exported PFX. Cheaper than
    // reaching into the manager's private state and keeps the contract
    // symmetric with the `dotnet` backend's recovery step.
    const loaded = await loadPfx(pfxPath);
    if (!loaded.cert) {
      throw new Error(
        `Native backend wrote ${pfxPath} but it could not be reparsed for thumbprint recovery.`
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
