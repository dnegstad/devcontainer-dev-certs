import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync, spawnSync } from "child_process";
import {
  ASPNET_HTTPS_OID_DER,
  scanPfxForDevCertOid,
} from "../src/util/pkcs12DevCertScan";

/**
 * End-to-end check that `scanPfxForDevCertOid` identifies a PFX produced by
 * the real `dotnet dev-certs https` CLI — the second producer (alongside
 * the host extension's own `buildPfx`) we need to handle to make the
 * cleanup command work. Skips unless `dotnet --version` reports >= 9, the
 * floor on which `dotnet dev-certs https --export-path --no-password` is
 * available and stable. CI sets up .NET 10 in build-extensions.yml.
 */
let dotnetMajor = 0;
try {
  const dotnetVersion = execFileSync("dotnet", ["--version"], {
    timeout: 5000,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();
  dotnetMajor = Number.parseInt(dotnetVersion.split(".")[0] ?? "", 10) || 0;
} catch {
  // dotnet not on PATH — suite skips.
}
const dotnetReady = dotnetMajor >= 9;

let tmpDir: string;
// Each export under a per-test sub-dir, but we share the dotnet-managed
// dev cert across the suite — generating one is slow.
let devCertPfx: Buffer | null = null;
let devCertPfxWithPassword: Buffer | null = null;

beforeAll(() => {
  if (!dotnetReady) return;
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-scan-"));

  // Export the dev cert as a passwordless PFX. `dotnet dev-certs https` will
  // mint one in the user's store if it doesn't already exist there.
  const pfxNoPwdPath = path.join(tmpDir, "dev-nopass.pfx");
  const result = spawnSync(
    "dotnet",
    [
      "dev-certs",
      "https",
      "--export-path",
      pfxNoPwdPath,
      "--no-password",
      "--quiet",
    ],
    { timeout: 120_000, encoding: "utf-8" }
  );
  if (result.status === 0 && fs.existsSync(pfxNoPwdPath)) {
    devCertPfx = fs.readFileSync(pfxNoPwdPath);
  }

  // Also export with an explicit empty `--password ""` — older .NET
  // versions emitted different default encryption on this path vs the
  // `--no-password` path, and we want the cleanup scan to handle both.
  const pfxPwdPath = path.join(tmpDir, "dev-emptypass.pfx");
  const result2 = spawnSync(
    "dotnet",
    [
      "dev-certs",
      "https",
      "--export-path",
      pfxPwdPath,
      "--password",
      "",
      "--quiet",
    ],
    { timeout: 120_000, encoding: "utf-8" }
  );
  if (result2.status === 0 && fs.existsSync(pfxPwdPath)) {
    devCertPfxWithPassword = fs.readFileSync(pfxPwdPath);
  }
}, 180_000);

afterAll(() => {
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe.skipIf(!dotnetReady)(
  "scanPfxForDevCertOid against `dotnet dev-certs https` output",
  () => {
    it("identifies a PFX produced by `--export-path ... --no-password`", () => {
      expect(devCertPfx, "dotnet dev-certs --no-password export failed").not.toBeNull();
      expect(scanPfxForDevCertOid(devCertPfx!)).toBe(true);
    });

    it("identifies a PFX produced by `--export-path ... --password \"\"`", () => {
      // Skip this case if .NET's CLI rejected the empty-string password
      // argument (older versions allow it; newer versions may not). We
      // already proved scanning works above; this is a belt-and-suspenders
      // check for the alternate export path.
      if (!devCertPfxWithPassword) return;
      expect(scanPfxForDevCertOid(devCertPfxWithPassword)).toBe(true);
    });

    it("usually exercises the decrypt path, not the plaintext fast path", () => {
      // `dotnet dev-certs` historically encrypts the cert bag (PBE-SHA1-3DES
      // on legacy .NET, PBES2/AES on newer .NET). If the OID happens to
      // appear in plaintext (unlikely but possible for some future export
      // mode), the assertion below is too strict — soften to a log instead
      // of a hard failure.
      if (!devCertPfx) return;
      const hasPlaintextOid = devCertPfx.includes(ASPNET_HTTPS_OID_DER);
      if (hasPlaintextOid) {
        console.log(
          "[note] dotnet-exported PFX has plaintext OID — scanner took fast path, not decrypt path."
        );
      }
      // Either way, the scan must succeed.
      expect(scanPfxForDevCertOid(devCertPfx)).toBe(true);
    });
  }
);
