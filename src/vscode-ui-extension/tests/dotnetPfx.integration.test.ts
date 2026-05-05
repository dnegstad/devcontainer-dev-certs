import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync, spawnSync } from "child_process";
import { generateCertificate } from "../src/cert/generator";
import { exportPfx } from "../src/cert/exporter";
import { VALIDITY_DAYS } from "../src/cert/properties";

/**
 * Skips unless `dotnet --version` reports a major SDK version >= 10. The
 * harness uses `X509CertificateLoader.LoadPkcs12`, which is the
 * non-obsolete PKCS#12 entry point landed in .NET 9 and the recommended
 * path on .NET 10 LTS.
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
const dotnetReady = dotnetMajor >= 10;

// The vitest run is always launched from `src/vscode-ui-extension/`
// (`npm test -w src/vscode-ui-extension`), so the repo's `test/` dir is
// two levels up from cwd. If you change how vitest is invoked, update
// this anchor.
const HARNESS_DIR = path.resolve(
  process.cwd(),
  "../../test/dotnet-pfx-roundtrip"
);

let tmpDir: string;

beforeAll(() => {
  if (!dotnetReady) return;
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-pfx-"));
  // Build once — `dotnet run --no-build` per test then takes ~1s instead
  // of ~5–10s. Build failures are surfaced here rather than swallowed by
  // the per-test invocation.
  execFileSync(
    "dotnet",
    ["build", HARNESS_DIR, "-c", "Release", "--nologo"],
    { timeout: 180_000, stdio: "pipe" }
  );
}, 200_000);

afterAll(() => {
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe.skipIf(!dotnetReady)(
  "PFX round-trip via .NET (X509CertificateLoader)",
  () => {
    it("loads the auto-generated dev cert PFX and matches its SHA-1 thumbprint", async () => {
      // Mirror the exact production flow for the auto-generated dev cert:
      //   generateCertificate(...)  → RSA-2048 / SHA-256, dev-cert OID set
      //   exportPfx(cert, key, dir) → PBES2/AES-256-CBC + HMAC-SHA-256, no password
      // If .NET stops accepting the resulting PFX, Kestrel's X509Store
      // fallback would fail at runtime — this catches that regression at
      // CI time instead.
      const now = new Date();
      const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
      const generated = await generateCertificate(now, expiry);

      const dir = fs.mkdtempSync(path.join(tmpDir, "case-"));
      const pfxPath = await exportPfx(generated.cert, generated.key, dir);

      const result = spawnSync(
        "dotnet",
        [
          "run",
          "--project",
          HARNESS_DIR,
          "-c",
          "Release",
          "--no-build",
          "--",
          pfxPath,
          "",
        ],
        { timeout: 60_000, encoding: "utf-8" }
      );

      const stdout = (result.stdout ?? "").trim();
      const stderr = (result.stderr ?? "").trim();
      const diagnostic = `dotnet harness:\n  status=${result.status}\n  stdout=${stdout}\n  stderr=${stderr}`;

      expect(result.status, diagnostic).toBe(0);

      const parts = stdout.split("\t");
      expect(parts[0], diagnostic).toBe("OK");
      // Subject is rendered by .NET as "CN=localhost".
      expect(parts[1], diagnostic).toContain("CN=localhost");
      // .NET's X509Certificate2.Thumbprint is SHA-1 uppercase hex — the
      // exact value our generator emits as `cert.thumbprintSha1`.
      expect(parts[2], diagnostic).toBe(generated.cert.thumbprintSha1);
    }, 60_000);
  }
);
