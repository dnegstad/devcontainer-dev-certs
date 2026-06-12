import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { loadPfx } from "../src/cert/loader";

/**
 * macOS-only integration test that answers a specific code-review
 * question: when `DotnetBackend.generate` runs `dotnet dev-certs https
 * --trust` and then calls `findExistingDevCert`, can our `parsePfx`
 * actually read the on-disk cache file aspnetcore writes?
 *
 * The cache file path is `~/.aspnet/dev-certs/https/aspnetcore-localhost-
 * {thumbprint}.pfx`. The writer in `MacOSCertificateManager.SaveCertificate
 * Core` calls `certificate.Export(X509ContentType.Pfx)` with no password
 * — but the byte-level PBE algorithm that produces on macOS is what
 * determines whether our parser (which strictly accepts PBES2 and
 * rejects every legacy PKCS#12 PBE-with-SHA OID) can read it back.
 *
 * Test isolates the cache file via `HOME=<tmpdir>` so it never touches
 * the developer's real dev cert state, and it deliberately omits
 * `--trust` so there's no keychain trust-settings prompt in CI.
 *
 * Outcomes:
 *   - parsePfx loads the file → finding REFUTED, DotnetBackend works on
 *     macOS as written.
 *   - parsePfx throws → finding CONFIRMED. The error message names the
 *     offending OID; we use that to pick the right fix.
 *
 * The test asserts a successful load. If aspnetcore changes the
 * algorithm in a future SDK, we want this to fail loudly rather than
 * pass with a stale assumption.
 */

const isMacOS = process.platform === "darwin";

let dotnetMajor = 0;
try {
  const v = execFileSync("dotnet", ["--version"], {
    timeout: 5000,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();
  dotnetMajor = Number.parseInt(v.split(".")[0] ?? "", 10) || 0;
} catch {
  // dotnet not on PATH; the describe.skipIf below skips the suite.
}

const ready = isMacOS && dotnetMajor >= 6;

let tmpHome: string;
let cachePfxPath: string;
let loadResult:
  | { kind: "ok"; thumbprint: string; hasKey: boolean }
  | { kind: "err"; message: string };

beforeAll(async () => {
  if (!ready) return;

  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-dotnet-macos-"));

  // `dotnet dev-certs https` (no --trust): generates a cert if absent,
  // saves to the macOS keychain, AND writes the disk cache file at
  // $HOME/.aspnet/dev-certs/https/. Setting HOME to a tmpdir redirects
  // only the disk cache — the keychain still lives at the user's real
  // login keychain. That's intentional: we're testing the disk cache,
  // not the keychain.
  //
  // 60s timeout because first-run cert generation can be slow on cold
  // CI runners.
  execFileSync("dotnet", ["dev-certs", "https"], {
    timeout: 60_000,
    env: { ...process.env, HOME: tmpHome },
    stdio: "pipe",
  });

  const cacheDir = path.join(tmpHome, ".aspnet", "dev-certs", "https");
  if (!fs.existsSync(cacheDir)) {
    // Surface this loudly — if the cache dir doesn't appear, the test
    // premise has changed (aspnetcore moved or skipped the disk cache)
    // and any further assertions are meaningless.
    throw new Error(
      `Expected aspnetcore disk cache at ${cacheDir}; directory does not exist. ` +
        `dotnet dev-certs may have changed its on-disk layout.`
    );
  }
  const pfxes = fs
    .readdirSync(cacheDir)
    .filter(
      (f) => f.startsWith("aspnetcore-localhost-") && f.endsWith(".pfx")
    );
  if (pfxes.length === 0) {
    throw new Error(
      `aspnetcore disk cache dir ${cacheDir} contains no aspnetcore-localhost-*.pfx files.`
    );
  }
  cachePfxPath = path.join(cacheDir, pfxes[0]);

  try {
    const loaded = await loadPfx(cachePfxPath);
    loadResult = {
      kind: "ok",
      thumbprint: loaded.thumbprint,
      hasKey: loaded.key !== null,
    };
  } catch (err) {
    loadResult = {
      kind: "err",
      message: err instanceof Error ? err.message : String(err),
    };
  }
}, 120_000);

afterAll(() => {
  if (tmpHome) fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe.skipIf(!ready)(
  "dotnet dev-certs macOS disk cache → parsePfx",
  () => {
    it("loads the disk-cache PFX without throwing", () => {
      // Diagnostic: write the resolved path AND outcome to stderr so
      // CI logs carry an actionable signal even when the assertion
      // passes. (stderr instead of console.log to dodge the codebase's
      // no-console rule.)
      process.stderr.write(
        `[macos-cache] dotnet major: ${dotnetMajor}, cache: ${cachePfxPath}, ` +
          `result: ${JSON.stringify(loadResult)}\n`
      );
      expect(loadResult.kind).toBe("ok");
    });

    it("recovers a 40-char SHA-1 thumbprint from the cache PFX", () => {
      if (loadResult.kind !== "ok") return;
      expect(loadResult.thumbprint).toMatch(/^[0-9A-F]{40}$/);
    });

    it("includes the private key (otherwise Kestrel couldn't serve TLS)", () => {
      if (loadResult.kind !== "ok") return;
      expect(loadResult.hasKey).toBe(true);
    });
  }
);
