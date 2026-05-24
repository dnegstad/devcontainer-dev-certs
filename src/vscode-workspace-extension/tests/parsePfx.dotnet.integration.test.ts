// Polyfill must load before any module that pulls in @peculiar/x509 (via
// shared). tsyringe — a transitive dep of @peculiar/x509 — wires up
// `@injectable` decorators against `Reflect.metadata` at module init.
import "reflect-metadata";

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { execFileSync, spawnSync } from "child_process";
import {
  ASPNET_HTTPS_OID,
  getDotNetStorePath,
  parsePfx,
} from "@devcontainer-dev-certs/shared";

/**
 * End-to-end check that the shared `parsePfx` reader (and therefore
 * `cleanupCerts.isAspNetDevCertPfx`, the dev-cert-OID identification
 * helper that's keyed on it) accepts the PFX that
 * `dotnet dev-certs https --trust` actually lands in the standard .NET
 * store directory on Linux.
 *
 * Background: dotnet dev-certs on Linux historically computes the outer
 * PKCS#12 MAC against `Encoding.BigEndianUnicode.GetBytes(password)`
 * (i.e. UTF-16BE WITHOUT a 00 00 terminator) rather than the RFC 7292
 * §B.1 form (UTF-16BE WITH a 00 00 terminator). pkijs's built-in MAC
 * verifier only accepts the RFC form, so before the dual-convention
 * verifier landed, parsePfx would throw "Integrity for the PKCS#12 data
 * is broken!" on every .NET-Linux dev-cert PFX — silently dropping it
 * from cleanup-sweep detection in the workspace extension. This test
 * pins that interop so the regression can't sneak back in.
 *
 * Gated to CI:
 *   - `--trust` mutates the host's .NET store and trust directories, so
 *     we don't want to stomp on a developer's real config when they
 *     `npm test` locally.
 *   - `CI=true` is the GitHub Actions convention; the CI workflow
 *     installs .NET 10 SDK ahead of `npm test`.
 *
 * Exit-code handling:
 *   - `dotnet dev-certs https --trust` returns 4 on Linux when
 *     SSL_CERT_DIR doesn't include the OpenSSL trust dir — "partial
 *     trust", but the .NET store write still happened. That's the only
 *     state we need for this test, so 4 is treated as success.
 */
const inCi = process.env["CI"] === "true";

let dotnetMajor = 0;
if (inCi) {
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
}
const ready = inCi && dotnetMajor >= 9;

const dotnetMyStore = getDotNetStorePath();
const PFX_RE = /^[A-F0-9]{40}\.pfx$/i;

function listPfxes(dir: string): string[] {
  try {
    return fs.readdirSync(dir).filter((f) => PFX_RE.test(f));
  } catch {
    return [];
  }
}

beforeAll(() => {
  if (!ready) return;

  const result = spawnSync(
    "dotnet",
    ["dev-certs", "https", "--trust", "--quiet"],
    { timeout: 180_000, encoding: "utf-8" }
  );

  // 0 = full success, 4 = partial trust (SSL_CERT_DIR didn't include the
  // OpenSSL trust dir). Both leave the .NET store PFX in place.
  if (result.status !== 0 && result.status !== 4) {
    throw new Error(
      `dotnet dev-certs --trust failed: status=${result.status}\n` +
        `stdout=${(result.stdout ?? "").trim()}\n` +
        `stderr=${(result.stderr ?? "").trim()}`
    );
  }
}, 200_000);

afterAll(() => {
  if (!ready) return;
  // Best-effort: roll back what --trust placed so the runner doesn't carry
  // dev-cert state between unrelated jobs.
  spawnSync("dotnet", ["dev-certs", "https", "--clean", "--quiet"], {
    timeout: 60_000,
  });
});

describe.skipIf(!ready)(
  "parsePfx against PFXes produced by `dotnet dev-certs https --trust`",
  () => {
    it("verifies the MAC and exposes the ASP.NET dev-cert OID extension", async () => {
      const candidates = listPfxes(dotnetMyStore);
      expect(
        candidates.length,
        `no thumbprint-keyed PFX files found in ${dotnetMyStore} after --trust`
      ).toBeGreaterThan(0);

      const positives: string[] = [];
      for (const f of candidates) {
        const bytes = fs.readFileSync(path.join(dotnetMyStore, f));
        // Passwordless dev-cert PFX. parsePfx must (a) verify the outer
        // MAC against .NET-Linux's no-terminator empty-password
        // convention without throwing, and (b) surface the dev-cert OID
        // extension on the parsed cert — exactly the contract that
        // `cleanupCerts.isAspNetDevCertPfx` depends on.
        const parsed = await parsePfx(bytes, "");
        if (parsed.cert.hasExtension(ASPNET_HTTPS_OID)) {
          positives.push(f);
        }
      }
      expect(
        positives.length,
        `parsePfx did not surface the ASPNET_HTTPS_OID extension on any ` +
          `PFX in ${dotnetMyStore} (candidates: ${candidates.join(", ")})`
      ).toBeGreaterThan(0);
    });
  }
);
