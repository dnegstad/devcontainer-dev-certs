import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { execFileSync, spawnSync } from "child_process";
import {
  getDotNetRootStorePath,
  getDotNetStorePath,
} from "@devcontainer-dev-certs/shared";
import {
  ASPNET_HTTPS_OID_DER,
  scanPfxForDevCertOid,
} from "../src/util/pkcs12DevCertScan";

/**
 * End-to-end check that `scanPfxForDevCertOid` identifies the PFX that
 * `dotnet dev-certs https --trust` actually lands in the standard .NET
 * store directories — i.e. exactly the file shape the cleanup command
 * will encounter at runtime, produced by the second producer we care
 * about (alongside this extension's own `buildPfx`).
 *
 * Gated to CI:
 *   - `--trust` mutates the host's .NET store and OpenSSL trust
 *     directories, so we don't want to stomp on a developer's real
 *     config when they `npm test` locally.
 *   - `CI=true` is the GitHub Actions convention; the CI workflow
 *     installs .NET 10 SDK ahead of `npm test`.
 *
 * Exit-code handling:
 *   - `dotnet dev-certs https --trust` returns 4 on Linux when
 *     SSL_CERT_DIR doesn't include the OpenSSL trust dir — "partial
 *     trust", but the .NET store + trust dir writes still happened.
 *     That's the only state we need for this scan, so 4 is treated as
 *     success here. Any other non-zero exit is a real failure and
 *     surfaces.
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

// Use the same path helpers production code uses so any future change
// to the canonical .NET store locations propagates here automatically.
const dotnetMyStore = getDotNetStorePath();
const dotnetRootStore = getDotNetRootStorePath();

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
  // OpenSSL trust dir — see banner comment). Both leave the same artifacts
  // on disk in the locations we scan below.
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
  // dev-cert state between unrelated jobs. `--clean` removes the cert from
  // every standard location it touched.
  spawnSync("dotnet", ["dev-certs", "https", "--clean", "--quiet"], {
    timeout: 60_000,
  });
});

describe.skipIf(!ready)(
  "scanPfxForDevCertOid against PFXes produced by `dotnet dev-certs https --trust`",
  () => {
    it("identifies the dev cert PFX in the CurrentUser/My .NET store", () => {
      const candidates = listPfxes(dotnetMyStore);
      expect(
        candidates.length,
        `no thumbprint-keyed PFX files found in ${dotnetMyStore} after --trust`
      ).toBeGreaterThan(0);

      const positives = candidates.filter((f) => {
        const bytes = fs.readFileSync(path.join(dotnetMyStore, f));
        return scanPfxForDevCertOid(bytes);
      });
      expect(
        positives.length,
        `scanPfxForDevCertOid did not identify any PFX in ${dotnetMyStore} ` +
          `as a dev cert (candidates: ${candidates.join(", ")})`
      ).toBeGreaterThan(0);
    });

    it("identifies the dev cert PFX in the CurrentUser/Root .NET store", () => {
      const candidates = listPfxes(dotnetRootStore);
      expect(
        candidates.length,
        `no thumbprint-keyed PFX files found in ${dotnetRootStore} after --trust`
      ).toBeGreaterThan(0);

      const positives = candidates.filter((f) => {
        const bytes = fs.readFileSync(path.join(dotnetRootStore, f));
        return scanPfxForDevCertOid(bytes);
      });
      expect(positives.length).toBeGreaterThan(0);
    });

    it("usually exercises the decrypt path, not the plaintext fast path", () => {
      // Modern .NET's PFX export encrypts the cert bag with PBES2/AES. If a
      // future runtime stops encrypting it, the fast path catches the OID
      // directly — still a pass, but we want a log so the test author knows
      // the decrypt path wasn't actually exercised on this runner.
      const candidates = listPfxes(dotnetMyStore);
      const pick = candidates[0];
      if (!pick) return;
      const bytes = fs.readFileSync(path.join(dotnetMyStore, pick));
      if (bytes.includes(ASPNET_HTTPS_OID_DER)) {
        console.log(
          `[note] PFX ${pick} in the .NET My store carried the OID in ` +
            `plaintext — scanner took the fast path, not the decrypt path.`
        );
      }
      expect(scanPfxForDevCertOid(bytes)).toBe(true);
    });
  }
);
