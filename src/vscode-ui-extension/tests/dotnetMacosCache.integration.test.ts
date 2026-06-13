import { describe, it, expect, beforeAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import * as pkijs from "pkijs";
import { loadPfx } from "../src/cert/loader";

/**
 * macOS-only integration test guarding the read-side compatibility
 * between `parsePfx` and the PFX `aspnetcore`'s `MacOSCertificateManager.
 * SaveCertificateCore` writes to disk at
 * `~/.aspnet/dev-certs/https/aspnetcore-localhost-{thumbprint}.pfx`.
 *
 * The cache file is produced by `dotnet dev-certs https` (no flags) —
 * the writer calls `certificate.Export(X509ContentType.Pfx)` with no
 * password. On every currently-supported .NET SDK that path emits
 * legacy `pbeWithSHA1And3-KeyTripleDES-CBC` (OID 1.2.840.113549.1.12.1.3)
 * + SHA-1, 2000 iterations. We need our parser to read this; the
 * narrow legacy-PBE handler in `pkcs12LegacyPbe.ts` exists exactly for
 * this case.
 *
 * Two things this test pins:
 *
 *   1. The cache file loads via `parsePfx` — Kestrel discovery, the
 *      VS Code host extension's read path, the workspace-extension's
 *      cert push, and anything else that goes through `parsePfx` keeps
 *      working as long as this passes.
 *   2. The on-disk PBE algorithm OID is the one our legacy handler is
 *      designed for. When aspnetcore eventually switches the macOS
 *      writer to `ExportPkcs12(PbeParameters(Aes256Cbc, …))` and ships
 *      PBES2 instead — the day this OID flips — the second assertion
 *      fails loudly and tells the next maintainer "the legacy 3DES
 *      handler in `pkcs12LegacyPbe.ts` can now be removed; see its
 *      removal checklist." That's the only way we'll know the
 *      workaround has aged out without monitoring upstream by hand.
 *
 * Both observations require running against a real dotnet on a real
 * macOS host; the test self-skips elsewhere.
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

// OIDs we recognize at the EncryptedData layer of the PKCS#12. Any
// other value means the writer started emitting a format we haven't
// catalogued; the test fails so the discrepancy is investigated.
const OID_PBE_3DES_SHA1 = "1.2.840.113549.1.12.1.3";
const OID_PBES2 = "1.2.840.113549.1.5.13";

let cachePfxPath: string;
let loadResult:
  | { kind: "ok"; thumbprint: string; hasKey: boolean }
  | { kind: "err"; message: string };
let observedPbeOid: string | null = null;

beforeAll(async () => {
  if (!ready) return;

  // 60s timeout because first-run cert generation can be slow on cold
  // CI runners. We use the real `$HOME` deliberately: macOS keychain
  // APIs resolve the login keychain via `$HOME/Library/Keychains/`
  // and `dotnet dev-certs` fails before it ever writes the disk
  // cache if HOME points at a tmpdir with no keychain.
  execFileSync("dotnet", ["dev-certs", "https"], {
    timeout: 60_000,
    stdio: "pipe",
  });

  const home = os.homedir();
  const cacheDir = path.join(home, ".aspnet", "dev-certs", "https");
  if (!fs.existsSync(cacheDir)) {
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

  observedPbeOid = await inspectFirstEncryptedDataOid(cachePfxPath);

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

// No afterAll cleanup — we wrote to the runner's real `~/.aspnet/dev-certs/
// https/` and login keychain. Both are owned by the ephemeral CI runner
// VM; trying to scrub them would mostly just hide our footprint from a
// follow-up investigation if the next run sees stale state.

describe.skipIf(!ready)(
  "aspnetcore macOS PFX format compatibility",
  () => {
    it("parsePfx loads aspnetcore's macOS disk-cache PFX", () => {
      // Diagnostic line carries the resolved path AND the observed PBE
      // OID so CI logs always show the discrepancy at-a-glance even
      // when the assertion passes. Stderr (not console.log) keeps the
      // codebase's no-console lint rule happy.
      process.stderr.write(
        `[macos-pfx] dotnet major: ${dotnetMajor}, cache: ${cachePfxPath}, ` +
          `observedPbeOid: ${observedPbeOid ?? "(unknown)"}, ` +
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

    it("aspnetcore is still emitting the legacy 3DES PBE algorithm we expect", () => {
      // This assertion exists to fire on a SUCCESS event from
      // aspnetcore's perspective — when they swap the macOS writer
      // over to `ExportPkcs12(PbeParameters(Aes256Cbc, ...))` and the
      // disk cache starts coming out as PBES2. When that day arrives,
      // this test goes red; the failure message is the next
      // maintainer's signal to clean up the legacy code:
      //
      //   - `src/shared/src/cert/pkcs12LegacyPbe.ts` can be deleted
      //     (follow its removal checklist).
      //   - The OID can return to `REJECTED_LEGACY_PBE_NAMES` in
      //     `pfx.ts`.
      //   - This very assertion gets flipped to expect PBES2 (or just
      //     deleted, depending on whether the codebase still needs
      //     to know).
      if (observedPbeOid === OID_PBES2) {
        throw new Error(
          "aspnetcore's macOS PFX writer appears to have switched to PBES2 " +
            "(OID 1.2.840.113549.1.5.13). The legacy 3DES handler in " +
            "src/shared/src/cert/pkcs12LegacyPbe.ts is no longer needed and " +
            "can be removed — see its docstring for the removal checklist."
        );
      }
      expect(observedPbeOid).toBe(OID_PBE_3DES_SHA1);
    });
  }
);

/**
 * Pull the encryption algorithm OID off the first `EncryptedData`
 * `ContentInfo` inside the PFX's `authenticatedSafe`. That's the
 * algorithm protecting the cert bag, which is what `pkcs12LegacyPbe.ts`
 * has to know how to decrypt.
 *
 * Walks pkijs's parsed structure directly rather than going through
 * `parsePfx` so it works regardless of whether the legacy handler can
 * decode the file — the OID is observable from the headers alone, no
 * password needed. `parseInternalValues` populates `pfx.parsedValue`;
 * `checkIntegrity: false` skips the HMAC step (which `parsePfx` itself
 * skips for the same reason — pkijs's MAC verification disagrees with
 * .NET's empty-password convention).
 *
 * Returns null if the structure doesn't contain an `EncryptedData`
 * (`Data`-typed contents are unencrypted, no OID to report).
 */
async function inspectFirstEncryptedDataOid(
  pfxPath: string
): Promise<string | null> {
  const bytes = fs.readFileSync(pfxPath);
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  const pfx = pkijs.PFX.fromBER(ab);
  await pfx.parseInternalValues({
    password: new ArrayBuffer(0),
    checkIntegrity: false,
  });
  const authSafe = pfx.parsedValue?.authenticatedSafe;
  if (!authSafe) return null;
  for (const contentInfo of authSafe.safeContents) {
    // 1.2.840.113549.1.7.6 = pkcs-7-encryptedData
    if (contentInfo.contentType !== "1.2.840.113549.1.7.6") continue;
    const encryptedData = new pkijs.EncryptedData({
      schema: contentInfo.content,
    });
    return encryptedData.encryptedContentInfo.contentEncryptionAlgorithm
      .algorithmId;
  }
  return null;
}
