import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { parsePfx } from "../src/cert/pfx";
import {
  decryptLegacyPbe,
  isLegacyPbeOid,
  LEGACY_PBE_OID_SHA_128_RC2,
  LEGACY_PBE_OID_SHA_40_RC2,
} from "../src/cert/legacyPbe";

let opensslAvailable = false;
try {
  execFileSync("openssl", ["version"], { timeout: 5000 });
  opensslAvailable = true;
} catch {
  // openssl not available — legacy fixture tests are skipped.
}

let fixtureDir: string;
let certPath: string;
let keyPath: string;

/** Build PEM cert + key once for the suite; reused by every fixture. */
beforeAll(() => {
  if (!opensslAvailable) return;
  fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-legacy-pfx-"));
  certPath = path.join(fixtureDir, "cert.pem");
  keyPath = path.join(fixtureDir, "key.pem");
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=localhost",
    ],
    { timeout: 15000, stdio: "pipe" }
  );
});

afterAll(() => {
  if (fixtureDir) fs.rmSync(fixtureDir, { recursive: true, force: true });
});

/**
 * `openssl pkcs12 -export -legacy` writes a PFX with the cert bag wrapped
 * in `pbeWithSHAAnd40BitRC2-CBC` and the key bag wrapped in
 * `pbeWithSHAAnd3-KeyTripleDES-CBC`. We use it to exercise both the
 * legacy-RC2 cert-bag decryption (supported) and the 3DES key-bag
 * rejection (deliberately unsupported).
 */
function makeLegacyFullPfx(password: string): Buffer {
  const out = path.join(fixtureDir, `legacy-full-${Date.now()}.pfx`);
  execFileSync(
    "openssl",
    [
      "pkcs12",
      "-export",
      "-in",
      certPath,
      "-inkey",
      keyPath,
      "-out",
      out,
      "-passout",
      `pass:${password}`,
      "-legacy",
    ],
    { timeout: 15000, stdio: "pipe" }
  );
  const bytes = fs.readFileSync(out);
  fs.unlinkSync(out);
  return bytes;
}

/**
 * Cert-only legacy PFX (RC2-40 cert bag, no key bag) — what we get when
 * a user exports a CA cert with `openssl pkcs12 -nokeys -legacy`. This
 * is the only legacy-PFX layout the shim is designed to migrate.
 */
function makeLegacyCertOnlyPfx(password: string): Buffer {
  const out = path.join(fixtureDir, `legacy-ca-${Date.now()}.pfx`);
  execFileSync(
    "openssl",
    [
      "pkcs12",
      "-export",
      "-in",
      certPath,
      "-nokeys",
      "-out",
      out,
      "-passout",
      `pass:${password}`,
      "-legacy",
    ],
    { timeout: 15000, stdio: "pipe" }
  );
  const bytes = fs.readFileSync(out);
  fs.unlinkSync(out);
  return bytes;
}

describe.skipIf(!opensslAvailable)(
  "parsePfx — legacy PBE compat",
  () => {
    it("parses a CA-only legacy PFX (RC2-40 cert bag, no key)", async () => {
      const bytes = makeLegacyCertOnlyPfx("");
      const parsed = await parsePfx(bytes, "");
      expect(parsed.cert.subjectCN).toBe("localhost");
      expect(parsed.key).toBeNull();

      // Cross-check against openssl's own SHA-1 fingerprint so we know
      // we're actually decoding the right bytes, not just any bytes.
      const opensslThumbprint = execFileSync(
        "openssl",
        ["x509", "-in", certPath, "-noout", "-fingerprint", "-sha1"],
        { timeout: 5000 }
      )
        .toString()
        .trim();
      const expected = opensslThumbprint
        .split("=")[1]
        .replace(/:/g, "")
        .toUpperCase();
      expect(parsed.cert.thumbprintSha1).toBe(expected);
    });

    it("parses a CA-only legacy PFX with a non-ASCII password", async () => {
      const password = "hünter2";
      const bytes = makeLegacyCertOnlyPfx(password);
      const parsed = await parsePfx(bytes, password);
      expect(parsed.cert.subjectCN).toBe("localhost");
      expect(parsed.key).toBeNull();
    });

    it("rejects a CA-only legacy PFX when the password is wrong", async () => {
      const bytes = makeLegacyCertOnlyPfx("right");
      // pkijs's outer HMAC verify catches this before our shim ever runs,
      // so the failure mode is the same as for a modern PFX.
      await expect(parsePfx(bytes, "wrong")).rejects.toThrow();
    });

    it("rejects a legacy PFX whose key bag is encrypted with 3DES", async () => {
      const bytes = makeLegacyFullPfx("");
      // The cert bag (RC2-40) is decryptable, but the key bag (3DES) isn't —
      // by design. Surface a clear error rather than silently dropping
      // the key.
      await expect(parsePfx(bytes, "")).rejects.toThrow(
        /1\.2\.840\.113549\.1\.12\.1\.3/
      );
    });
  }
);

/**
 * Algorithm-level coverage that doesn't need openssl — exercises the OID
 * dispatch and the supported algorithms list.
 */
describe("legacyPbe shim", () => {
  it("isLegacyPbeOid recognizes the two supported OIDs", () => {
    expect(isLegacyPbeOid(LEGACY_PBE_OID_SHA_128_RC2)).toBe(true);
    expect(isLegacyPbeOid(LEGACY_PBE_OID_SHA_40_RC2)).toBe(true);
  });

  it("isLegacyPbeOid rejects 3DES-based PKCS#12 PBE OIDs", () => {
    // Deliberately unsupported — DES is not in scope for the shim.
    expect(isLegacyPbeOid("1.2.840.113549.1.12.1.3")).toBe(false);
    expect(isLegacyPbeOid("1.2.840.113549.1.12.1.4")).toBe(false);
  });

  it("isLegacyPbeOid rejects PBES2 and unrelated OIDs", () => {
    expect(isLegacyPbeOid("1.2.840.113549.1.5.13")).toBe(false); // PBES2
    expect(isLegacyPbeOid("1.2.840.113549.1.7.1")).toBe(false); // data
    expect(isLegacyPbeOid("not-an-oid")).toBe(false);
  });

  it("decryptLegacyPbe rejects unsupported OIDs", () => {
    expect(() =>
      decryptLegacyPbe(
        "1.2.840.113549.1.5.13",
        { salt: Buffer.alloc(8), iterations: 2048, password: "" },
        Buffer.alloc(16)
      )
    ).toThrow(/supported legacy PBE OID/i);
  });

  it("decryptLegacyPbe rejects 3DES OIDs (out of scope)", () => {
    expect(() =>
      decryptLegacyPbe(
        "1.2.840.113549.1.12.1.3",
        { salt: Buffer.alloc(8), iterations: 2048, password: "" },
        Buffer.alloc(16)
      )
    ).toThrow(/supported legacy PBE OID/i);
  });
});
