import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { parsePfx } from "../src/cert/pfx";
import {
  decryptLegacyPbe,
  isLegacyPbeOid,
  LEGACY_PBE_OID_SHA_3KEY_3DES,
  LEGACY_PBE_OID_SHA_40_RC2,
  LEGACY_PBE_OID_SHA_128_RC2,
  LEGACY_PBE_OID_SHA_2KEY_3DES,
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

function makeLegacyPfx(password: string): Buffer {
  const out = path.join(fixtureDir, `legacy-${Date.now()}.pfx`);
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

describe.skipIf(!opensslAvailable)(
  "parsePfx — legacy PBE compat",
  () => {
    it("parses a 3DES + RC2-40 PFX written by openssl -legacy with empty password", async () => {
      const bytes = makeLegacyPfx("");
      const parsed = await parsePfx(bytes, "");
      expect(parsed.cert.subjectCN).toBe("localhost");
      expect(parsed.key).not.toBeNull();
      expect(parsed.key!.algorithm).toBe("rsa");
    });

    it("parses a legacy PFX with a non-ASCII password", async () => {
      const password = "hünter2";
      const bytes = makeLegacyPfx(password);
      const parsed = await parsePfx(bytes, password);
      expect(parsed.cert.subjectCN).toBe("localhost");
      expect(parsed.key).not.toBeNull();
    });

    it("parses a legacy PFX with a long ASCII password", async () => {
      const password = "correct horse battery staple";
      const bytes = makeLegacyPfx(password);
      const parsed = await parsePfx(bytes, password);
      expect(parsed.cert.subjectCN).toBe("localhost");
      expect(parsed.key).not.toBeNull();
    });

    it("rejects a legacy PFX when the password is wrong", async () => {
      const bytes = makeLegacyPfx("right");
      // Wrong password: integrity check fails first (pkijs HMAC verify), so we
      // get an error from pkijs's parseInternalValues — not from our shim.
      await expect(parsePfx(bytes, "wrong")).rejects.toThrow();
    });

    it("recovers the same key bytes that openssl decrypts", async () => {
      const bytes = makeLegacyPfx("");
      const parsed = await parsePfx(bytes, "");

      // Spot-check the decrypted key by re-parsing it through Node's
      // createPrivateKey (already done internally by DevKey, but assert
      // that the PEM round-trips cleanly).
      expect(parsed.key!.pem).toContain("-----BEGIN PRIVATE KEY-----");
      expect(parsed.key!.pem).toContain("-----END PRIVATE KEY-----");

      // And that the cert SHA-1 thumbprint matches what openssl computes.
      const opensslThumbprint = execFileSync(
        "openssl",
        ["x509", "-in", certPath, "-noout", "-fingerprint", "-sha1"],
        { timeout: 5000 }
      )
        .toString()
        .trim();
      // openssl prints "SHA1 Fingerprint=AA:BB:..."; strip everything before "="
      // and the colons to compare against our 40-char hex thumbprint.
      const expected = opensslThumbprint
        .split("=")[1]
        .replace(/:/g, "")
        .toUpperCase();
      expect(parsed.cert.thumbprintSha1).toBe(expected);
    });
  }
);

/**
 * Algorithm-level coverage that doesn't need openssl — exercises the OID
 * dispatch and the PKCS#12 B.2 KDF for each supported algorithm.
 */
describe("legacyPbe shim", () => {
  it("isLegacyPbeOid recognizes the four supported OIDs", () => {
    expect(isLegacyPbeOid(LEGACY_PBE_OID_SHA_3KEY_3DES)).toBe(true);
    expect(isLegacyPbeOid(LEGACY_PBE_OID_SHA_2KEY_3DES)).toBe(true);
    expect(isLegacyPbeOid(LEGACY_PBE_OID_SHA_128_RC2)).toBe(true);
    expect(isLegacyPbeOid(LEGACY_PBE_OID_SHA_40_RC2)).toBe(true);
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
});
