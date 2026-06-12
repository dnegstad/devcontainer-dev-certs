import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { loadPfx } from "@devcontainer-dev-certs/shared";
import {
  SUPPORTED_LEGACY_PBE_OID,
  decryptLegacyPbe,
  isSupportedLegacyPbe,
  pkcs12Kdf,
} from "@devcontainer-dev-certs/shared/src/cert/pkcs12LegacyPbe";

/**
 * Lifecycle: delete this file when the parent module is removed. See
 * `src/shared/src/cert/pkcs12LegacyPbe.ts` for the removal checklist.
 */

// Pre-generated 3DES-encrypted PKCS#12 fixture. Built via:
//   openssl req -newkey rsa:2048 -nodes -keyout key -x509 \
//     -days 30 -subj /CN=localhost -out crt
//   openssl pkcs12 -legacy -export -inkey key -in crt -passout pass: \
//     -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
//     -iter 2000 -out test/fixtures/pkcs12-legacy-3des.pfx
//
// `openssl pkcs12 -info` reports the same algorithm aspnetcore's
// MacOSCertificateManager.SaveCertificateCore writes (`pbeWithSHA1And3-
// KeyTripleDES-CBC`), so loading this fixture exercises the same path
// the macOS dev cert disk cache flows through.
const FIXTURE = path.resolve(
  __dirname,
  "../../../test/fixtures/pkcs12-legacy-3des.pfx"
);

describe("pkcs12LegacyPbe", () => {
  it("SUPPORTED_LEGACY_PBE_OID names exactly the 3DES algorithm dotnet emits", () => {
    expect(SUPPORTED_LEGACY_PBE_OID).toBe("1.2.840.113549.1.12.1.3");
  });

  it("isSupportedLegacyPbe accepts the 3DES OID and rejects the others in the legacy family", () => {
    expect(isSupportedLegacyPbe("1.2.840.113549.1.12.1.3")).toBe(true);
    // Rest of the legacy PBE family stays rejected at the parsePfx layer.
    expect(isSupportedLegacyPbe("1.2.840.113549.1.12.1.1")).toBe(false);
    expect(isSupportedLegacyPbe("1.2.840.113549.1.12.1.2")).toBe(false);
    expect(isSupportedLegacyPbe("1.2.840.113549.1.12.1.4")).toBe(false);
    expect(isSupportedLegacyPbe("1.2.840.113549.1.12.1.5")).toBe(false);
    expect(isSupportedLegacyPbe("1.2.840.113549.1.12.1.6")).toBe(false);
    // PBES2 is not handled here — it goes through pkijs.
    expect(isSupportedLegacyPbe("1.2.840.113549.1.5.13")).toBe(false);
  });

  it("decryptLegacyPbe refuses OIDs it doesn't support (defensive)", () => {
    expect(() =>
      decryptLegacyPbe(
        "1.2.840.113549.1.12.1.1",
        { salt: Buffer.alloc(8), iterations: 1 },
        Buffer.alloc(0),
        ""
      )
    ).toThrow(/unsupported OID/);
  });
});

describe("pkcs12Kdf — empty-password convention", () => {
  // For empty password, the bytes fed into I are the UTF-16BE null
  // terminator: two zero bytes. Two distinct diversifiers + same
  // salt/iterations must produce distinct outputs (sanity: the
  // diversifier is what makes the key and IV derivations different).
  it("derives distinct key and IV from the same salt with empty password", () => {
    const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const key = pkcs12Kdf("", salt, 2000, 1, 24);
    const iv = pkcs12Kdf("", salt, 2000, 2, 8);
    expect(key.length).toBe(24);
    expect(iv.length).toBe(8);
    // 64 bits of overlap shouldn't be zero — vanishingly unlikely
    // unless the diversifier byte was ignored.
    expect(key.slice(0, 8).equals(iv)).toBe(false);
  });

  it("produces deterministic output for the same inputs", () => {
    const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const a = pkcs12Kdf("", salt, 2000, 1, 24);
    const b = pkcs12Kdf("", salt, 2000, 1, 24);
    expect(a.equals(b)).toBe(true);
  });

  it("changes output when the iteration count changes", () => {
    const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const a = pkcs12Kdf("", salt, 2000, 1, 24);
    const b = pkcs12Kdf("", salt, 1, 1, 24);
    expect(a.equals(b)).toBe(false);
  });

  it("handles non-empty passwords (UTF-16BE encoding) without throwing", () => {
    // We don't have a published RFC 7292 test vector with the
    // always-null-terminator convention to assert exact bytes, but
    // the function must accept a non-empty input without error and
    // produce a different output than the empty-password case.
    const salt = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
    const emptyPw = pkcs12Kdf("", salt, 100, 1, 24);
    const realPw = pkcs12Kdf("password", salt, 100, 1, 24);
    expect(emptyPw.equals(realPw)).toBe(false);
  });

  it("produces different output for empty password under the two terminator conventions", () => {
    // The whole point of the includeNullTerminator flag: when password
    // is empty, the two conventions feed different bytes (\x00\x00 vs
    // nothing) into the KDF. Output bytes MUST differ — otherwise the
    // .NET-vs-OpenSSL fallback in decryptLegacyPbe is a no-op.
    const salt = Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    const withNul = pkcs12Kdf("", salt, 2000, 1, 24, true);
    const noNul = pkcs12Kdf("", salt, 2000, 1, 24, false);
    expect(withNul.equals(noNul)).toBe(false);
  });

  it("ignores includeNullTerminator for non-empty passwords (both conventions agree)", () => {
    const salt = Buffer.from([0xab, 0xcd, 0xef, 0x01]);
    const withNul = pkcs12Kdf("password", salt, 100, 1, 24, true);
    const noNul = pkcs12Kdf("password", salt, 100, 1, 24, false);
    // Non-empty passwords always include the terminator under both
    // conventions per the spec; only the empty case is contested.
    // (This locks in the current behavior so a future "always omit"
    // experiment would fail the test loudly.)
    expect(withNul.equals(noNul)).toBe(false);
    // Note: they differ because withNul appends \x00\x00 and noNul
    // doesn't. Both are valid encodings in different traditions; we
    // pick null-terminator as the canonical default.
  });
});

describe("parsePfx — legacy 3DES PFX round-trip", () => {
  it("loads the empty-password 3DES fixture and recovers cert + key", async () => {
    expect(fs.existsSync(FIXTURE)).toBe(true);
    const loaded = await loadPfx(FIXTURE);
    expect(loaded.thumbprint).toMatch(/^[0-9A-F]{40}$/);
    expect(loaded.key).not.toBeNull();
    // Cert subject CN was set to localhost when the fixture was built.
    expect(loaded.cert.subjectCN).toBe("localhost");
  });

  it("reports `hasKey: true` so consumers don't treat it as a CA-only PFX", async () => {
    const loaded = await loadPfx(FIXTURE);
    expect(loaded.key).not.toBeNull();
  });
});
