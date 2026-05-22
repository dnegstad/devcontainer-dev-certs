// @peculiar/x509 (transitively pulled in by the host-extension imports
// below) depends on tsyringe, which requires the reflect-metadata polyfill
// at module-load time. The UI extension carries the same import at its
// entry point.
import "reflect-metadata";

import { describe, it, expect, beforeAll } from "vitest";
import {
  ASPNET_HTTPS_OID_DER,
  scanPfxForDevCertOid,
} from "../src/util/pkcs12DevCertScan";

// Cross-package import: pull the host extension's PFX builder + dev-cert
// generator straight from source. The workspace and UI extensions share
// `node_modules` via the monorepo root, so pkijs/asn1js/@peculiar/x509
// resolve fine, and vitest compiles the TS at load time. Kept to test
// files only — production code never reaches across this boundary.
import { buildPfx } from "../../vscode-ui-extension/src/cert/pfx";
import { generateCertificate } from "../../vscode-ui-extension/src/cert/generator";
import { VALIDITY_DAYS } from "../../vscode-ui-extension/src/cert/properties";

describe("scanPfxForDevCertOid", () => {
  describe("plaintext / fast-path inputs", () => {
    it("returns true when the OID appears anywhere in the buffer", () => {
      const buf = Buffer.concat([
        Buffer.from([0x00, 0x01, 0x02]),
        ASPNET_HTTPS_OID_DER,
        Buffer.from([0xff]),
      ]);
      expect(scanPfxForDevCertOid(buf)).toBe(true);
    });

    it("returns false when the OID byte sequence is absent", () => {
      // One assertion covers every "fast-path miss" shape we care about:
      // empty input, a truncated OID prefix that mustn't match, and
      // unrelated bytes that don't even resemble a PFX.
      expect(scanPfxForDevCertOid(Buffer.alloc(0))).toBe(false);
      expect(
        scanPfxForDevCertOid(Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04]))
      ).toBe(false);
      expect(scanPfxForDevCertOid(Buffer.from("not a pfx, just text"))).toBe(false);
    });
  });

  describe("real PBES2 / PBKDF2-SHA-256 / AES-256-CBC PFX (host producer)", () => {
    // Building the cert via `generateCertificate` is slow (~1-2s for the
    // key gen) so we share the result across the cases below.
    let devPfx: Buffer;
    let thumbprint: string;

    beforeAll(async () => {
      const now = new Date();
      const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
      const dev = await generateCertificate(now, expiry);
      devPfx = await buildPfx({ cert: dev.cert, key: dev.key, password: "" });
      thumbprint = dev.cert.thumbprintSha1;
    }, 30_000);

    it("identifies a real host-built dev cert PFX (PBES2/AES-256-CBC, empty password)", () => {
      expect(scanPfxForDevCertOid(devPfx)).toBe(true);
      // Sanity check that the OID byte run is NOT present in plaintext —
      // i.e. we genuinely went through the decrypt path, not the fast path.
      // If this ever flips, our test is asserting the wrong thing.
      expect(devPfx.includes(ASPNET_HTTPS_OID_DER)).toBe(false);
      expect(thumbprint).toMatch(/^[A-F0-9]{40}$/);
    });

    it("returns false when the password is wrong (decrypt fails)", () => {
      // Empty password is the contract — anything else fails AES decryption
      // (padding mismatch) and we fail-closed without throwing.
      expect(scanPfxForDevCertOid(devPfx, "wrong-password")).toBe(false);
    });
  });

  describe("malformed / hostile inputs (must never throw)", () => {
    it("returns false when truncated mid-SEQUENCE", () => {
      // Tag 0x30 (SEQUENCE), long-form length claiming 0x1000 bytes that
      // aren't there.
      expect(
        scanPfxForDevCertOid(Buffer.from([0x30, 0x82, 0x10, 0x00, 0xff]))
      ).toBe(false);
    });

    it("returns false when version is not 3", () => {
      // SEQUENCE { INTEGER 1 (version 1, not PKCS#12) } — invalid PFX.
      expect(
        scanPfxForDevCertOid(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]))
      ).toBe(false);
    });

    it("returns false for indefinite-length BER (unsupported in DER PFXes)", () => {
      // Tag 0x30, length byte 0x80 = indefinite-length BER.
      expect(
        scanPfxForDevCertOid(Buffer.from([0x30, 0x80, 0x00, 0x00]))
      ).toBe(false);
    });
  });
});
