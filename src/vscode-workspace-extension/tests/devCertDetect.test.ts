import { describe, it, expect } from "vitest";
import {
  ASPNET_HTTPS_OID_DER,
  isDotNetDevCertPfx,
} from "../src/util/devCertDetect";

describe("isDotNetDevCertPfx", () => {
  it("returns true when the OID byte sequence appears anywhere in the buffer", () => {
    const buf = Buffer.concat([
      Buffer.from([0x00, 0x01, 0x02]),
      ASPNET_HTTPS_OID_DER,
      Buffer.from([0xff, 0xfe]),
    ]);
    expect(isDotNetDevCertPfx(buf)).toBe(true);
  });

  it("returns false when the OID is absent", () => {
    expect(isDotNetDevCertPfx(Buffer.from([0xde, 0xad, 0xbe, 0xef]))).toBe(false);
  });

  it("returns false on an empty buffer", () => {
    expect(isDotNetDevCertPfx(Buffer.alloc(0))).toBe(false);
  });

  it("returns false for a partial / truncated OID match", () => {
    // First 6 bytes of the OID only — Buffer.includes must not match this.
    const partial = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04]);
    expect(isDotNetDevCertPfx(partial)).toBe(false);
  });

  it("encodes the documented 12-byte OID DER", () => {
    expect(ASPNET_HTTPS_OID_DER.length).toBe(12);
    expect(Array.from(ASPNET_HTTPS_OID_DER)).toEqual([
      0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x54, 0x01, 0x01,
    ]);
  });
});
