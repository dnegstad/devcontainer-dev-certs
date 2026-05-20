import { describe, it, expect, beforeEach } from "vitest";
import { initLogger } from "@devcontainer-dev-certs/shared";
import { logMessages } from "./__mocks__/vscode";
import { selectBestDevCert, type UsableDevCert } from "../src/platform/baseStore";
import { generateCertificate } from "../src/cert/generator";

initLogger("test");

async function makeCert(
  notBefore: Date,
  notAfter: Date
): Promise<UsableDevCert> {
  const { cert, key, thumbprint } = await generateCertificate(notBefore, notAfter);
  return { cert, key, thumbprint };
}

describe("selectBestDevCert", () => {
  beforeEach(() => {
    logMessages.length = 0;
  });

  it("returns null for an empty list", () => {
    const result = selectBestDevCert([], "test-ctx");
    expect(result).toBeNull();
    expect(logMessages).toHaveLength(0);
  });

  it("returns the single candidate without logging", async () => {
    const now = new Date();
    const exp = new Date(now.getTime() + 365 * 86400 * 1000);
    const c = await makeCert(now, exp);
    const result = selectBestDevCert([c], "test-ctx");
    expect(result).toBe(c);
    expect(logMessages).toHaveLength(0);
  });

  it("logs the multi-candidate warning when more than one candidate is present", async () => {
    const now = new Date();
    const expA = new Date(now.getTime() + 100 * 86400 * 1000);
    const expB = new Date(now.getTime() + 200 * 86400 * 1000);
    const a = await makeCert(now, expA);
    const b = await makeCert(now, expB);

    const result = selectBestDevCert([a, b], "Windows CurrentUser\\My");
    // Both certs have the same (current) version — tiebreaker is later notAfter.
    expect(result).toBe(b);

    expect(logMessages).toHaveLength(1);
    const msg = logMessages[0];
    expect(msg).toContain("Multiple valid ASP.NET dev certs");
    expect(msg).toContain("Windows CurrentUser\\My");
    expect(msg).toContain(`selected ${b.thumbprint}`);
    expect(msg).toContain("[selected]");
    expect(msg).toContain("[skipped]");
    expect(msg).toContain(`thumbprint=${b.thumbprint}`);
    expect(msg).toContain(`thumbprint=${a.thumbprint}`);
  });

  it("picks the later notAfter when versions are equal", async () => {
    const now = new Date();
    const expA = new Date(now.getTime() + 50 * 86400 * 1000);
    const expB = new Date(now.getTime() + 150 * 86400 * 1000);
    const a = await makeCert(now, expA);
    const b = await makeCert(now, expB);

    expect(selectBestDevCert([a, b], "ctx")).toBe(b);
    logMessages.length = 0;
    expect(selectBestDevCert([b, a], "ctx")).toBe(b);
  });

  it("is deterministic regardless of input order", async () => {
    const now = new Date();
    const exp1 = new Date(now.getTime() + 100 * 86400 * 1000);
    const exp2 = new Date(now.getTime() + 200 * 86400 * 1000);
    const exp3 = new Date(now.getTime() + 300 * 86400 * 1000);
    const c1 = await makeCert(now, exp1);
    const c2 = await makeCert(now, exp2);
    const c3 = await makeCert(now, exp3);

    const orderings = [
      [c1, c2, c3],
      [c3, c2, c1],
      [c2, c1, c3],
      [c2, c3, c1],
    ];
    for (const ordering of orderings) {
      const r = selectBestDevCert(ordering, "ctx");
      expect(r).toBe(c3);
    }
  });
});
