import { describe, it, expect, beforeEach } from "vitest";
import { initLogger } from "@devcontainer-dev-certs/shared";
import { logMessages } from "./__mocks__/vscode";
import { classifyCandidate } from "../src/platform/baseStore";
import { generateCertificate } from "../src/cert/generator";
import { DevKey, DevCert } from "../src/cert/types";
import { X509CertificateGenerator, cryptoProvider } from "@peculiar/x509";
import { webcrypto } from "node:crypto";

initLogger("test");

cryptoProvider.set(webcrypto as unknown as Crypto);

async function makeValidDevCert() {
  const now = new Date();
  const exp = new Date(now.getTime() + 365 * 86400 * 1000);
  return generateCertificate(now, exp);
}

async function makeBogusLocalhostCert(): Promise<{
  cert: DevCert;
  key: DevKey;
}> {
  // Make a CN=localhost cert that LACKS the ASPNET_HTTPS_OID extension —
  // not a dev cert per isValidDevCert, should classify as silent null.
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
  const now = new Date();
  const exp = new Date(now.getTime() + 30 * 86400 * 1000);
  const cert = await X509CertificateGenerator.create({
    serialNumber: "01",
    subject: "CN=localhost",
    issuer: "CN=localhost",
    notBefore: now,
    notAfter: exp,
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    extensions: [],
  });
  return {
    cert: new DevCert(cert),
    key: await DevKey.fromCryptoKey(keyPair.privateKey),
  };
}

describe("classifyCandidate", () => {
  beforeEach(() => {
    logMessages.length = 0;
  });

  it("returns usable for a valid cert + key (no log)", async () => {
    const { cert, key, thumbprint } = await makeValidDevCert();
    const result = classifyCandidate({
      kind: "loaded",
      source: "/path/to/file.pfx",
      loaded: { cert, key, thumbprint },
    });
    expect(result?.kind).toBe("usable");
    expect(logMessages).toHaveLength(0);
  });

  it("returns null silently for a cert that doesn't pass isValidDevCert", async () => {
    const { cert, key } = await makeBogusLocalhostCert();
    const result = classifyCandidate({
      kind: "loaded",
      source: "/path/to/file.pfx",
      loaded: { cert, key, thumbprint: cert.thumbprintSha1 },
    });
    expect(result).toBeNull();
    expect(logMessages).toHaveLength(0);
  });

  it("returns skipped + logs when a valid dev cert has no private key", async () => {
    const { cert, thumbprint } = await makeValidDevCert();
    const result = classifyCandidate({
      kind: "loaded",
      source: "/aspnet/dev-certs/https/aspnetcore-localhost-X.pfx",
      loaded: { cert, key: null, thumbprint },
    });
    expect(result?.kind).toBe("skipped");
    expect(logMessages).toHaveLength(1);
    expect(logMessages[0]).toContain("certificate without matching private key");
    expect(logMessages[0]).toContain(thumbprint);
    expect(logMessages[0]).toContain("subjectCN=localhost");
  });

  it("returns skipped + logs on parse failure for canonical filenames", () => {
    const result = classifyCandidate({
      kind: "parseFailure",
      source: "/aspnet/dev-certs/https/aspnetcore-localhost-ABCDEF.pfx",
      thumbprintHint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
    });
    expect(result?.kind).toBe("skipped");
    expect(logMessages).toHaveLength(1);
    expect(logMessages[0]).toContain("failed to parse PFX");
  });

  it("returns null silently on parse failure when no canonical thumbprint hint", () => {
    const result = classifyCandidate({
      kind: "parseFailure",
      source: "/some/dir/random.pfx",
      thumbprintHint: null,
    });
    expect(result).toBeNull();
    expect(logMessages).toHaveLength(0);
  });

  it("returns skipped + logs for forcedSkip with metadata", () => {
    const result = classifyCandidate({
      kind: "forcedSkip",
      source: "macOS login keychain",
      reason: "present in keychain but no matching PFX on disk",
      metadata: {
        thumbprint: "ABC123",
        subjectCN: "localhost",
        version: 6,
        notBefore: new Date("2026-01-01T00:00:00Z"),
        notAfter: new Date("2027-01-01T00:00:00Z"),
      },
    });
    expect(result?.kind).toBe("skipped");
    expect(logMessages).toHaveLength(1);
    expect(logMessages[0]).toContain("macOS login keychain");
    expect(logMessages[0]).toContain("present in keychain");
    expect(logMessages[0]).toContain("subjectCN=localhost");
    expect(logMessages[0]).toContain("version=6");
    expect(logMessages[0]).toContain("notBefore=2026-01-01T00:00:00.000Z");
    expect(logMessages[0]).toContain("notAfter=2027-01-01T00:00:00.000Z");
  });
});
