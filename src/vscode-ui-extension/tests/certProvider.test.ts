import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { CertProvider } from "../src/certProvider";
import type { UserCertificateConfig } from "../src/certProvider";
import {
  exportPem,
  generateCertificate,
  buildPfx,
  parsePfx,
  VALIDITY_DAYS,
} from "@devcontainer-dev-certs/shared";
import type {
  CertManager,
  DevCert,
  DevKey,
} from "@devcontainer-dev-certs/shared";
import { __resetConfig, __setConfig, errorMessages, warningMessages, } from "./__mocks__/vscode";

async function makeValidCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

async function makeExpiredCert(): ReturnType<typeof generateCertificate> {
  const past = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const expiry = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000);
  return generateCertificate(past, expiry);
}

interface Tmp {
  dir: string;
  certPath: string;
  keyPath: string;
}

function writeCertFiles(cert: DevCert, key: DevKey): Tmp {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-cp-test-"));
  const { certPath, keyPath } = exportPem(cert, key, dir);
  return { dir, certPath, keyPath };
}

function mockManager(thumbprint: string): CertManager {
  const status = {
    exists: true,
    isTrusted: true,
    thumbprint,
    notBefore: null,
    notAfter: null,
    version: 1,
  };
  return {
    check: vi.fn(async () => status),
    trust: vi.fn(async () => {}),
    // Matches the store's thumbprint, so the provider's staleness check
    // (loadedThumbprint vs check()) sees a consistent manager and does
    // not invalidate.
    loadedThumbprint: thumbprint,
    invalidateLoadedCert: vi.fn(),
    exportCert: vi.fn(
      async (format: "pfx" | "pem" | "root-pfx", outputDir: string) => {
        fs.mkdirSync(outputDir, { recursive: true });
        const fakeCert = await makeValidCert();
        if (format === "pem") {
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev.pem"),
            fakeCert.cert.pem
          );
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev.key"),
            fakeCert.key.pem
          );
        } else if (format === "pfx") {
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev.pfx"),
            Buffer.from("fake-pfx")
          );
        } else {
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev-root.pfx"),
            Buffer.from("fake-root")
          );
        }
      }
    ),
  } as unknown as CertManager;
}

const cleanupDirs: string[] = [];

beforeEach(() => {
  __resetConfig();
});

afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

describe("CertProvider.getAllCertMaterial", () => {
  it("returns dotnet-dev cert only when includeUserCerts=false", async () => {
    const { thumbprint } = await makeValidCert();
    const provider = new CertProvider(mockManager(thumbprint));

    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: true,
      includeUserCerts: false,
    });
    expect(bundle.certs).toHaveLength(1);
    expect(bundle.certs[0].kind).toBe("dotnet-dev");
    expect(bundle.certs[0].name).toBe("aspnetcore-dev");
    expect(bundle.certs[0].trustInContainer).toBe(true);
  });

  it("returns user certs only when includeDotNetDev=false", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    const userConfigs: UserCertificateConfig[] = [
      {
        name: "corp-ca",
        pemCertPath: tmp.certPath,
        pemKeyPath: tmp.keyPath,
      },
    ];
    __setConfig("devcontainerDevCerts", { userCertificates: userConfigs });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.certs).toHaveLength(1);
    expect(bundle.certs[0].kind).toBe("user");
    expect(bundle.certs[0].name).toBe("corp-ca");
    expect(bundle.certs[0].thumbprint).toBe(thumbprint);
    expect(bundle.certs[0].pfxBase64).toBeTruthy();
    expect(bundle.certs[0].pemKeyBase64).toBeTruthy();
    expect(bundle.certs[0].rootPfxBase64).toBeTruthy();
  });

  it("returns both dotnet-dev and user certs when both enabled", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        {
          name: "corp-ca",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: true,
      includeUserCerts: true,
    });

    expect(bundle.certs).toHaveLength(2);
    expect(bundle.certs.map((c) => c.kind).sort()).toEqual([
      "dotnet-dev",
      "user",
    ]);
  });

  it("returns empty bundle when everything is disabled", async () => {
    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: false,
    });
    expect(bundle.certs).toHaveLength(0);
  });

  it("honors generateDotNetCert=false host setting", async () => {
    __setConfig("devcontainerDevCerts", { generateDotNetCert: false });
    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: true,
      includeUserCerts: false,
    });
    expect(bundle.certs).toHaveLength(0);
  });

  it("emits a single expiry warning per expired user cert", async () => {
    const { cert, key } = await makeExpiredCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    const { cert: validCert, key: validKey } = await makeValidCert();
    const tmpValid = writeCertFiles(validCert, validKey);
    cleanupDirs.push(tmpValid.dir);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        {
          name: "expired",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
        },
        {
          name: "fresh",
          pemCertPath: tmpValid.certPath,
          pemKeyPath: tmpValid.keyPath,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    const expiryWarnings = warningMessages.filter((m) =>
      m.includes("expired")
    );
    expect(expiryWarnings).toHaveLength(1);
    expect(expiryWarnings[0]).toContain("'expired'");
    expect(warningMessages.some((m) => m.includes("'fresh'"))).toBe(false);
  });

  it("rejects userCertificates entries with traversal-capable names", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        {
          name: "../evil",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.certs).toHaveLength(0);
    expect(
      errorMessages.some((m) => m.includes("Invalid certificate name"))
    ).toBe(true);
  });

  it("caches user certs across calls", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        { name: "corp-ca", pemCertPath: tmp.certPath, pemKeyPath: tmp.keyPath },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const first = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    const second = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    expect(first.certs[0]).toBe(second.certs[0]);
  });

  it("synthesizes a passwordless PFX for PEM-source certs with no pfxPassword", async () => {
    // The source PEM key file is unencrypted on disk; emitting a passwordless
    // PFX from it doesn't reduce the security posture (nothing to strip).
    // This differs from the PFX-source path, where an unset password would
    // mean the source file itself is passwordless.
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        { name: "synth", pemCertPath: tmp.certPath, pemKeyPath: tmp.keyPath },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.certs).toHaveLength(1);
    expect(bundle.certs[0].pfxBase64).toBeTruthy();
    const wireBytes = Buffer.from(bundle.certs[0].pfxBase64!, "base64");
    // Sanity: the bytes are a real PFX that opens with the empty password.
    const parsed = await parsePfx(wireBytes, "");
    expect(parsed.cert).toBeTruthy();
    expect(parsed.key).toBeTruthy();
  });

  it("respects installUserCertsToDotNetStore=true for user certs", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      installUserCertsToDotNetStore: true,
      userCertificates: [
        {
          name: "kept",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
          pfxPassword: "secret",
        },
        {
          name: "exempt",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
          pfxPassword: "secret",
          excludeFromDotNetStore: true,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    const kept = bundle.certs.find((c) => c.name === "kept")!;
    const exempt = bundle.certs.find((c) => c.name === "exempt")!;

    expect(kept.installToDotNetStore).toBe(true);
    expect(kept.dotNetStorePfxBase64).toBeTruthy();
    // The store copy MUST be distinct from pfxBase64 — the latter preserves
    // the user's password; the former is the consented passwordless copy.
    expect(kept.dotNetStorePfxBase64).not.toBe(kept.pfxBase64);

    expect(exempt.installToDotNetStore).toBe(false);
    expect(exempt.dotNetStorePfxBase64).toBeUndefined();
  });

  it("ignores excludeFromDotNetStore when the global setting is off", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      installUserCertsToDotNetStore: false,
      userCertificates: [
        {
          name: "noop",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
          pfxPassword: "secret",
          excludeFromDotNetStore: true,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.certs[0].installToDotNetStore).toBe(false);
    expect(bundle.certs[0].dotNetStorePfxBase64).toBeUndefined();
  });

  it("rebuilds cached material when the global store opt-in toggles", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    const userCertificates: UserCertificateConfig[] = [
      {
        name: "toggled",
        pemCertPath: tmp.certPath,
        pemKeyPath: tmp.keyPath,
        pfxPassword: "secret",
      },
    ];

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));

    __setConfig("devcontainerDevCerts", {
      installUserCertsToDotNetStore: false,
      userCertificates,
    });
    const off = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    expect(off.certs[0].installToDotNetStore).toBe(false);
    expect(off.certs[0].dotNetStorePfxBase64).toBeUndefined();

    __setConfig("devcontainerDevCerts", {
      installUserCertsToDotNetStore: true,
      userCertificates,
    });
    const on = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    expect(on.certs[0].installToDotNetStore).toBe(true);
    expect(on.certs[0].dotNetStorePfxBase64).toBeTruthy();
  });

  it("transmits PFX-source bytes verbatim on V3 without re-encoding", async () => {
    // Use a real PFX with a known password so we can prove the bytes
    // round-trip the V3 IPC unchanged — no decrypt/re-encrypt strip.
    // The V2 wire contract still forces passwordless bytes; that's the
    // tradeoff for keeping V2 consumers working.
    const { cert, key } = await makeValidCert();
    const password = "round-trip-secret";
    const sourceBytes = await buildPfx({ cert, key, password });

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-cp-pfx-"));
    cleanupDirs.push(dir);
    const pfxPath = path.join(dir, "source.pfx");
    fs.writeFileSync(pfxPath, sourceBytes);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        { name: "verbatim", pfxPath, pfxPassword: password },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const v3 = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    const v3Bytes = Buffer.from(v3.certs[0].pfxBase64!, "base64");
    expect(v3Bytes.equals(sourceBytes)).toBe(true);

    // V2 endpoint, by contrast, strips the password (passwordless wire
    // contract). The bytes differ, but still describe the same cert+key.
    const v2 = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    const v2Bytes = Buffer.from(v2.certs[0].pfxBase64!, "base64");
    expect(v2Bytes.equals(sourceBytes)).toBe(false);
    const v2Parsed = await parsePfx(v2Bytes, "");
    expect(v2Parsed.cert).toBeTruthy();
    expect(v2Parsed.key).toBeTruthy();
  });

  it("supports user certs with ECDSA keys", async () => {
    const now = new Date();
    const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const { cert, key, thumbprint } = await generateCertificate(now, expiry, {
      kind: "ec",
      namedCurve: "P-256",
    });
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      userCertificates: [
        { name: "ec-corp", pemCertPath: tmp.certPath, pemKeyPath: tmp.keyPath },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });
    expect(bundle.certs).toHaveLength(1);
    expect(bundle.certs[0].thumbprint).toBe(thumbprint);
  });
});

describe("CertProvider defaultKestrelCertificate", () => {
  it("attaches the pointer with name+password when the setting matches", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      defaultKestrelCertificate: "corp-ca",
      userCertificates: [
        {
          name: "corp-ca",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
          pfxPassword: "hunter2",
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.defaultKestrelCert).toEqual({
      name: "corp-ca",
      password: "hunter2",
    });
    // The pointer is bundle-level; per-cert material is untouched.
    expect(bundle.certs[0]).not.toHaveProperty("pfxPassword");
    expect(bundle.certs[0]).not.toHaveProperty("isDefaultKestrelCert");
  });

  it("omits password when the source entry has none", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      defaultKestrelCertificate: "no-pw",
      userCertificates: [
        {
          name: "no-pw",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.defaultKestrelCert).toEqual({ name: "no-pw" });
    expect(bundle.defaultKestrelCert?.password).toBeUndefined();
  });

  it("warns and omits the pointer when the setting names a missing cert", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      defaultKestrelCertificate: "does-not-exist",
      userCertificates: [
        {
          name: "corp-ca",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.defaultKestrelCert).toBeUndefined();
    expect(warningMessages.some((m) => m.includes("does-not-exist"))).toBe(
      true
    );
  });

  it("refuses to point at a CA-only entry (no private key)", async () => {
    const { cert } = await makeValidCert();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-ca-only-"));
    cleanupDirs.push(dir);
    const certPath = path.join(dir, "ca.pem");
    fs.writeFileSync(certPath, cert.pem);

    __setConfig("devcontainerDevCerts", {
      defaultKestrelCertificate: "ca-only",
      userCertificates: [
        { name: "ca-only", pemCertPath: certPath },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    expect(bundle.defaultKestrelCert).toBeUndefined();
    expect(
      warningMessages.some(
        (m) => m.includes("ca-only") && m.includes("no private key")
      )
    ).toBe(true);
  });

  it("refuses to target the dotnet-dev cert with a dedicated message (not the generic missing-entry one)", async () => {
    __setConfig("devcontainerDevCerts", {
      defaultKestrelCertificate: "aspnetcore-dev",
    });

    const provider = new CertProvider(mockManager("DEV-THUMB"));
    const bundle = await provider.getAllCertMaterialV3({
      includeDotNetDev: true,
      includeUserCerts: true,
    });

    expect(bundle.defaultKestrelCert).toBeUndefined();
    // The cert IS in the bundle — make sure we don't mislead the user
    // with the generic "no userCertificates entry with that name was
    // synced" warning. They get the dotnet-dev-specific guidance instead.
    expect(
      warningMessages.some((m) =>
        m.includes("no userCertificates entry with that name was synced")
      )
    ).toBe(false);
    expect(
      warningMessages.some(
        (m) =>
          m.includes("aspnetcore-dev") &&
          m.includes("auto-generated dotnet-dev certificate") &&
          m.includes("X509Store")
      )
    ).toBe(true);
  });

  it("is absent on the V2 endpoint (V3-only wire field)", async () => {
    const { cert, key } = await makeValidCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    __setConfig("devcontainerDevCerts", {
      defaultKestrelCertificate: "corp-ca",
      userCertificates: [
        {
          name: "corp-ca",
          pemCertPath: tmp.certPath,
          pemKeyPath: tmp.keyPath,
          pfxPassword: "hunter2",
        },
      ] satisfies UserCertificateConfig[],
    });

    const provider = new CertProvider(mockManager("DOTNET-THUMB"));
    const v2 = (await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    })) as unknown as Record<string, unknown>;
    expect(v2.defaultKestrelCert).toBeUndefined();
  });
});
