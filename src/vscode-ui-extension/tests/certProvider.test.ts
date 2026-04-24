import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { CertProvider } from "../src/certProvider";
import type { UserCertificateConfig } from "../src/certProvider";
import { exportPem } from "../src/cert/exporter";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";
import type { CertManager } from "../src/cert/manager";
import {
  __resetConfig,
  __setConfig,
  errorMessages,
  warningMessages,
} from "./__mocks__/vscode";

function makeValidCert() {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

function makeExpiredCert() {
  const past = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const expiry = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000);
  return generateCertificate(past, expiry);
}

interface Tmp {
  dir: string;
  certPath: string;
  keyPath: string;
}

function writeCertFiles(cert: forge.pki.Certificate, key: forge.pki.rsa.PrivateKey): Tmp {
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
    exportCert: vi.fn(
      async (format: "pfx" | "pem" | "root-pfx", outputDir: string) => {
        fs.mkdirSync(outputDir, { recursive: true });
        const fakeCert = makeValidCert();
        if (format === "pem") {
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev.pem"),
            forge.pki.certificateToPem(fakeCert.cert)
          );
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev.key"),
            forge.pki.privateKeyToPem(fakeCert.key)
          );
        } else if (format === "pfx") {
          fs.writeFileSync(path.join(outputDir, "aspnetcore-dev.pfx"), Buffer.from("fake-pfx"));
        } else {
          fs.writeFileSync(path.join(outputDir, "aspnetcore-dev-root.pfx"), Buffer.from("fake-root"));
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
    const { thumbprint } = makeValidCert();
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
    const { cert, key, thumbprint } = makeValidCert();
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
    const { cert, key } = makeValidCert();
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
    const { cert, key } = makeExpiredCert();
    const tmp = writeCertFiles(cert, key);
    cleanupDirs.push(tmp.dir);

    const { cert: validCert, key: validKey } = makeValidCert();
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
    // Call again to check the warning isn't duplicated on cache hit.
    await provider.getAllCertMaterial({
      includeDotNetDev: false,
      includeUserCerts: true,
    });

    const expiryWarnings = warningMessages.filter((m) =>
      m.includes("expired")
    );
    expect(expiryWarnings).toHaveLength(1);
    expect(expiryWarnings[0]).toContain("'expired'");
    // The fresh cert should not have generated a warning
    expect(warningMessages.some((m) => m.includes("'fresh'"))).toBe(false);
  });

  it("rejects userCertificates entries with traversal-capable names", async () => {
    const { cert, key } = makeValidCert();
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
    const { cert, key } = makeValidCert();
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
});
