import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type * as Shared from "@devcontainer-dev-certs/shared";
import type { CertMaterialV3 } from "@devcontainer-dev-certs/shared";

// Sandbox the .NET store / trust-dir paths into per-test temp dirs so the
// real filesystem locations stay untouched.
let storeDir: string;
let rootStoreDir: string;
let trustDir: string;

vi.mock("@devcontainer-dev-certs/shared", async (importOriginal) => {
  const original = await importOriginal<typeof Shared>();
  return {
    ...original,
    getDotNetStorePath: () => storeDir,
    getDotNetRootStorePath: () => rootStoreDir,
    getOpenSslTrustDir: () => trustDir,
  };
});

import {
  installUserCert,
  installDotNetDevCert,
  isCertInstalled,
} from "../src/certInstaller";

const cleanupDirs: string[] = [];

beforeEach(() => {
  storeDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-store-"));
  rootStoreDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-root-"));
  trustDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-trust-"));
  cleanupDirs.push(storeDir, rootStoreDir, trustDir);
});

afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

function userMaterial(overrides: Partial<CertMaterialV3> = {}): CertMaterialV3 {
  return {
    kind: "user",
    name: "corp-ca",
    thumbprint: "AABBCCDDEEFF",
    pemCertBase64: Buffer.from(
      "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
    ).toString("base64"),
    pemKeyBase64: Buffer.from(
      "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"
    ).toString("base64"),
    pfxBase64: Buffer.from("PFX-PRESERVED").toString("base64"),
    rootPfxBase64: Buffer.from("ROOT-PFX").toString("base64"),
    trustInContainer: true,
    installToDotNetStore: false,
    ...overrides,
  };
}

describe.skipIf(process.platform === "win32")("installUserCert store gating", () => {
  it("does NOT write the store PFX when installToDotNetStore is false", () => {
    installUserCert(userMaterial({ installToDotNetStore: false }));
    const storePath = path.join(storeDir, "AABBCCDDEEFF.pfx");
    expect(fs.existsSync(storePath)).toBe(false);
    // Trust dir copy still happens because trustInContainer = true.
    expect(fs.existsSync(path.join(trustDir, "corp-ca.pem"))).toBe(true);
  });

  it("writes the store PFX with the store-only bytes when opted in", () => {
    const dotNetStorePfxBase64 = Buffer.from("PFX-PASSWORDLESS").toString(
      "base64"
    );
    installUserCert(
      userMaterial({
        installToDotNetStore: true,
        dotNetStorePfxBase64,
      })
    );
    const storePath = path.join(storeDir, "AABBCCDDEEFF.pfx");
    expect(fs.existsSync(storePath)).toBe(true);
    // The store copy carries the passwordless bytes, never the password-
    // preserving pfxBase64 — the host's separation must propagate to disk.
    expect(fs.readFileSync(storePath).toString()).toBe("PFX-PASSWORDLESS");
  });

  it("sweeps a stale store PFX when the opt-in is later cleared", () => {
    const storePath = path.join(storeDir, "AABBCCDDEEFF.pfx");
    installUserCert(
      userMaterial({
        installToDotNetStore: true,
        dotNetStorePfxBase64: Buffer.from("OLD").toString("base64"),
      })
    );
    expect(fs.existsSync(storePath)).toBe(true);

    // User flips the global opt-in off (or adds excludeFromDotNetStore on
    // this entry). On the next sync the workspace MUST remove the stale
    // plain-text copy, not orphan it.
    installUserCert(userMaterial({ installToDotNetStore: false }));
    expect(fs.existsSync(storePath)).toBe(false);
  });

  it("skips the store write when opt-in is true but bytes are missing", () => {
    // Defense in depth — host should always pair the flag with bytes, but
    // workspace gates on both so a malformed IPC payload can't accidentally
    // strip a write target.
    installUserCert(
      userMaterial({
        installToDotNetStore: true,
        dotNetStorePfxBase64: undefined,
      })
    );
    const storePath = path.join(storeDir, "AABBCCDDEEFF.pfx");
    expect(fs.existsSync(storePath)).toBe(false);
  });
});

describe.skipIf(process.platform === "win32")("installDotNetDevCert", () => {
  it("always writes to the store regardless of any opt-in flag", () => {
    const material: CertMaterialV3 = {
      kind: "dotnet-dev",
      name: "aspnetcore-dev",
      thumbprint: "DEADBEEF",
      pemCertBase64: Buffer.from(
        "-----BEGIN CERTIFICATE-----\nDEV\n-----END CERTIFICATE-----\n"
      ).toString("base64"),
      pemKeyBase64: Buffer.from(
        "-----BEGIN PRIVATE KEY-----\nDEV\n-----END PRIVATE KEY-----\n"
      ).toString("base64"),
      pfxBase64: Buffer.from("DEV-PFX").toString("base64"),
      rootPfxBase64: Buffer.from("DEV-ROOT").toString("base64"),
      trustInContainer: true,
      installToDotNetStore: true,
      dotNetStorePfxBase64: Buffer.from("DEV-PFX").toString("base64"),
    };
    installDotNetDevCert(material);
    expect(fs.existsSync(path.join(storeDir, "DEADBEEF.pfx"))).toBe(true);
    expect(fs.existsSync(path.join(rootStoreDir, "DEADBEEF.pfx"))).toBe(true);
  });
});

describe.skipIf(process.platform === "win32")("isCertInstalled", () => {
  it("returns true for a user cert opted out of the store with no store file", () => {
    installUserCert(userMaterial({ installToDotNetStore: false }));
    expect(isCertInstalled(userMaterial({ installToDotNetStore: false }))).toBe(
      true
    );
  });

  it("returns false for an opted-in user cert when the store file is missing", () => {
    // Only the trust-dir copy was installed (simulate a half-completed install
    // or a manual deletion). The check should reflect that the store file is
    // missing.
    installUserCert(userMaterial({ installToDotNetStore: false }));
    expect(
      isCertInstalled(
        userMaterial({
          installToDotNetStore: true,
          dotNetStorePfxBase64: Buffer.from("X").toString("base64"),
        })
      )
    ).toBe(false);
  });
});
