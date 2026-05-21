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
  const SAMPLE_DEV_PEM =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBkTCB+wIJANSsAUOhwHK7MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n" +
    "Y2FsaG9zdDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBQxEjAQBgNV\n" +
    "BAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAyx0qMlYa\n" +
    "PEzL0c9XBYNcQ6KAjMjbDLp6FrW+lWZHCKf8/aSJW7CnH2tQHrPiU8r6QYBSWQ7c\n" +
    "VTrA8h8wYy7eRdQk31uLR7tGzZ5JxBz2DYxcuxR1RJ/+QbR1m6Z5w9p5UqxQ4l3+\n" +
    "AbsmPwy3J7t4cqo3PVPmF6mPiK7M+M0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQAt\n" +
    "-----END CERTIFICATE-----\n";

  function devMaterial(thumbprint: string): CertMaterialV3 {
    return {
      kind: "dotnet-dev",
      name: "aspnetcore-dev",
      thumbprint,
      pemCertBase64: Buffer.from(SAMPLE_DEV_PEM).toString("base64"),
      pemKeyBase64: Buffer.from(
        "-----BEGIN PRIVATE KEY-----\nDEV\n-----END PRIVATE KEY-----\n"
      ).toString("base64"),
      pfxBase64: Buffer.from("DEV-PFX").toString("base64"),
      rootPfxBase64: Buffer.from("DEV-ROOT").toString("base64"),
      trustInContainer: true,
      installToDotNetStore: true,
      dotNetStorePfxBase64: Buffer.from("DEV-PFX").toString("base64"),
    };
  }

  it("always writes to the store regardless of any opt-in flag", () => {
    installDotNetDevCert(devMaterial("DEADBEEF"));
    expect(fs.existsSync(path.join(storeDir, "DEADBEEF.pfx"))).toBe(true);
    expect(fs.existsSync(path.join(rootStoreDir, "DEADBEEF.pfx"))).toBe(true);
  });

  it("creates exactly one hash symlink for the new PEM (no duplicate .0/.1)", () => {
    installDotNetDevCert(devMaterial("DEADBEEF"));
    const links = fs
      .readdirSync(trustDir)
      .filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f));
    expect(links).toHaveLength(1);
    expect(links[0].endsWith(".0")).toBe(true);
    expect(fs.readlinkSync(path.join(trustDir, links[0]))).toBe(
      "aspnetcore-localhost-DEADBEEF.pem"
    );
  });

  it("does NOT sweep pre-existing aspnetcore-localhost PEMs from prior rotations", () => {
    const stalePath = path.join(
      trustDir,
      "aspnetcore-localhost-CAFEBABE.pem"
    );
    fs.writeFileSync(stalePath, "old");

    installDotNetDevCert(devMaterial("DEADBEEF"));

    // Old PEM is left intact — the user is expected to invoke the cleanup
    // command explicitly to remove it.
    expect(fs.existsSync(stalePath)).toBe(true);
  });

  it("is idempotent when called twice with the same thumbprint", () => {
    // Reload-of-window flow: `isCertInstalled` may already short-circuit
    // upstream, but the install function itself must not corrupt state
    // when invoked twice in a row — same single PFX in each store, exactly
    // one PEM in the trust dir, exactly one {hash}.0 symlink pointing at
    // it.
    installDotNetDevCert(devMaterial("DEADBEEF"));
    installDotNetDevCert(devMaterial("DEADBEEF"));

    expect(fs.readdirSync(storeDir)).toEqual(["DEADBEEF.pfx"]);
    expect(fs.readdirSync(rootStoreDir)).toEqual(["DEADBEEF.pfx"]);

    const trustEntries = fs.readdirSync(trustDir);
    const pems = trustEntries.filter((f) => f.endsWith(".pem"));
    const links = trustEntries.filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f));
    expect(pems).toEqual(["aspnetcore-localhost-DEADBEEF.pem"]);
    expect(links).toHaveLength(1);
    expect(links[0].endsWith(".0")).toBe(true);
    expect(fs.readlinkSync(path.join(trustDir, links[0]))).toBe(
      "aspnetcore-localhost-DEADBEEF.pem"
    );
  });

  // The "leaves pre-existing hash symlinks for unrelated PEMs untouched"
  // invariant is covered at the unit level in
  // `tests/rehash.test.ts > leaves pre-existing hash symlinks for OTHER
  // PEMs untouched`. Don't duplicate it here.
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
