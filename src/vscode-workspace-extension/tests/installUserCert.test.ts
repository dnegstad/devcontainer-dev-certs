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

const REAL_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBkTCB+wIJANSsAUOhwHK7MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n" +
  "Y2FsaG9zdDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBQxEjAQBgNV\n" +
  "BAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAyx0qMlYa\n" +
  "PEzL0c9XBYNcQ6KAjMjbDLp6FrW+lWZHCKf8/aSJW7CnH2tQHrPiU8r6QYBSWQ7c\n" +
  "VTrA8h8wYy7eRdQk31uLR7tGzZ5JxBz2DYxcuxR1RJ/+QbR1m6Z5w9p5UqxQ4l3+\n" +
  "AbsmPwy3J7t4cqo3PVPmF6mPiK7M+M0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQAt\n" +
  "-----END CERTIFICATE-----\n";

const ROTATED_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIDXzCCAkegAwIBAgIUbKzt8uWkwdhKI7QVANKvuaAuga4wDQYJKoZIhvcNAQEL\n" +
  "BQAwPzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUV4YW1wbGUgIE9yZyAxGDAWBgNV\n" +
  "BAMMD01peGVkIENhc2UgTmFtZTAeFw0yNjA4MjgwMDAzNThaFw0zNjA4MjUwMDAz\n" +
  "NThaMD8xCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1FeGFtcGxlICBPcmcgMRgwFgYD\n" +
  "VQQDDA9NaXhlZCBDYXNlIE5hbWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
  "AoIBAQDLuNsJ2dI5mBGcGeK5lfzKA/8dY5Dunjl10gZybeKcLCUuBwIecUg4rHFR\n" +
  "5OoH9s5UIIvOLA+aGR1gNxx4Jai3IUJtcGS67oh9Gz7F1w6hswO2y0rzXPVq0W+N\n" +
  "mAXmEqDpRjqmS6sGHFqtQkKNtc3WRhxc42RD4FiuMuWDkq5//fEEPClg/16i16uF\n" +
  "u/17fwq3rnJPQQbxMpxlJp/wJgJdfTNN0eypuvqRMc+4HYELcagtjOX0rBkIO3SG\n" +
  "xXqm2uJOCyPMoxWCVZax3+tuZY4onqajxtaz1ztURlbLejxXw4DfEH2CI6VPIc7X\n" +
  "bK/Ec5UBnyo1OVOaEcGNLIoQNjxFAgMBAAGjUzBRMB0GA1UdDgQWBBTLRAf/8wQx\n" +
  "YLYQMDUW/g+HiamzSDAfBgNVHSMEGDAWgBTLRAf/8wQxYLYQMDUW/g+HiamzSDAP\n" +
  "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAbc3i28qmW6cbOwpIR\n" +
  "OzSgg0BlyK9dOyGrfwRI44i1NEyZGM9Y8ced4AS7DgnZpuKfy54QiibCKxMzENOX\n" +
  "kogGgoDriLdDdGfdz2zrFQvHfYa2ccieJ6NV5Bi8Mgnnx+s/DGxZN6Yz76n5/Qic\n" +
  "eqmw7pgOMeeqGB5spiOw28INsZK5bxZEcpTyhgPUbhC3EjFp0UMNd7SFstfY7zGo\n" +
  "H6t+jC75hgl0PivQC97LrBpzNn0EZCdzoyCUomilR5XEk+L5WIC5H8Z+LxU1hBOS\n" +
  "ziEyIosRJFOAv0D4KYNITnCe6km2AzD+AAC5juMXFwaaDYtzmfKUsTFzGGIvC3C8\n" +
  "9l5Y\n" +
  "-----END CERTIFICATE-----\n";

function userMaterial(overrides: Partial<CertMaterialV3> = {}): CertMaterialV3 {
  return {
    kind: "user",
    name: "corp-ca",
    thumbprint: "AABBCCDDEEFF",
    // A real certificate, not a placeholder: `isCertInstalled` now requires a
    // resolvable OpenSSL hash symlink, which can only be derived from a PEM
    // whose subject actually parses.
    pemCertBase64: Buffer.from(REAL_PEM).toString("base64"),
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
  // invariant is covered at the unit level in `tests/rehash.test.ts`.
});

describe.skipIf(process.platform === "win32")("isCertInstalled", () => {
  it("returns true for a user cert opted out of the store with no store file", () => {
    installUserCert(userMaterial({ installToDotNetStore: false }));
    expect(isCertInstalled(userMaterial({ installToDotNetStore: false }))).toBe(
      true
    );
  });

  it("returns false when the PEM has no resolvable hash symlink (upgrade repair)", () => {
    // An install made before the subject hash was computed canonically has its
    // symlink under the WRONG hash. Every file is present, so a files-only
    // check reports "installed", activation skips the install, and the bad link
    // is never repaired — leaving trust broken for exactly the users this fix
    // exists for. Reproduced by installing, then renaming the link to a
    // wrong-hash name: the state such a container is actually in.
    installUserCert(userMaterial());
    expect(isCertInstalled(userMaterial())).toBe(true);

    const links = fs
      .readdirSync(trustDir)
      .filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f));
    expect(links).toHaveLength(1);
    const target = fs.readlinkSync(path.join(trustDir, links[0]));
    fs.unlinkSync(path.join(trustDir, links[0]));
    fs.symlinkSync(target, path.join(trustDir, "deadbeef.0"));

    expect(isCertInstalled(userMaterial())).toBe(false);

    // Re-running the install repairs it, which is what activation will now do.
    installUserCert(userMaterial());
    expect(isCertInstalled(userMaterial())).toBe(true);
  });

  it("returns false when a user cert rotated under the same name", () => {
    // User certs are keyed by the user-chosen `name`, not by thumbprint, so a
    // rotated certificate lands on the same `{name}.pem`. The stale file's own
    // hash link resolves perfectly well, so an existence check would report
    // "installed" and the container would keep serving the superseded cert
    // indefinitely. Content comparison is what catches it.
    installUserCert(userMaterial());
    expect(isCertInstalled(userMaterial())).toBe(true);

    const rotated = userMaterial({
      pemCertBase64: Buffer.from(ROTATED_PEM).toString("base64"),
    });
    expect(isCertInstalled(rotated)).toBe(false);

    installUserCert(rotated);
    expect(isCertInstalled(rotated)).toBe(true);
    expect(fs.readFileSync(path.join(trustDir, "corp-ca.pem"), "utf-8")).toBe(
      ROTATED_PEM
    );
  });

  it("returns false when a trusted user cert's .NET Root PFX is missing", () => {
    // `installUserCert` writes the Root-store PFX alongside the OpenSSL PEM.
    // Checking only the OpenSSL side would call the cert installed after that
    // file was deleted, so activation would skip the reinstall and .NET
    // clients in the container would keep distrusting it.
    installUserCert(userMaterial());
    expect(isCertInstalled(userMaterial())).toBe(true);

    fs.rmSync(path.join(rootStoreDir, "AABBCCDDEEFF.pfx"));
    expect(isCertInstalled(userMaterial())).toBe(false);

    installUserCert(userMaterial());
    expect(isCertInstalled(userMaterial())).toBe(true);
  });

  it("does not require a Root PFX the bundle never supplied", () => {
    // Gated on `rootPfxBase64`: a bundle without one would never have had the
    // file written, so demanding it would loop the install forever.
    const noRoot = userMaterial({ rootPfxBase64: undefined });
    installUserCert(noRoot);
    expect(isCertInstalled(noRoot)).toBe(true);
  });

  it("does not demand a symlink for a PEM whose subject cannot be hashed", () => {
    // `ensureHashSymlink` is a no-op for an unparseable PEM, so reporting "not
    // installed" would re-run the install every activation and never converge.
    const unhashable = userMaterial({
      pemCertBase64: Buffer.from("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n").toString("base64"),
    });
    installUserCert(unhashable);
    expect(isCertInstalled(unhashable)).toBe(true);
  });

  it("returns false when opted out but a stale store PFX is still on disk", () => {
    // The opt-out sweep lives in `installUserCert`'s else-branch, and the
    // activation path only calls that when `isCertInstalled` says false. If
    // this reported "installed" the sweep would be unreachable and the
    // passwordless (plain-text-key) copy would survive the user flipping
    // `installUserCertsToDotNetStore` off, forever.
    installUserCert(
      userMaterial({
        installToDotNetStore: true,
        dotNetStorePfxBase64: Buffer.from("OLD").toString("base64"),
      })
    );
    expect(fs.existsSync(path.join(storeDir, "AABBCCDDEEFF.pfx"))).toBe(true);

    expect(isCertInstalled(userMaterial({ installToDotNetStore: false }))).toBe(
      false
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
