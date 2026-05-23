// Polyfill must load before any module that pulls in @peculiar/x509 (via
// shared) — the test entry imports the scanner which imports shared.
import "reflect-metadata";

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  Extension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import {
  DevCert,
  DevKey,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  buildPfx,
  initLogger,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
} from "@devcontainer-dev-certs/shared";
import * as vscode from "vscode";
import {
  findBestContainerDevCert,
  pushContainerCertToHost,
  type AcceptContainerCertResult,
} from "../src/containerCertPush";

cryptoProvider.set(webcrypto as unknown as Crypto);
initLogger("test");

interface MakeOptions {
  versionByte?: number;
  notBefore?: Date;
  notAfter?: Date;
  cn?: string;
  omitOid?: boolean;
  omitKey?: boolean;
  pfxFileName?: string;
}

async function writeDevPfxInDir(
  dir: string,
  opts: MakeOptions = {}
): Promise<{ thumbprint: string; pfxPath: string }> {
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
  const extensions = [
    new SubjectAlternativeNameExtension(
      [
        ...SAN_DNS_NAMES.map((d) => ({ type: "dns" as const, value: d })),
        ...SAN_IP_ADDRESSES.map((ip) => ({ type: "ip" as const, value: ip })),
      ],
      true
    ),
  ];
  if (!opts.omitOid) {
    extensions.push(
      new Extension(
        ASPNET_HTTPS_OID,
        false,
        new Uint8Array([opts.versionByte ?? CURRENT_CERTIFICATE_VERSION]).buffer
      )
    );
  }
  const cert = await X509CertificateGenerator.create({
    serialNumber: "01",
    subject: `CN=${opts.cn ?? "localhost"}`,
    issuer: `CN=${opts.cn ?? "localhost"}`,
    notBefore: opts.notBefore ?? now,
    notAfter: opts.notAfter ?? new Date(now.getTime() + 30 * 86400_000),
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    extensions,
  });
  const devCert = new DevCert(cert);
  const devKey = opts.omitKey
    ? null
    : await DevKey.fromCryptoKey(keyPair.privateKey);
  const pfxBytes = await buildPfx({ cert: devCert, key: devKey });
  const fileName =
    opts.pfxFileName ?? `${devCert.thumbprintSha1.toUpperCase()}.pfx`;
  const pfxPath = path.join(dir, fileName);
  fs.writeFileSync(pfxPath, pfxBytes);
  return { thumbprint: devCert.thumbprintSha1, pfxPath };
}

function makeTmpHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-container-push-"));
}

function patchHome(tmp: string): { restore: () => void } {
  // The shared path helpers consult `os.homedir()` via `os.userInfo`.
  // The simpler hook here is HOME, which os.homedir() consults first on
  // Linux/macOS. Restore afterwards so other tests aren't polluted.
  const previousHome = process.env.HOME;
  process.env.HOME = tmp;
  // On Windows os.homedir() consults USERPROFILE; not exercised in CI but
  // keep the symmetric save/restore for robustness.
  const previousUserprofile = process.env.USERPROFILE;
  process.env.USERPROFILE = tmp;
  return {
    restore: () => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      if (previousUserprofile === undefined) delete process.env.USERPROFILE;
      else process.env.USERPROFILE = previousUserprofile;
    },
  };
}

function makeDotNetStoreDir(home: string): string {
  const dir = path.join(
    home,
    ".dotnet",
    "corefx",
    "cryptography",
    "x509stores",
    "my"
  );
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describe("findBestContainerDevCert", () => {
  let tmpHome: string;
  let restoreHome: () => void;

  beforeEach(() => {
    tmpHome = makeTmpHome();
    restoreHome = patchHome(tmpHome).restore;
  });

  afterEach(() => {
    restoreHome();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("returns null when the .NET store directory doesn't exist", async () => {
    const result = await findBestContainerDevCert();
    expect(result).toBeNull();
  });

  it("returns null when the .NET store directory is empty", async () => {
    makeDotNetStoreDir(tmpHome);
    const result = await findBestContainerDevCert();
    expect(result).toBeNull();
  });

  it("returns the single valid dev cert", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    const { thumbprint } = await writeDevPfxInDir(dir);
    const result = await findBestContainerDevCert();
    expect(result).not.toBeNull();
    expect(result?.loaded.thumbprint).toBe(thumbprint);
  });

  it("returns null when the only cert is missing the dev-cert OID", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    await writeDevPfxInDir(dir, { omitOid: true });
    const result = await findBestContainerDevCert();
    expect(result).toBeNull();
  });

  it("picks the latest-notAfter when multiple valid certs are present", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    const now = new Date();
    const earlier = new Date(now.getTime() + 30 * 86400_000);
    const later = new Date(now.getTime() + 90 * 86400_000);
    const a = await writeDevPfxInDir(dir, { notAfter: earlier });
    const b = await writeDevPfxInDir(dir, { notAfter: later });
    const result = await findBestContainerDevCert();
    expect(result?.loaded.thumbprint).toBe(b.thumbprint);
    expect(result?.loaded.thumbprint).not.toBe(a.thumbprint);
  });

  it("ignores non-pfx files in the store directory", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    fs.writeFileSync(path.join(dir, "garbage.txt"), "not a pfx");
    const { thumbprint } = await writeDevPfxInDir(dir);
    const result = await findBestContainerDevCert();
    expect(result?.loaded.thumbprint).toBe(thumbprint);
  });

  it("silently skips a corrupt PFX with a non-canonical filename", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    fs.writeFileSync(path.join(dir, "random-tool.pfx"), Buffer.from("garbage"));
    const { thumbprint } = await writeDevPfxInDir(dir);
    const result = await findBestContainerDevCert();
    expect(result?.loaded.thumbprint).toBe(thumbprint);
  });
});

describe("pushContainerCertToHost", () => {
  let tmpHome: string;
  let restoreHome: () => void;

  beforeEach(() => {
    tmpHome = makeTmpHome();
    restoreHome = patchHome(tmpHome).restore;
  });

  afterEach(() => {
    restoreHome();
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("returns null when no container cert is found (no push attempted)", async () => {
    const spy = vi.spyOn(vscode.commands, "executeCommand");
    const result = await pushContainerCertToHost();
    expect(result).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it("sends the best dev cert to the host and surfaces an accepted result", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    const { thumbprint } = await writeDevPfxInDir(dir);
    const spy = vi
      .spyOn(vscode.commands, "executeCommand")
      .mockImplementation(
        async (_cmd: string): Promise<AcceptContainerCertResult> => ({
          accepted: true,
        })
      );
    const result = await pushContainerCertToHost();
    expect(result).toEqual({ accepted: true });
    expect(spy).toHaveBeenCalledTimes(1);
    const [cmd, payload] = spy.mock.calls[0] as [
      string,
      { thumbprint: string; pfxBase64: string },
    ];
    expect(cmd).toBe("devcontainer-dev-certs.acceptContainerDevCert");
    expect(payload.thumbprint).toBe(thumbprint);
    expect(payload.pfxBase64.length).toBeGreaterThan(0);
  });

  it("surfaces alreadyTrusted without erroring", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    await writeDevPfxInDir(dir);
    vi.spyOn(vscode.commands, "executeCommand").mockImplementation(
      async (_cmd: string): Promise<AcceptContainerCertResult> => ({
        accepted: true,
        alreadyTrusted: true,
      })
    );
    const result = await pushContainerCertToHost();
    expect(result).toEqual({ accepted: true, alreadyTrusted: true });
  });

  it("falls back gracefully when the host command isn't registered", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    await writeDevPfxInDir(dir);
    vi.spyOn(vscode.commands, "executeCommand").mockRejectedValue(
      new Error(
        "command 'devcontainer-dev-certs.acceptContainerDevCert' not found"
      )
    );
    const result = await pushContainerCertToHost();
    expect(result).toBeNull();
  });

  it("returns the host's rejection verbatim when the user declines", async () => {
    const dir = makeDotNetStoreDir(tmpHome);
    await writeDevPfxInDir(dir);
    vi.spyOn(vscode.commands, "executeCommand").mockImplementation(
      async (_cmd: string): Promise<AcceptContainerCertResult> => ({
        accepted: false,
        reason: "user-declined",
      })
    );
    const result = await pushContainerCertToHost();
    expect(result).toEqual({ accepted: false, reason: "user-declined" });
  });
});
