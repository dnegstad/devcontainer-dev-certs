import { describe, it, expect, beforeEach, vi } from "vitest";
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
import {
  acceptContainerDevCert,
  type AcceptContainerCertDeps,
  type AcceptContainerCertPayload,
} from "../src/containerCertAccept";

cryptoProvider.set(webcrypto as unknown as Crypto);
initLogger("test");

interface MakeDevCertOptions {
  cn?: string;
  versionByte?: number;
  notBefore?: Date;
  notAfter?: Date;
  sans?: { type: "dns" | "ip"; value: string }[];
  omitOid?: boolean;
  omitKey?: boolean;
}

async function makeDevPfx(
  opts: MakeDevCertOptions = {}
): Promise<{ pfxBase64: string; thumbprint: string }> {
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
  const sans = opts.sans ?? [
    ...SAN_DNS_NAMES.map((d) => ({ type: "dns" as const, value: d })),
    ...SAN_IP_ADDRESSES.map((ip) => ({ type: "ip" as const, value: ip })),
  ];
  const extensions = [new SubjectAlternativeNameExtension(sans, true)];
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
  const pfxBytes = await buildPfx({
    cert: devCert,
    key: devKey,
  });
  return {
    pfxBase64: pfxBytes.toString("base64"),
    thumbprint: devCert.thumbprintSha1,
  };
}

function makeDeps(
  overrides: Partial<AcceptContainerCertDeps> = {}
): AcceptContainerCertDeps & {
  acceptCertificate: ReturnType<typeof vi.fn>;
  promptUser: ReturnType<typeof vi.fn>;
  recordConsent: ReturnType<typeof vi.fn>;
  onAccepted: ReturnType<typeof vi.fn>;
} {
  const acceptCertificate = vi.fn(async () => undefined);
  const promptUser = vi.fn(async () => true);
  const recordConsent = vi.fn(async () => undefined);
  const onAccepted = vi.fn();
  return {
    generateDotNetCert: true,
    autoProvision: true,
    allowNonLocalSans: false,
    getCurrentThumbprint: async () => null,
    hasConsent: () => false,
    recordConsent,
    promptUser,
    acceptCertificate,
    onAccepted,
    ...overrides,
    // Re-set the spies after spread so they take precedence over manual
    // overrides that re-passed the spy refs.
    ...(overrides.acceptCertificate === undefined
      ? { acceptCertificate }
      : {}),
    ...(overrides.promptUser === undefined ? { promptUser } : {}),
    ...(overrides.recordConsent === undefined ? { recordConsent } : {}),
    ...(overrides.onAccepted === undefined ? { onAccepted } : {}),
  };
}

describe("acceptContainerDevCert", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects when generateDotNetCert is false on the host", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const deps = makeDeps({ generateDotNetCert: false });
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result).toEqual({
      accepted: false,
      reason: "host-setting-disabled",
    });
    expect(deps.acceptCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("rejects when autoProvision is false on the host", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const deps = makeDeps({ autoProvision: false });
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result).toEqual({
      accepted: false,
      reason: "host-setting-disabled",
    });
    expect(deps.acceptCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("rejects with parse-failed when the PFX bytes are garbage", async () => {
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64: Buffer.from("not a pfx").toString("base64"), thumbprint: "x" },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
    expect(deps.acceptCertificate).not.toHaveBeenCalled();
  });

  it("rejects parse-failed when the payload thumbprint disagrees with the cert", async () => {
    const { pfxBase64 } = await makeDevPfx();
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      {
        pfxBase64,
        thumbprint: "0000000000000000000000000000000000000000",
      },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
    expect(result.detail).toMatch(/mismatch/i);
  });

  it("rejects parse-failed when the PFX has no private key", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx({ omitKey: true });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
  });

  it("rejects not-valid-dev-cert when CN ≠ localhost", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx({ cn: "example.com" });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-valid-dev-cert");
  });

  it("rejects not-valid-dev-cert when the dev-cert OID is missing", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx({ omitOid: true });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-valid-dev-cert");
  });

  it("rejects not-valid-dev-cert when the cert is expired", async () => {
    const past = new Date(Date.now() - 365 * 86400_000);
    const lastYear = new Date(Date.now() - 30 * 86400_000);
    const { pfxBase64, thumbprint } = await makeDevPfx({
      notBefore: past,
      notAfter: lastYear,
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-valid-dev-cert");
  });

  it("rejects non-local-sans when SAN contains a public DNS name and override is off", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx({
      sans: [
        { type: "dns", value: "localhost" },
        { type: "dns", value: "evil.example.com" },
      ],
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("non-local-sans");
    expect(result.detail).toContain("dns:evil.example.com");
    expect(deps.acceptCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("accepts non-local SANs when allowNonLocalContainerCertSans is on (and prompts with them)", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx({
      sans: [
        { type: "dns", value: "localhost" },
        { type: "dns", value: "evil.example.com" },
      ],
    });
    const deps = makeDeps({ allowNonLocalSans: true });
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(true);
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    const promptArgs = deps.promptUser.mock.calls[0][1] as Array<unknown>;
    expect(promptArgs).toEqual([
      { type: "dns", value: "evil.example.com" },
    ]);
    expect(deps.acceptCertificate).toHaveBeenCalledTimes(1);
  });

  it("short-circuits with alreadyTrusted when thumbprint matches the existing dev cert", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const deps = makeDeps({
      getCurrentThumbprint: async () => thumbprint,
    });
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: true, alreadyTrusted: true });
    expect(deps.acceptCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("prompts and records consent on first accept", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: true });
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    expect(deps.recordConsent).toHaveBeenCalledTimes(1);
    expect(deps.acceptCertificate).toHaveBeenCalledTimes(1);
    expect(deps.onAccepted).toHaveBeenCalledTimes(1);
  });

  it("skips the modal when consent was previously recorded", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const deps = makeDeps({ hasConsent: () => true });
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: true });
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
    expect(deps.acceptCertificate).toHaveBeenCalledTimes(1);
  });

  it("returns user-declined when the prompt is dismissed", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const deps = makeDeps({ promptUser: vi.fn(async () => false) });
    const result = await acceptContainerDevCert(
      { pfxBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: false, reason: "user-declined" });
    expect(deps.acceptCertificate).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });
});

describe("acceptContainerDevCert end-to-end against a temp dev cert", () => {
  it("happy path round-trips a generated dev cert through accept", async () => {
    const { pfxBase64, thumbprint } = await makeDevPfx();
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-accept-test-"));
    try {
      const acceptCertificate = vi.fn(async () => undefined);
      const payload: AcceptContainerCertPayload = { pfxBase64, thumbprint };
      const deps = makeDeps({ acceptCertificate });
      const result = await acceptContainerDevCert(payload, deps);
      expect(result.accepted).toBe(true);
      expect(acceptCertificate).toHaveBeenCalledTimes(1);
      const installed = (acceptCertificate.mock.calls[0] as unknown[])[0] as {
        thumbprint: string;
      };
      expect(installed.thumbprint).toBe(thumbprint);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
