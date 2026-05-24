import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  Extension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import {
  DevCert,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
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
}

/**
 * Produce just what the wire payload needs: a PEM-encoded cert and its
 * SHA-1 thumbprint. The private key is generated only to sign the
 * self-signed cert; it's never returned, mirroring the reverse-sync wire
 * contract (host gets the public cert only).
 */
async function makeDevPem(
  opts: MakeDevCertOptions = {}
): Promise<{ pemCertBase64: string; thumbprint: string }> {
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
  return {
    pemCertBase64: Buffer.from(devCert.pem, "utf-8").toString("base64"),
    thumbprint: devCert.thumbprintSha1,
  };
}

function makeDeps(
  overrides: Partial<AcceptContainerCertDeps> = {}
): AcceptContainerCertDeps & {
  trustCertificate: ReturnType<typeof vi.fn>;
  promptUser: ReturnType<typeof vi.fn>;
  recordConsent: ReturnType<typeof vi.fn>;
} {
  const trustCertificate = vi.fn(async () => undefined);
  const promptUser = vi.fn(async () => true);
  const recordConsent = vi.fn(async () => undefined);
  return {
    generateDotNetCert: true,
    autoProvision: true,
    allowNonLocalSans: false,
    hasConsent: () => false,
    recordConsent,
    promptUser,
    trustCertificate,
    ...overrides,
    // Re-set the spies after spread so they take precedence over manual
    // overrides that re-passed the spy refs.
    ...(overrides.trustCertificate === undefined
      ? { trustCertificate }
      : {}),
    ...(overrides.promptUser === undefined ? { promptUser } : {}),
    ...(overrides.recordConsent === undefined ? { recordConsent } : {}),
  };
}

describe("acceptContainerDevCert", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects when generateDotNetCert is false on the host", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ generateDotNetCert: false });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({
      accepted: false,
      reason: "host-setting-disabled",
    });
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("rejects when autoProvision is false on the host", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ autoProvision: false });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({
      accepted: false,
      reason: "host-setting-disabled",
    });
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("rejects with parse-failed when the PEM bytes are garbage", async () => {
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      {
        pemCertBase64: Buffer.from("not a pem cert").toString("base64"),
        thumbprint: "x",
      },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });

  it("rejects parse-failed when the payload thumbprint disagrees with the cert", async () => {
    const { pemCertBase64 } = await makeDevPem();
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      {
        pemCertBase64,
        thumbprint: "0000000000000000000000000000000000000000",
      },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
    expect(result.detail).toMatch(/mismatch/i);
  });

  it("rejects not-valid-dev-cert when CN ≠ localhost", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      cn: "example.com",
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-valid-dev-cert");
  });

  it("rejects not-valid-dev-cert when the dev-cert OID is missing", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({ omitOid: true });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-valid-dev-cert");
  });

  it("rejects not-valid-dev-cert when the cert is expired", async () => {
    const past = new Date(Date.now() - 365 * 86400_000);
    const lastYear = new Date(Date.now() - 30 * 86400_000);
    const { pemCertBase64, thumbprint } = await makeDevPem({
      notBefore: past,
      notAfter: lastYear,
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-valid-dev-cert");
  });

  it("rejects non-local-sans when SAN contains a public DNS name and override is off", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      sans: [
        { type: "dns", value: "localhost" },
        { type: "dns", value: "evil.example.com" },
      ],
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("non-local-sans");
    expect(result.detail).toContain("dns:evil.example.com");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("accepts non-local SANs when allowNonLocalContainerCertSans is on (and prompts with them)", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      sans: [
        { type: "dns", value: "localhost" },
        { type: "dns", value: "evil.example.com" },
      ],
    });
    const deps = makeDeps({ allowNonLocalSans: true });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(true);
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    const promptArgs = deps.promptUser.mock.calls[0][1] as Array<unknown>;
    expect(promptArgs).toEqual([
      { type: "dns", value: "evil.example.com" },
    ]);
    expect(deps.trustCertificate).toHaveBeenCalledTimes(1);
  });

  it("prompts and records consent on first accept", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: true });
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    expect(deps.recordConsent).toHaveBeenCalledTimes(1);
    expect(deps.trustCertificate).toHaveBeenCalledTimes(1);
  });

  it("skips the modal when consent was previously recorded", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ hasConsent: () => true });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: true });
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
    expect(deps.trustCertificate).toHaveBeenCalledTimes(1);
  });

  it("returns user-declined when the prompt is dismissed", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ promptUser: vi.fn(async () => false) });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: false, reason: "user-declined" });
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("repeat pushes of the same cert call trustCertificate idempotently (no short-circuit)", async () => {
    // The handler no longer queries the platform store for an
    // already-trusted thumbprint — each platform's trustCertificate is
    // idempotent at the OS layer. This test pins the behavior: same
    // cert pushed twice → trustCertificate invoked twice, no rejection.
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ hasConsent: () => true });
    const first = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    const second = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(first).toEqual({ accepted: true });
    expect(second).toEqual({ accepted: true });
    expect(deps.trustCertificate).toHaveBeenCalledTimes(2);
  });
});

describe("acceptContainerDevCert end-to-end against a generated dev cert", () => {
  it("happy path round-trips a generated dev cert through accept", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const trustCertificate = vi.fn(async () => undefined);
    const payload: AcceptContainerCertPayload = { pemCertBase64, thumbprint };
    const deps = makeDeps({ trustCertificate });
    const result = await acceptContainerDevCert(payload, deps);
    expect(result.accepted).toBe(true);
    expect(trustCertificate).toHaveBeenCalledTimes(1);
    const trusted = (trustCertificate.mock.calls[0] as unknown[])[0] as {
      thumbprint: string;
    };
    expect(trusted.thumbprint).toBe(thumbprint);
  });
});
