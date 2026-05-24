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

  it("repeat pushes of the same cert call trustCertificate twice at the handler level — idempotency is enforced one layer down in CertManager.trustExternalCertificate via store.isCertTrusted", async () => {
    // The handler does NOT query the platform store for an already-
    // trusted thumbprint itself. The downstream `trustCertificate`
    // dep injected by `extension.ts` IS responsible for the
    // verify-on-disk short-circuit (it calls store.isCertTrusted
    // before invoking store.trustCertificate). This test pins
    // handler-level behavior: same cert pushed twice → the dep is
    // invoked twice — the dep itself decides whether to make a real
    // platform-trust call.
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

  it("returns parse-failed (not a thrown TypeError) when payload.thumbprint is missing", async () => {
    const { pemCertBase64 } = await makeDevPem();
    const deps = makeDeps();
    // Cast to bypass the type — simulating a malformed wire payload.
    const result = await acceptContainerDevCert(
      { pemCertBase64 } as unknown as AcceptContainerCertPayload,
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("returns parse-failed when payload.pemCertBase64 is missing", async () => {
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { thumbprint: "ABCD" } as unknown as AcceptContainerCertPayload,
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
  });

  it("does NOT persist consent when trustCertificate throws — next push re-prompts the user", async () => {
    // Critical UX invariant: if the platform-level trust step fails
    // (macOS keychain dialog cancelled, NSS DB not writable, etc.)
    // the consent must stay UN-persisted so the next push re-shows
    // the modal. Otherwise the user is silently stuck in
    // hasConsent()===true while trust keeps failing with no
    // surfaceable retry.
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({
      trustCertificate: vi.fn(async () => {
        throw new Error("simulated trust failure");
      }),
    });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    // The outer try/catch maps the throw to parse-failed.
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("parse-failed");
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    // KEY ASSERTION: consent was NOT persisted.
    expect(deps.recordConsent).not.toHaveBeenCalled();
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
