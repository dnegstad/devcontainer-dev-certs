import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import { BasicConstraintsExtension, ExtendedKeyUsage, ExtendedKeyUsageExtension, Extension, SubjectAlternativeNameExtension, X509CertificateGenerator, cryptoProvider, } from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import {
  DevCert,
  generateCertificate,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
  VALIDITY_DAYS,
} from "@devcontainer-dev-certs/shared";
import { initLogger } from "@devcontainer-dev-certs/shared/src/loggerVscode";
import { acceptContainerDevCert, type AcceptContainerCertDeps, type AcceptContainerCertPayload, } from "../src/containerCertAccept";
import { normalizeContainerCertConsent } from "../src/extension";

cryptoProvider.set(webcrypto as unknown as Crypto);
initLogger("test");

interface MakeDevCertOptions {
  cn?: string;
  versionByte?: number;
  notBefore?: Date;
  notAfter?: Date;
  sans?: { type: "dns" | "ip"; value: string }[];
  omitSanExtension?: boolean;
  omitOid?: boolean;
  /** basicConstraints cA value. Default false (a leaf), like a real dev cert. */
  ca?: boolean;
  /** Drop basicConstraints entirely. */
  omitBasicConstraints?: boolean;
  /** EKU OIDs. Default [serverAuth]. `null` drops the extension. */
  eku?: string[] | null;
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
  // Default to the shape a genuine ASP.NET dev cert has: a leaf
  // (basicConstraints cA=FALSE, critical) scoped to server authentication.
  // Both are required by `validateLeafTrustShape`, so the happy-path fixture
  // has to carry them or every test would exercise a rejection.
  const extensions: Extension[] = [];
  if (!opts.omitSanExtension) {
    extensions.push(new SubjectAlternativeNameExtension(sans, true));
  }
  if (!opts.omitBasicConstraints) {
    extensions.push(
      new BasicConstraintsExtension(opts.ca ?? false, undefined, true)
    );
  }
  if (opts.eku !== null) {
    extensions.push(
      new ExtendedKeyUsageExtension(
        opts.eku ?? [ExtendedKeyUsage.serverAuth],
        true
      )
    );
  }
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

type DepOverrides = Partial<
  Omit<
    AcceptContainerCertDeps,
    "trustCertificate" | "promptUser" | "recordConsent"
  >
> & {
  trustCertificate?: Mock<AcceptContainerCertDeps["trustCertificate"]>;
  promptUser?: Mock<AcceptContainerCertDeps["promptUser"]>;
  recordConsent?: Mock<AcceptContainerCertDeps["recordConsent"]>;
};

function makeDeps(
  overrides: DepOverrides = {}
): AcceptContainerCertDeps & {
  trustCertificate: Mock<AcceptContainerCertDeps["trustCertificate"]>;
  promptUser: Mock<AcceptContainerCertDeps["promptUser"]>;
  recordConsent: Mock<AcceptContainerCertDeps["recordConsent"]>;
} {
  const trustCertificate =
    overrides.trustCertificate ??
    vi.fn<AcceptContainerCertDeps["trustCertificate"]>(async () => undefined);
  const promptUser =
    overrides.promptUser ??
    vi.fn<AcceptContainerCertDeps["promptUser"]>(async () => "trust");
  const recordConsent =
    overrides.recordConsent ??
    vi.fn<AcceptContainerCertDeps["recordConsent"]>(async () => undefined);
  return {
    generateDotNetCert: true,
    autoProvision: true,
    allowNonLocalSans: false,
    readConsent: () => "unset" as const,
    ...overrides,
    trustCertificate,
    promptUser,
    recordConsent,
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

  it("skips the modal when consent was previously granted", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ readConsent: () => "granted" });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: true });
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
    expect(deps.trustCertificate).toHaveBeenCalledTimes(1);
  });

  it("returns user-declined and records NOTHING when the prompt is dismissed", async () => {
    // Cancel / Escape declines this push only. Recording a denial here would
    // let a stray keystroke disable the feature for good.
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ promptUser: vi.fn(async () => "dismiss") });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: false, reason: "user-declined" });
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("records a denial when the user picks Never", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ promptUser: vi.fn(async () => "never") });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result).toEqual({ accepted: false, reason: "user-declined" });
    expect(deps.recordConsent).toHaveBeenCalledWith("denied");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });

  it("short-circuits a standing denial without re-prompting", async () => {
    // The defect this fixes: an accept persisted forever while a decline
    // persisted nothing, so the only durable state the prompt could reach was
    // the permissive one and declining meant being asked again on every
    // single container activation.
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({ readConsent: () => "denied" });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("user-declined");
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("records the grant as \"granted\", not a bare boolean", async () => {
    // The stored value is read back through a migration that maps legacy
    // `true` to "granted"; writing a boolean again would defeat the tri-state.
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps();
    await acceptContainerDevCert({ pemCertBase64, thumbprint }, deps);
    expect(deps.recordConsent).toHaveBeenCalledWith("granted");
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
    const deps = makeDeps({ readConsent: () => "granted" });
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
    expect(result.accepted).toBe(false);
    // Reported as a trust failure, not a parse failure: the cert parsed and
    // validated, so telling the user it was unreadable would be false and
    // point them at the wrong remedy.
    expect(result.reason).toBe("trust-failed");
    expect(result.detail).toContain("simulated trust failure");
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    // KEY ASSERTION: consent was NOT persisted.
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("reports trust-failed for an already-consented push whose trust step fails", async () => {
    // The consented path skips the modal entirely, so this is the branch a
    // returning user hits — e.g. `ensureHashSymlink` throwing on slot
    // exhaustion, which this branch made a thrown error rather than a
    // silent no-op. It must not surface as "could not parse".
    const { pemCertBase64, thumbprint } = await makeDevPem();
    const deps = makeDeps({
      readConsent: () => "granted" as const,
      trustCertificate: vi.fn(async () => {
        throw new Error("no free hash slot");
      }),
    });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("trust-failed");
    expect(deps.promptUser).not.toHaveBeenCalled();
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

/**
 * The SAN-local restriction only constrains a certificate that can
 * authenticate ONLY itself. A CA's own SANs place no limit on what it may
 * issue, so a CA with `localhost` SANs sails through `validateLocalSans` and
 * — once the host puts it in `CurrentUser\Root` / the login keychain / the
 * OpenSSL CApath / NSS with the `C` flag — can mint a leaf for any name it
 * likes. These tests pin the gate that closes that.
 */
describe("acceptContainerDevCert trust-anchor shape gate", () => {
  it("refuses a CA certificate even when every SAN is local", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({ ca: true });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-a-leaf-cert");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("refuses a CA certificate even with allowNonLocalContainerCertSans on", async () => {
    // The override relaxes SAN *scope*. It must not be readable as "trust
    // whatever this container sends" — a CA is a different question entirely.
    const { pemCertBase64, thumbprint } = await makeDevPem({ ca: true });
    const deps = makeDeps({ allowNonLocalSans: true });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-a-leaf-cert");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });

  it("refuses a certificate with no basicConstraints (cA is unanswerable)", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      omitBasicConstraints: true,
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("not-a-leaf-cert");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });

  it("refuses a certificate with no extendedKeyUsage", async () => {
    // Absent EKU reads as "any purpose"; Windows `certutil -addstore Root`
    // applies no policy constraint of its own, so the cert would be trusted
    // well beyond TLS.
    const { pemCertBase64, thumbprint } = await makeDevPem({ eku: null });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("unsupported-eku");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });

  it("refuses anyExtendedKeyUsage, which re-opens 'any purpose'", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      eku: ["2.5.29.37.0"],
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("unsupported-eku");
  });

  it("refuses an EKU that omits serverAuth", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      eku: ["1.3.6.1.5.5.7.3.3"], // codeSigning
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("unsupported-eku");
  });

  it("accepts an EKU carrying serverAuth alongside other specific usages", async () => {
    // Only anyExtendedKeyUsage is refused; extra concrete usages such as
    // clientAuth are tolerated so the check isn't brittle.
    const { pemCertBase64, thumbprint } = await makeDevPem({
      eku: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(true);
    expect(deps.trustCertificate).toHaveBeenCalledTimes(1);
  });
});

describe("acceptContainerDevCert structural SAN gate", () => {
  it("refuses a certificate with no SAN extension", async () => {
    const { pemCertBase64, thumbprint } = await makeDevPem({
      omitSanExtension: true,
    });
    const deps = makeDeps();
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("malformed-sans");
    expect(result.detail).toContain("missing");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });

  it("allowNonLocalContainerCertSans does NOT override a structural SAN failure", async () => {
    // The override is a statement about scope — "yes, I mean to trust this
    // cert for that name". It can't mean anything about a certificate whose
    // names we were unable to read at all.
    const { pemCertBase64, thumbprint } = await makeDevPem({
      omitSanExtension: true,
    });
    const deps = makeDeps({ allowNonLocalSans: true });
    const result = await acceptContainerDevCert(
      { pemCertBase64, thumbprint },
      deps
    );

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("malformed-sans");
    expect(deps.trustCertificate).not.toHaveBeenCalled();
  });
});

describe("acceptContainerDevCert accepts what this project actually generates", () => {
  it("a cert straight from generateCertificate passes every gate", async () => {
    // The gates above reject a cert that isn't a server-auth leaf with a
    // local-only dNSName/iPAddress SAN set. That description is supposed to
    // be exactly the certificate this project produces — and exactly what
    // `dotnet dev-certs https` produces, which `generateCertificate` mirrors
    // field for field. Driving the real generator (rather than the fixture
    // factory above) means any future divergence between what we emit and
    // what we're willing to trust fails here instead of in someone's
    // container.
    const now = new Date();
    const { cert } = await generateCertificate(
      now,
      new Date(now.getTime() + VALIDITY_DAYS * 86400_000)
    );
    const payload: AcceptContainerCertPayload = {
      pemCertBase64: Buffer.from(cert.pem, "utf-8").toString("base64"),
      thumbprint: cert.thumbprintSha1,
    };
    const deps = makeDeps();

    const result = await acceptContainerDevCert(payload, deps);

    expect(result).toEqual({ accepted: true });
    expect(deps.trustCertificate).toHaveBeenCalledTimes(1);
  });
});

describe("normalizeContainerCertConsent", () => {
  it("maps the legacy boolean grant to 'granted' so upgraders are not re-prompted", () => {
    // The key previously held a boolean that could only ever be `true`.
    // Reading that back as anything but a grant would show the modal again to
    // every user who had already consented.
    expect(normalizeContainerCertConsent(true)).toBe("granted");
  });

  it("round-trips the tri-state values", () => {
    expect(normalizeContainerCertConsent("granted")).toBe("granted");
    expect(normalizeContainerCertConsent("denied")).toBe("denied");
  });

  it("falls back to 'unset' for anything unrecognized", () => {
    // Ask, rather than silently opting the user in or out, for a stale value,
    // a hand-edited state file, or a key that was never written.
    for (const value of [undefined, null, false, 0, "", "yes", {}, []]) {
      expect(normalizeContainerCertConsent(value)).toBe("unset");
    }
  });
});
