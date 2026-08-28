import {
  DevCert,
  isValidDevCert,
  log,
  validateLeafTrustShape,
  validateLocalSans,
} from "@devcontainer-dev-certs/shared";
import type { NonLocalSanEntry } from "@devcontainer-dev-certs/shared";

/**
 * Wire-protocol payload sent by the workspace extension when it scans the
 * container's .NET store and finds a valid ASP.NET dev cert to push.
 *
 * Public cert only — the host's role in this flow is to trust the cert, not
 * to act as a server for it. Sending the private key would leak it across
 * the IPC boundary and onto the host's disk for no functional benefit;
 * Kestrel uses its own copy of the key inside the container.
 */
export interface AcceptContainerCertPayload {
  thumbprint: string;
  /** PEM-encoded certificate, base64-encoded (UTF-8 PEM string). */
  pemCertBase64: string;
}

/**
 * Internal view of a parsed-and-validated container-pushed cert. Used by
 * the consent prompt + the trust step. No private key — see the payload
 * docs above for why.
 */
export interface AcceptedContainerCert {
  cert: DevCert;
  thumbprint: string;
}

export type AcceptContainerCertRejectReason =
  | "host-setting-disabled"
  | "user-declined"
  | "parse-failed"
  | "not-valid-dev-cert"
  /**
   * basicConstraints says cA=TRUE, or is absent so we can't tell. Trusting
   * it would put an issuing CA in the host's root store, which the SAN-local
   * restriction cannot constrain — a CA's own SANs say nothing about what it
   * may issue for.
   */
  | "not-a-leaf-cert"
  /** No extendedKeyUsage, anyExtendedKeyUsage, or no id-kp-serverAuth. */
  | "unsupported-eku"
  /**
   * The SAN set is structurally unusable (absent, undecodable, empty, or
   * carrying a GeneralName type other than dNSName / iPAddress) — distinct
   * from `non-local-sans`, and NOT overridable by
   * `allowNonLocalContainerCertSans`.
   */
  | "malformed-sans"
  | "non-local-sans";

export interface AcceptContainerCertResult {
  accepted: boolean;
  reason?: AcceptContainerCertRejectReason;
  /** Free-form supplemental detail (e.g. offending SAN entries). */
  detail?: string;
}

/**
 * Dependencies for `acceptContainerDevCert`. Extracted as an explicit
 * interface so the handler is unit-testable without touching real
 * platform stores or the vscode API.
 */
export interface AcceptContainerCertDeps {
  /**
   * `devcontainerDevCerts.generateDotNetCert` host setting. When false,
   * the user has opted out of having any extension-managed ASP.NET dev
   * cert on their host trust store — a container-pushed cert would
   * violate that intent, so we reject.
   */
  generateDotNetCert: boolean;
  /**
   * `devcontainerDevCerts.autoProvision` host setting. When false, the
   * user has disabled automatic provisioning entirely; we don't prompt
   * or trust in response to an unsolicited push.
   */
  autoProvision: boolean;
  /** `devcontainerDevCerts.allowNonLocalContainerCertSans` host setting. */
  allowNonLocalSans: boolean;
  /** True iff the user has previously consented to container-cert sync. */
  hasConsent: () => boolean;
  /** Persist consent for future pushes. */
  recordConsent: () => Promise<void>;
  /** Show the modal consent prompt. Returns true iff the user accepted. */
  promptUser: (
    cert: AcceptedContainerCert,
    nonLocalSansOverridden: NonLocalSanEntry[]
  ) => Promise<boolean>;
  /**
   * Trust the supplied cert in the host's OS trust store. The
   * implementation is the same code path the host-generation flow uses,
   * but called with NO private key — we don't sync or persist the key,
   * and we don't write the cert into CurrentUser/My, the macOS login
   * keychain, or the .NET store's `my/` dir. The trust step is
   * public-cert-only on every supported platform (Root store / OpenSSL
   * trust dir / NSS DBs / login keychain trust settings).
   */
  trustCertificate: (cert: AcceptedContainerCert) => Promise<void>;
}

/**
 * Host-side handler for the reverse-sync command. Steps, in order:
 *
 *  1. Host gating: gate on the SAME settings the host-generation flow
 *     uses — `devcontainerDevCerts.generateDotNetCert` (the user opted
 *     out of having any extension-managed dotnet dev cert on their
 *     host) and `devcontainerDevCerts.autoProvision` (the user
 *     disabled automatic provisioning altogether). If either is off,
 *     decline with `host-setting-disabled`.
 *  2. Parse the supplied PEM cert. Failure → `parse-failed`.
 *  3. Validate it actually is an ASP.NET dev cert (CN, validity, OID,
 *     version) — independent of whatever the workspace asserted.
 *     Failure → `not-valid-dev-cert`.
 *  4. Trust-anchor shape (`validateLeafTrustShape`). The cert must be a
 *     leaf (basicConstraints present, cA=FALSE) and scoped to server
 *     auth (EKU present, includes serverAuth, not anyExtendedKeyUsage).
 *     Failure → `not-a-leaf-cert` / `unsupported-eku`. This gates step 5
 *     rather than sitting beside it: step 5 asks what names the cert
 *     covers, which only constrains anything for a cert that can
 *     authenticate ONLY itself. A CA's own SANs place no limit on what
 *     it may issue, so without this check the SAN restriction is
 *     bypassed by pushing a CA with `localhost` SANs and then signing a
 *     leaf for any name at all.
 *  5. SAN-local restriction. A structurally unusable SAN set (absent,
 *     undecodable, empty, or carrying a GeneralName type other than
 *     dNSName / iPAddress) rejects with `malformed-sans` and is NOT
 *     overridable. Otherwise, unless the `allowNonLocalContainerCertSans`
 *     override is on, any dNSName / iPAddress outside well-known local
 *     scopes (see validateLocalSans) rejects with `non-local-sans`.
 *     Together these defend against a malicious or misconfigured
 *     container tricking the host into trusting a cert valid for
 *     arbitrary domains.
 *  6. Modal consent prompt (one-time, gated on `containerCertProvisionConsented`
 *     in extension global state — distinct from the host-generation
 *     consent because the user is approving trust of a cert that came
 *     from a container they may or may not control). Declining →
 *     `user-declined`.
 *  7. Trust the cert in the host platform store. Public-cert-only:
 *     writes the cert to the OS trust surfaces (.NET Root / OpenSSL
 *     trust dir / NSS / login keychain / CurrentUser-Root) but NEVER
 *     to a my-store location and NEVER with a private key — the host
 *     is purely a trust anchor here, not a cert distribution point.
 *     The platform layer fires its own native prompts (macOS keychain,
 *     Windows MMC) on first trust of this thumbprint.
 *
 * Idempotent on repeat pushes of the same cert: each platform's
 * `trustCertificate` is a no-op when the cert is already in the trust
 * surfaces, so we don't bother short-circuiting based on a separate
 * "already trusted" check.
 */
export async function acceptContainerDevCert(
  payload: AcceptContainerCertPayload,
  deps: AcceptContainerCertDeps
): Promise<AcceptContainerCertResult> {
  // Top-level guard: every uncaught exception inside the handler maps to a
  // structured `parse-failed` result instead of escaping past the command
  // boundary. The workspace's containerCertPush.ts checks the result.reason
  // and routes per-reason UX; a raw rejection from executeCommand would
  // collapse into its generic "Failed to push" toast and lose that signal.
  // Specific reject branches inside the body still return their own
  // typed reasons (host-setting-disabled, not-valid-dev-cert, etc.).
  try {
    return await acceptContainerDevCertInner(payload, deps);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`acceptContainerDevCert: unexpected error: ${message}`);
    return { accepted: false, reason: "parse-failed", detail: message };
  }
}

async function acceptContainerDevCertInner(
  payload: AcceptContainerCertPayload,
  deps: AcceptContainerCertDeps
): Promise<AcceptContainerCertResult> {
  if (!deps.generateDotNetCert) {
    log(
      "acceptContainerDevCert: devcontainerDevCerts.generateDotNetCert is false; declining (host opted out of managed dotnet dev certs)."
    );
    return { accepted: false, reason: "host-setting-disabled" };
  }
  if (!deps.autoProvision) {
    log(
      "acceptContainerDevCert: devcontainerDevCerts.autoProvision is false; declining (host disabled automatic provisioning)."
    );
    return { accepted: false, reason: "host-setting-disabled" };
  }

  // Validate the payload shape BEFORE parsing — a missing or non-string
  // thumbprint would otherwise throw on the .toUpperCase() call later and
  // bypass the structured reject path.
  if (typeof payload?.pemCertBase64 !== "string") {
    return {
      accepted: false,
      reason: "parse-failed",
      detail: "payload.pemCertBase64 missing or not a string",
    };
  }
  if (typeof payload?.thumbprint !== "string") {
    return {
      accepted: false,
      reason: "parse-failed",
      detail: "payload.thumbprint missing or not a string",
    };
  }

  let parsed: AcceptedContainerCert;
  try {
    const pem = Buffer.from(payload.pemCertBase64, "base64").toString("utf-8");
    const cert = new DevCert(pem);
    parsed = { cert, thumbprint: cert.thumbprintSha1 };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`acceptContainerDevCert: PEM parse failed: ${message}`);
    return { accepted: false, reason: "parse-failed", detail: message };
  }

  if (parsed.thumbprint !== payload.thumbprint.toUpperCase()) {
    // Mismatched thumbprints mean the payload was tampered with in transit
    // OR the workspace miscomputed — either way, refuse silently and treat
    // it as a parse failure for log consistency.
    log(
      `acceptContainerDevCert: thumbprint mismatch — payload claimed ${payload.thumbprint.toUpperCase()}, actual ${parsed.thumbprint}.`
    );
    return {
      accepted: false,
      reason: "parse-failed",
      detail: "Thumbprint mismatch between payload and parsed certificate",
    };
  }

  if (!isValidDevCert(parsed.cert)) {
    log(
      `acceptContainerDevCert: rejected ${parsed.thumbprint} — fails isValidDevCert (CN/validity/OID/version).`
    );
    return { accepted: false, reason: "not-valid-dev-cert" };
  }

  // Shape before scope. A CA cert can be perfectly "local" by its own SANs
  // and still issue a leaf for any name it likes, so this has to gate the
  // SAN check rather than sit beside it — and its rejection is the more
  // useful one to surface when a cert fails both.
  const shape = validateLeafTrustShape(parsed.cert);
  if (!shape.ok) {
    const suffix = shape.detail ? ` (${shape.detail})` : "";
    if (
      shape.reason === "is-certificate-authority" ||
      shape.reason === "missing-basic-constraints"
    ) {
      log(
        `acceptContainerDevCert: rejected ${parsed.thumbprint} — ${shape.reason}${suffix}. ` +
          `Trusting it would install an issuing CA in this host's root store; the SAN-local ` +
          `restriction cannot constrain what a CA signs.`
      );
      return {
        accepted: false,
        reason: "not-a-leaf-cert",
        detail: shape.reason,
      };
    }
    if (shape.reason === "unreadable") {
      log(
        `acceptContainerDevCert: rejected ${parsed.thumbprint} — could not read basicConstraints/EKU${suffix}.`
      );
      return { accepted: false, reason: "parse-failed", detail: shape.detail };
    }
    log(
      `acceptContainerDevCert: rejected ${parsed.thumbprint} — ${shape.reason}${suffix}. ` +
        `A dev cert this host will trust must be scoped to server authentication.`
    );
    return {
      accepted: false,
      reason: "unsupported-eku",
      detail: shape.detail ? `${shape.reason}: ${shape.detail}` : shape.reason,
    };
  }

  const sanResult = validateLocalSans(parsed.cert);
  // Structural SAN failures are NOT scope decisions, so
  // `allowNonLocalContainerCertSans` deliberately does not override them.
  // That setting exists so a user can say "yes, I really do mean to trust
  // this cert for that name" — it can't mean anything about a cert whose
  // names we were unable to read in the first place.
  if (!sanResult.ok && sanResult.reason !== "non-local") {
    const detail = sanResult.detail
      ? `${sanResult.reason}: ${sanResult.detail}`
      : sanResult.reason;
    log(
      `acceptContainerDevCert: rejected ${parsed.thumbprint} — unusable SAN set (${detail}).`
    );
    return { accepted: false, reason: "malformed-sans", detail };
  }
  if (!sanResult.ok && !deps.allowNonLocalSans) {
    const detail = sanResult.nonLocalEntries
      .map((e) => `${e.type}:${e.value}`)
      .join(", ");
    log(
      `acceptContainerDevCert: rejected ${parsed.thumbprint} — non-local SAN entries: ${detail}. Override via devcontainerDevCerts.allowNonLocalContainerCertSans.`
    );
    return { accepted: false, reason: "non-local-sans", detail };
  }
  const nonLocalOverridden =
    !sanResult.ok && deps.allowNonLocalSans ? sanResult.nonLocalEntries : [];
  if (nonLocalOverridden.length > 0) {
    log(
      `acceptContainerDevCert: ${parsed.thumbprint} has non-local SAN entries but allowNonLocalContainerCertSans is true; proceeding. Non-local entries: ${nonLocalOverridden
        .map((e) => `${e.type}:${e.value}`)
        .join(", ")}`
    );
  }

  const needsConsent = !deps.hasConsent();
  if (needsConsent) {
    const consented = await deps.promptUser(parsed, nonLocalOverridden);
    if (!consented) {
      log(
        `acceptContainerDevCert: user declined trusting ${parsed.thumbprint}.`
      );
      return { accepted: false, reason: "user-declined" };
    }
  }

  // Run the trust step BEFORE persisting consent. If trustCertificate
  // throws (macOS keychain dialog cancelled, NSS DB not writable, etc.)
  // we let the outer try/catch convert it to `parse-failed` — and
  // crucially the consent stays UN-persisted, so the next push retries
  // the modal prompt with the same fresh state instead of silently
  // re-trying trust without UX.
  await deps.trustCertificate(parsed);

  if (needsConsent) {
    await deps.recordConsent();
  }

  log(`acceptContainerDevCert: ${parsed.thumbprint} trusted on host.`);
  return { accepted: true };
}

