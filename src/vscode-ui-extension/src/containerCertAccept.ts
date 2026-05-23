import {
  isValidDevCert,
  log,
  parsePfx,
  validateLocalSans,
  type LoadedCert,
  type NonLocalSanEntry,
} from "@devcontainer-dev-certs/shared";

/**
 * Wire-protocol payload sent by the workspace extension when it scans the
 * container's .NET store and finds a valid ASP.NET dev cert to push.
 */
export interface AcceptContainerCertPayload {
  thumbprint: string;
  /** Passwordless PFX bytes, base64-encoded. */
  pfxBase64: string;
  /** PEM-encoded certificate, base64-encoded (UTF-8 PEM string). */
  pemCertBase64?: string;
  /** PEM-encoded private key, base64-encoded; absent for CA-only certs. */
  pemKeyBase64?: string;
}

export type AcceptContainerCertRejectReason =
  | "host-setting-disabled"
  | "user-declined"
  | "parse-failed"
  | "not-valid-dev-cert"
  | "non-local-sans";

export interface AcceptContainerCertResult {
  accepted: boolean;
  alreadyTrusted?: boolean;
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
   * `devcontainer-dev-certs.autoProvision` host setting. When false, the
   * user has disabled automatic provisioning entirely; we don't prompt
   * or trust in response to an unsolicited push.
   */
  autoProvision: boolean;
  /** `devcontainerDevCerts.allowNonLocalContainerCertSans` host setting. */
  allowNonLocalSans: boolean;
  /** Returns the current dev cert thumbprint, or null when none exists. */
  getCurrentThumbprint: () => Promise<string | null>;
  /** True iff the user has previously consented to container-cert sync. */
  hasConsent: () => boolean;
  /** Persist consent for future pushes. */
  recordConsent: () => Promise<void>;
  /** Show the modal consent prompt. Returns true iff the user accepted. */
  promptUser: (
    cert: LoadedCert,
    nonLocalSansOverridden: NonLocalSanEntry[]
  ) => Promise<boolean>;
  /** Install + trust the supplied cert. */
  acceptCertificate: (cert: LoadedCert) => Promise<void>;
  /** Invalidate the host certProvider's cache so the next pull serves this cert. */
  onAccepted: () => void;
}

/**
 * Host-side handler for the reverse-sync command. Steps, in order:
 *
 *  1. Host gating: gate on the SAME settings the host-generation flow
 *     uses — `devcontainerDevCerts.generateDotNetCert` (the user opted
 *     out of having any extension-managed dotnet dev cert on their
 *     host) and `devcontainer-dev-certs.autoProvision` (the user
 *     disabled automatic provisioning altogether). If either is off,
 *     decline with `host-setting-disabled`.
 *  2. Parse + load the supplied PFX. Failure → `parse-failed`.
 *  3. Validate it actually is an ASP.NET dev cert (CN, validity, OID,
 *     version) — independent of whatever the workspace asserted.
 *     Failure → `not-valid-dev-cert`.
 *  4. SAN-local restriction. Unless the
 *     `allowNonLocalContainerCertSans` override is on, any SAN entry
 *     outside well-known local scopes (see validateLocalSans) rejects
 *     the cert with `non-local-sans`. Defends against a malicious or
 *     misconfigured container tricking the host into trusting a cert
 *     valid for arbitrary domains.
 *  5. Already-trusted short-circuit. If the host platform store already
 *     has a dev cert with this thumbprint, return `{ accepted: true,
 *     alreadyTrusted: true }` without prompting.
 *  6. Modal consent prompt (one-time, gated on `containerCertProvisionConsented`
 *     in extension global state — distinct from the host-generation
 *     consent because the user is approving trust of a cert that came
 *     from a container they may or may not control). Declining →
 *     `user-declined`.
 *  7. Save + trust the cert in the host platform store. The platform
 *     layer fires its own native prompts (macOS keychain, Windows MMC).
 *  8. Clear the certProvider cache so the next `getAllCertMaterial(V3)`
 *     call returns the freshly-trusted container cert.
 */
export async function acceptContainerDevCert(
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
      "acceptContainerDevCert: devcontainer-dev-certs.autoProvision is false; declining (host disabled automatic provisioning)."
    );
    return { accepted: false, reason: "host-setting-disabled" };
  }

  let loaded: LoadedCert;
  try {
    const pfxBytes = Buffer.from(payload.pfxBase64, "base64");
    const { cert, key } = await parsePfx(pfxBytes, "");
    loaded = {
      cert,
      key,
      thumbprint: cert.thumbprintSha1,
      isExpired: cert.notAfter.getTime() < Date.now(),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    log(`acceptContainerDevCert: PFX parse failed: ${message}`);
    return { accepted: false, reason: "parse-failed", detail: message };
  }

  if (!loaded.key) {
    log(
      `acceptContainerDevCert: rejected ${loaded.thumbprint} — PFX contains no private key, refusing to install a CA-only cert as a dev cert.`
    );
    return {
      accepted: false,
      reason: "parse-failed",
      detail: "PFX contained no private key",
    };
  }

  if (loaded.thumbprint !== payload.thumbprint.toUpperCase()) {
    // Mismatched thumbprints mean the payload was tampered with in transit
    // OR the workspace miscomputed — either way, refuse silently and treat
    // it as a parse failure for log consistency.
    log(
      `acceptContainerDevCert: thumbprint mismatch — payload claimed ${payload.thumbprint.toUpperCase()}, actual ${loaded.thumbprint}.`
    );
    return {
      accepted: false,
      reason: "parse-failed",
      detail: "Thumbprint mismatch between payload and parsed certificate",
    };
  }

  if (!isValidDevCert(loaded.cert)) {
    log(
      `acceptContainerDevCert: rejected ${loaded.thumbprint} — fails isValidDevCert (CN/validity/OID/version).`
    );
    return { accepted: false, reason: "not-valid-dev-cert" };
  }

  const sanResult = validateLocalSans(loaded.cert);
  if (!sanResult.ok && !deps.allowNonLocalSans) {
    const detail = sanResult.nonLocalEntries
      .map((e) => `${e.type}:${e.value}`)
      .join(", ");
    log(
      `acceptContainerDevCert: rejected ${loaded.thumbprint} — non-local SAN entries: ${detail}. Override via devcontainerDevCerts.allowNonLocalContainerCertSans.`
    );
    return { accepted: false, reason: "non-local-sans", detail };
  }
  const nonLocalOverridden =
    !sanResult.ok && deps.allowNonLocalSans ? sanResult.nonLocalEntries : [];
  if (nonLocalOverridden.length > 0) {
    log(
      `acceptContainerDevCert: ${loaded.thumbprint} has non-local SAN entries but allowNonLocalContainerCertSans is true; proceeding. Non-local entries: ${nonLocalOverridden
        .map((e) => `${e.type}:${e.value}`)
        .join(", ")}`
    );
  }

  // Already-trusted short-circuit. If the platform store already holds a
  // dev cert with this thumbprint, no work to do — surface the success
  // without re-prompting or re-trusting.
  const existingThumbprint = await deps.getCurrentThumbprint();
  if (existingThumbprint && existingThumbprint === loaded.thumbprint) {
    log(
      `acceptContainerDevCert: ${loaded.thumbprint} already trusted on host; no action needed.`
    );
    return { accepted: true, alreadyTrusted: true };
  }

  if (!deps.hasConsent()) {
    const consented = await deps.promptUser(loaded, nonLocalOverridden);
    if (!consented) {
      log(
        `acceptContainerDevCert: user declined trusting ${loaded.thumbprint}.`
      );
      return { accepted: false, reason: "user-declined" };
    }
    await deps.recordConsent();
  }

  await deps.acceptCertificate(loaded);
  deps.onAccepted();

  log(`acceptContainerDevCert: ${loaded.thumbprint} trusted on host.`);
  return { accepted: true };
}

