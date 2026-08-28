import { DevCert } from "./types";
import {
  ASPNET_HTTPS_OID,
  ASPNET_HTTPS_OID_FRIENDLY_NAME,
  MINIMUM_CERTIFICATE_VERSION,
} from "./properties";

/**
 * Check whether a parsed certificate looks like a valid ASP.NET Core HTTPS
 * dev cert: CN=localhost, currently within its validity window, and tagged
 * with the dev-cert custom OID at an acceptable version.
 */
export function isValidDevCert(
  cert: DevCert,
  minimumVersion: number = MINIMUM_CERTIFICATE_VERSION
): boolean {
  if (cert.subjectCN !== "localhost") return false;

  const now = new Date();
  if (cert.notBefore > now || cert.notAfter < now) return false;

  const version = getCertificateVersion(cert);
  if (version < 0 || version < minimumVersion) return false;

  return true;
}

/**
 * Extract the version byte from the ASP.NET dev cert custom-OID extension.
 * Returns -1 if the extension is absent.
 */
export function getCertificateVersion(cert: DevCert): number {
  const ext = cert.getExtension(ASPNET_HTTPS_OID);
  if (!ext) return -1;

  // The extension's extnValue is itself a DER OCTET STRING wrapping the
  // version byte (matching how `dotnet dev-certs` and node-forge serialise
  // the value). Peel back one layer of OCTET STRING if present, otherwise
  // treat the bytes directly.
  const raw = unwrapOctetString(ext.value);

  if (raw.length === 0) return 0;

  // Legacy v0 cert: raw bytes spell out the friendly name.
  if (
    raw.length === ASPNET_HTTPS_OID_FRIENDLY_NAME.length &&
    raw[0] === 0x41 // 'A'
  ) {
    return 0;
  }

  return raw[0];
}

function unwrapOctetString(value: Buffer): Buffer {
  if (value.length >= 2 && value[0] === 0x04) {
    // OCTET STRING tag is 0x04. Decode short-form length.
    if ((value[1] & 0x80) === 0) {
      const len = value[1];
      if (value.length === 2 + len) {
        return value.subarray(2);
      }
    } else {
      const numLenBytes = value[1] & 0x7f;
      if (numLenBytes <= 4 && value.length >= 2 + numLenBytes) {
        let len = 0;
        for (let i = 0; i < numLenBytes; i++) {
          len = (len << 8) | value[2 + i];
        }
        if (value.length === 2 + numLenBytes + len) {
          return value.subarray(2 + numLenBytes);
        }
      }
    }
  }
  return value;
}

/**
 * Compute the SHA-1 thumbprint of a PEM-encoded certificate string.
 * Uppercase hex, matching .NET's `X509Certificate2.Thumbprint` and the
 * filename convention used by Kestrel's X509Store fallback.
 */
export function computeThumbprint(pemCert: string): string {
  return new DevCert(pemCert).thumbprintSha1;
}

// ---------------------------------------------------------------------------
// SAN-local-only validation — used when the host accepts a dev cert pushed
// from inside a Dev Container. The default dev cert SAN set covers a few
// loopback / docker host names; we reject anything outside well-known local
// scopes so a malicious / misconfigured container can't trick the host into
// trusting a cert that's valid for `example.com`.
// ---------------------------------------------------------------------------

export interface NonLocalSanEntry {
  type: "dns" | "ip";
  value: string;
}

/**
 * Why a SAN set was rejected. Split into *structural* problems — the cert's
 * SAN extension isn't the shape a dev cert has, so we can't meaningfully say
 * what it's scoped to — and `non-local`, which means we read it fine and it
 * covers names outside local scopes.
 *
 * The distinction is load-bearing at the call site:
 * `allowNonLocalContainerCertSans` is an opt-out for *scope*, so it may
 * override `non-local` and must never override a structural reject. Trusting
 * a cert whose SAN we could not read is not a scope decision the user is in
 * a position to make.
 */
export type SanRejectReason =
  /** No SubjectAlternativeName extension at all. */
  | "missing"
  /** SAN extension present but its DER doesn't decode. */
  | "unparseable"
  /** SAN decoded but held zero entries. */
  | "no-host-entries"
  /** SAN carried a GeneralName type other than dNSName / iPAddress. */
  | "unsupported-entry"
  /** SAN read fine; at least one dNSName / iPAddress is outside local scope. */
  | "non-local";

export interface SanLocalValidationResult {
  ok: boolean;
  /** Set whenever `ok` is false. */
  reason?: SanRejectReason;
  /** Populated only for `reason === "non-local"`. */
  nonLocalEntries: NonLocalSanEntry[];
  /** Human-readable supplement for logs / UI. */
  detail?: string;
}

/** Successful scan, or the structural reason the SAN set is unusable. */
export type SanScanResult =
  | { ok: true; entries: NonLocalSanEntry[] }
  | {
      ok: false;
      reason: Exclude<SanRejectReason, "non-local">;
      detail?: string;
    };

const ALLOWED_DNS_EXACT = new Set<string>([
  "localhost",
  "host.docker.internal",
  "host.containers.internal",
  "gateway.docker.internal",
]);

/**
 * Suffix patterns (no leading wildcard) — a SAN entry matches when it equals
 * the suffix exactly OR ends with `.<suffix>`. So `localhost` is matched by
 * the exact set and `foo.localhost` by the `.localhost` suffix rule.
 */
const ALLOWED_DNS_SUFFIXES = [
  ".localhost",
  ".dev.localhost",
  ".dev.internal",
];

/**
 * Inspect a cert's SubjectAlternativeName entries and report any that aren't
 * confined to local-only scopes. Returns `{ ok: true, nonLocalEntries: [] }`
 * for the canonical ASP.NET dev cert SAN set (localhost, *.dev.localhost,
 * *.dev.internal, host.docker.internal, host.containers.internal,
 * 127.0.0.1, ::1) and rejects anything beyond those plus private-IP ranges.
 *
 * Allowed:
 *   DNS — `localhost`, `host.docker.internal`, `host.containers.internal`,
 *         `gateway.docker.internal`, plus any name ending in `.localhost`,
 *         `.dev.localhost`, or `.dev.internal`. Wildcard entries (`*.foo`)
 *         are evaluated by stripping the leading `*.` and matching the
 *         remainder against the same rules.
 *   IPv4 — loopback (127.0.0.0/8), private (10/8, 172.16/12, 192.168/16),
 *          link-local (169.254/16).
 *   IPv6 — loopback (::1), unique-local (fc00::/7), link-local (fe80::/10).
 *
 * Fail-closed on anything we can't fully read: a missing, undecodable, empty,
 * or non-dNSName/iPAddress SAN set is rejected outright rather than being
 * treated as "nothing to object to". See `scanSanEntries`.
 */
export function validateLocalSans(cert: DevCert): SanLocalValidationResult {
  const scan = scanSanEntries(cert);
  if (!scan.ok) {
    return {
      ok: false,
      reason: scan.reason,
      nonLocalEntries: [],
      detail: scan.detail,
    };
  }

  const nonLocalEntries = scan.entries.filter((entry) =>
    entry.type === "dns"
      ? !isLocalDnsName(entry.value)
      : !isLocalIp(entry.value)
  );

  if (nonLocalEntries.length > 0) {
    return { ok: false, reason: "non-local", nonLocalEntries };
  }
  return { ok: true, nonLocalEntries: [] };
}

/**
 * Read a cert's SubjectAlternativeName entries, or say precisely why they
 * can't be read.
 *
 * Every rejection here is deliberate rather than a silent drop, because the
 * caller's next step is installing the cert into an OS trust store. Three
 * cases that a "collect what we recognize and ignore the rest" reader would
 * have waved through:
 *
 * - **No SAN extension / an empty one.** Nothing to scope-check, so the
 *   local-only restriction has nothing to bite on. No genuine ASP.NET dev
 *   cert looks like this (the canonical one carries seven entries), and a
 *   cert with no SAN can't authenticate a hostname to any modern client
 *   anyway — so there's no legitimate reason to trust one.
 * - **A GeneralName type other than dNSName / iPAddress** (rfc822Name,
 *   uniformResourceIdentifier, directoryName, otherName…). These aren't
 *   used for TLS server identity, so ignoring them is defensible on paper —
 *   but it means reporting "SANs are local-only" about a cert we only
 *   partially inspected. A dev cert has no business carrying them, so
 *   rejecting costs nothing real and keeps the report honest.
 * - **Undecodable SAN DER.** `@peculiar/x509` parses extensions lazily and
 *   throws from `getExtension`, so this used to surface as an exception that
 *   happened to be caught two frames up in the accept handler and mapped to
 *   a generic parse failure. That made fail-closed an accident of the call
 *   site: adding a `try/catch` here — the obvious defensive edit — would
 *   have silently turned it into fail-open. It's now explicit and local.
 */
export function scanSanEntries(cert: DevCert): SanScanResult {
  let items: { type?: string; value?: string }[];
  try {
    const ext = cert.inner.getExtension(SAN_EXTENSION_OID);
    if (!ext) return { ok: false, reason: "missing" };

    // @peculiar/x509 exposes SubjectAlternativeNameExtension with parsed
    // `names` (a GeneralNames sequence). Walking it via the wrapper avoids
    // re-implementing ASN.1 parsing here.
    const names = (
      ext as unknown as {
        names?: { items?: { type?: string; value?: string }[] };
      }
    ).names;
    if (!Array.isArray(names?.items)) {
      return {
        ok: false,
        reason: "unparseable",
        detail: "SAN extension did not decode into GeneralNames",
      };
    }
    items = names.items;
  } catch (err: unknown) {
    return {
      ok: false,
      reason: "unparseable",
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  const entries: NonLocalSanEntry[] = [];
  for (const item of items) {
    if (item.type === "dns" && typeof item.value === "string") {
      entries.push({ type: "dns", value: item.value });
    } else if (
      (item.type === "ip" || item.type === "ipAddress") &&
      typeof item.value === "string"
    ) {
      entries.push({ type: "ip", value: item.value });
    } else {
      return {
        ok: false,
        reason: "unsupported-entry",
        detail: `SAN entry of type '${item.type ?? "unknown"}'`,
      };
    }
  }

  if (entries.length === 0) return { ok: false, reason: "no-host-entries" };
  return { ok: true, entries };
}

const SAN_EXTENSION_OID = "2.5.29.17";

// ---------------------------------------------------------------------------
// Trust-anchor shape validation — the second half of the container-push
// gate. `validateLocalSans` asks "what names is this cert scoped to?", which
// only constrains anything if the cert is a leaf that can authenticate ONLY
// itself. A CA certificate's own SANs say nothing about what it may issue
// for, so without the check below the SAN restriction is trivially bypassed:
// push a CA whose own SANs are `localhost`, then sign a leaf for any name
// you like and the host trusts the chain.
// ---------------------------------------------------------------------------

export type LeafTrustRejectReason =
  /** basicConstraints / EKU present but undecodable. */
  | "unreadable"
  /** No basicConstraints extension, so "is this a CA?" is unanswerable. */
  | "missing-basic-constraints"
  /** basicConstraints says cA=TRUE. */
  | "is-certificate-authority"
  /** No extendedKeyUsage, which most stacks read as "any purpose". */
  | "missing-eku"
  /** EKU contains anyExtendedKeyUsage, which re-opens "any purpose". */
  | "eku-any-purpose"
  /** EKU present but without id-kp-serverAuth. */
  | "eku-no-server-auth";

export interface LeafTrustShapeResult {
  ok: boolean;
  reason?: LeafTrustRejectReason;
  detail?: string;
}

const BASIC_CONSTRAINTS_OID = "2.5.29.19";
const EKU_OID = "2.5.29.37";
const EKU_SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
const EKU_ANY_PURPOSE_OID = "2.5.29.37.0";

/**
 * Check that a certificate is safe to install as a trust anchor for TLS and
 * nothing more: it must be a leaf (cannot issue other certificates) and it
 * must be scoped to server authentication.
 *
 * Required, not merely preferred, because `trustCertificate` puts the cert in
 * `CurrentUser\Root` on Windows, the login keychain's SSL trust settings on
 * macOS, and the .NET Root store + OpenSSL CApath + browser NSS databases
 * (with the `C` "trusted CA" flag) on Linux. Those are CA positions. Whether
 * the cert can actually *act* as a CA from there comes down to
 * basicConstraints — which nothing checked before this.
 *
 * Both extensions are required to be **present**, not just non-contradictory.
 * An absent basicConstraints leaves "is this a CA?" to each validator's
 * historical quirks, and an absent EKU reads as "any purpose" on Windows,
 * where `certutil -addstore Root` applies no policy constraint of its own.
 * Every genuine ASP.NET dev cert carries both — ours via `generateCertificate`
 * and .NET's via `CertificateManager` — so requiring them rejects nothing
 * legitimate.
 *
 * Additional specific EKUs (say `clientAuth`) are tolerated; only
 * `anyExtendedKeyUsage` is refused, since it is equivalent to no constraint.
 */
export function validateLeafTrustShape(cert: DevCert): LeafTrustShapeResult {
  let isCa: boolean | undefined;
  let ekuUsages: string[] | undefined;

  try {
    const bc = cert.inner.getExtension(BASIC_CONSTRAINTS_OID) as unknown as
      | { ca?: boolean }
      | null;
    if (!bc) return { ok: false, reason: "missing-basic-constraints" };
    isCa = bc.ca;

    const eku = cert.inner.getExtension(EKU_OID) as unknown as
      | { usages?: string[] }
      | null;
    ekuUsages = eku ? eku.usages : undefined;
    if (eku && !Array.isArray(ekuUsages)) {
      return {
        ok: false,
        reason: "unreadable",
        detail: "extendedKeyUsage did not decode into a usage list",
      };
    }
    if (!eku) return { ok: false, reason: "missing-eku" };
  } catch (err: unknown) {
    return {
      ok: false,
      reason: "unreadable",
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  if (typeof isCa !== "boolean") {
    return {
      ok: false,
      reason: "unreadable",
      detail: "basicConstraints did not decode a cA flag",
    };
  }
  if (isCa) return { ok: false, reason: "is-certificate-authority" };

  const usages = ekuUsages ?? [];
  if (usages.includes(EKU_ANY_PURPOSE_OID)) {
    return { ok: false, reason: "eku-any-purpose" };
  }
  if (!usages.includes(EKU_SERVER_AUTH_OID)) {
    return {
      ok: false,
      reason: "eku-no-server-auth",
      detail: usages.join(", "),
    };
  }

  return { ok: true };
}

function isLocalDnsName(name: string): boolean {
  let candidate = name.trim().toLowerCase();
  if (candidate.length === 0) return false;
  // Strip trailing root-zone dot ("localhost." → "localhost") so the suffix
  // checks match either form.
  if (candidate.endsWith(".")) candidate = candidate.slice(0, -1);
  // Wildcard entries: strip the leading `*.` and evaluate the remainder.
  // `*.foo.dev.localhost` is allowed iff `foo.dev.localhost` is. A bare
  // wildcard `*` is treated as non-local.
  if (candidate.startsWith("*.")) {
    candidate = candidate.slice(2);
    if (candidate.length === 0) return false;
  } else if (candidate === "*") {
    return false;
  }

  if (ALLOWED_DNS_EXACT.has(candidate)) return true;
  for (const suffix of ALLOWED_DNS_SUFFIXES) {
    // Suffix matches as "ends with .suffix" OR "equals suffix without the
    // leading dot" — so both `foo.dev.internal` and `dev.internal` (the
    // wildcard-stripped form of `*.dev.internal`) match a `.dev.internal`
    // suffix entry.
    const bareSuffix = suffix.startsWith(".") ? suffix.slice(1) : suffix;
    if (candidate.endsWith(suffix)) return true;
    if (candidate === bareSuffix) return true;
  }
  return false;
}

function isLocalIp(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return false;

  if (trimmed.includes(":")) return isLocalIpv6(trimmed);
  return isLocalIpv4(trimmed);
}

function isLocalIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  const octets: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
    octets.push(n);
  }
  // 127.0.0.0/8 — loopback
  if (octets[0] === 127) return true;
  // 10.0.0.0/8 — private
  if (octets[0] === 10) return true;
  // 172.16.0.0/12 — private
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  // 192.168.0.0/16 — private
  if (octets[0] === 192 && octets[1] === 168) return true;
  // 169.254.0.0/16 — link-local
  if (octets[0] === 169 && octets[1] === 254) return true;
  return false;
}

function isLocalIpv6(value: string): boolean {
  const normalized = expandIpv6(value);
  if (!normalized) return false;

  // ::1 — loopback (all-zero groups except the last == 1)
  if (
    normalized.slice(0, 7).every((g) => g === 0) &&
    normalized[7] === 1
  ) {
    return true;
  }

  const firstByte = (normalized[0] >> 8) & 0xff;

  // fc00::/7 — unique local addresses (RFC 4193). Top 7 bits = 1111 110x
  // i.e. firstByte in 0xfc..0xfd.
  if (firstByte === 0xfc || firstByte === 0xfd) return true;

  // fe80::/10 — link-local. First 10 bits = 1111 1110 10xx
  // i.e. firstByte == 0xfe AND second-byte top 2 bits == 10 (0x80..0xbf).
  if (firstByte === 0xfe) {
    const secondByte = normalized[0] & 0xff;
    if (secondByte >= 0x80 && secondByte <= 0xbf) return true;
  }

  return false;
}

/**
 * Expand an IPv6 address into its 8 16-bit groups, handling `::` shorthand.
 * Returns null on a malformed address. Treats trailing IPv4-mapped notation
 * (`::ffff:127.0.0.1`) as malformed since dev certs don't use it — callers
 * that hit such a SAN entry will fall through to "non-local" by default.
 */
function expandIpv6(value: string): number[] | null {
  if (value.includes(".")) return null;

  const doubleColonIdx = value.indexOf("::");
  let leftPart: string;
  let rightPart: string;
  if (doubleColonIdx === -1) {
    leftPart = value;
    rightPart = "";
  } else {
    leftPart = value.slice(0, doubleColonIdx);
    rightPart = value.slice(doubleColonIdx + 2);
    if (leftPart.includes("::") || rightPart.includes("::")) return null;
  }

  const leftGroups = leftPart === "" ? [] : leftPart.split(":");
  const rightGroups = rightPart === "" ? [] : rightPart.split(":");

  if (leftGroups.length + rightGroups.length > 8) return null;
  if (doubleColonIdx === -1 && leftGroups.length !== 8) return null;

  for (const g of [...leftGroups, ...rightGroups]) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
  }

  const missing = 8 - leftGroups.length - rightGroups.length;
  const groups: number[] = [];
  for (const g of leftGroups) groups.push(parseInt(g, 16));
  for (let i = 0; i < missing; i++) groups.push(0);
  for (const g of rightGroups) groups.push(parseInt(g, 16));

  return groups.length === 8 ? groups : null;
}
