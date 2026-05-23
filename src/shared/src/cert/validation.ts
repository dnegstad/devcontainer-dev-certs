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

export interface SanLocalValidationResult {
  ok: boolean;
  nonLocalEntries: NonLocalSanEntry[];
}

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
 * A SAN entry that doesn't parse is treated as non-local — fail-closed.
 */
export function validateLocalSans(cert: DevCert): SanLocalValidationResult {
  const sanEntries = collectSanEntries(cert);
  const nonLocalEntries: NonLocalSanEntry[] = [];

  for (const entry of sanEntries) {
    if (entry.type === "dns") {
      if (!isLocalDnsName(entry.value)) {
        nonLocalEntries.push(entry);
      }
    } else {
      if (!isLocalIp(entry.value)) {
        nonLocalEntries.push(entry);
      }
    }
  }

  return { ok: nonLocalEntries.length === 0, nonLocalEntries };
}

/**
 * Extract DNS + IP entries from a cert's SubjectAlternativeName extension.
 * Returns an empty list when the extension is missing — callers treat that
 * as "no entries to inspect"; the surrounding `isValidDevCert` check
 * separately enforces CN=localhost.
 */
export function collectSanEntries(cert: DevCert): NonLocalSanEntry[] {
  const ext = cert.inner.getExtension(SAN_EXTENSION_OID);
  if (!ext) return [];

  // @peculiar/x509 exposes SubjectAlternativeNameExtension with parsed
  // `names` (a GeneralNames sequence). Walking it via the wrapper avoids
  // re-implementing ASN.1 parsing here.
  const names = (
    ext as unknown as {
      names?: { items?: { type?: string; value?: string }[] };
    }
  ).names;
  const items = names?.items ?? [];

  const out: NonLocalSanEntry[] = [];
  for (const item of items) {
    if (item.type === "dns" && typeof item.value === "string") {
      out.push({ type: "dns", value: item.value });
    } else if (
      (item.type === "ip" || item.type === "ipAddress") &&
      typeof item.value === "string"
    ) {
      out.push({ type: "ip", value: item.value });
    }
  }
  return out;
}

const SAN_EXTENSION_OID = "2.5.29.17";

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
    if (candidate.endsWith(suffix)) return true;
    // Bare suffix without leading dot — `.localhost` matches `localhost`
    // via the exact set above, so we don't need a separate equality here.
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
