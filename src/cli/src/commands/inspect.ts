import * as fs from "fs";
import {
  type DevCert,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  MINIMUM_CERTIFICATE_VERSION,
  getCertificateVersion,
  isValidDevCert,
  loadPfx,
  loadPemPair,
  validateLocalSans,
  collectSanEntries,
} from "@devcontainer-dev-certs/shared";

export interface InspectCommandOptions {
  json?: boolean;
}

interface InspectReport {
  path: string;
  format: "pfx" | "pem";
  subjectCN: string | null;
  thumbprintSha1: string;
  thumbprintSha256: string;
  notBefore: string;
  notAfter: string;
  expiresInDays: number;
  hasPrivateKey: boolean;
  devCertOidPresent: boolean;
  devCertVersion: number | null;
  isValidDevCert: boolean;
  sans: Array<{ type: string; value: string }>;
  nonLocalSans: Array<{ type: string; value: string }>;
  warnings: string[];
}

/**
 * `dcdc inspect <path>` — load a PFX or PEM (cert-only) and report its
 * vital statistics. Text by default; `--json` switches to machine-readable.
 */
export async function runInspect(
  certPath: string,
  options: InspectCommandOptions
): Promise<void> {
  if (!fs.existsSync(certPath)) {
    throw new Error(`File not found: ${certPath}`);
  }

  const report = await buildReport(certPath);
  if (options.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    process.stdout.write(formatTextReport(report));
  }
}

/**
 * Locate a sibling PEM private key next to a cert PEM, returning the
 * first match or null. Probes both naming conventions:
 *
 * - `<stem>.key` — what our exporter writes, what `openssl` writes by
 *   convention.
 * - `<filename>.key` — what `dotnet dev-certs --format PEM
 *   --export-path foo.pem` writes (`foo.pem.key`).
 */
function findSiblingKey(certPath: string): string | null {
  const stem = certPath.replace(/\.[^.]+$/, "");
  for (const candidate of [`${stem}.key`, `${certPath}.key`]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

async function buildReport(certPath: string): Promise<InspectReport> {
  const ext = certPath.toLowerCase();
  const warnings: string[] = [];

  let cert: DevCert;
  let hasPrivateKey: boolean;
  let format: "pfx" | "pem";

  if (ext.endsWith(".pfx") || ext.endsWith(".p12")) {
    format = "pfx";
    const loaded = await loadPfx(certPath);
    cert = loaded.cert;
    hasPrivateKey = loaded.key !== null;
  } else {
    format = "pem";
    // PEM inspection: opportunistically look for a sibling key. Two
    // conventions are in the wild — `stem.key` (our exporter + openssl)
    // and `filename.pem.key` (`dotnet dev-certs --format PEM
    // --export-path foo.pem` writes `foo.pem.key`). Probe both so
    // dotnet-generated key pairs aren't misreported as cert-only.
    const keyPath = findSiblingKey(certPath);
    const loaded = loadPemPair(certPath, keyPath);
    cert = loaded.cert;
    hasPrivateKey = loaded.key !== null;
  }

  const devCertOidPresent = cert.hasExtension(ASPNET_HTTPS_OID);
  const devCertVersion = devCertOidPresent ? getCertificateVersion(cert) : null;
  const sansAll = collectSanEntries(cert).map((entry) => ({
    type: entry.type,
    value: entry.value,
  }));
  const localCheck = validateLocalSans(cert);

  if (devCertOidPresent && devCertVersion !== null) {
    if (devCertVersion < MINIMUM_CERTIFICATE_VERSION) {
      warnings.push(
        `Dev-cert version byte ${devCertVersion} is below the minimum (${MINIMUM_CERTIFICATE_VERSION}). Regenerate with a current dotnet SDK.`
      );
    }
    if (devCertVersion > CURRENT_CERTIFICATE_VERSION) {
      warnings.push(
        `Dev-cert version byte ${devCertVersion} is newer than this build expects (${CURRENT_CERTIFICATE_VERSION}). The cert may use features we don't know about.`
      );
    }
  }
  if (!hasPrivateKey && format === "pfx") {
    warnings.push("PFX contains no private key — Kestrel will not be able to serve TLS from this file.");
  }
  if (localCheck.nonLocalEntries.length > 0) {
    warnings.push(
      `${localCheck.nonLocalEntries.length} non-local SAN entr${localCheck.nonLocalEntries.length === 1 ? "y" : "ies"} present — this cert grants TLS to names beyond the developer machine.`
    );
  }

  const now = Date.now();
  const expiresInDays = Math.floor(
    (cert.notAfter.getTime() - now) / 86400_000
  );

  return {
    path: certPath,
    format,
    subjectCN: cert.subjectCN ?? null,
    thumbprintSha1: cert.thumbprintSha1,
    thumbprintSha256: cert.thumbprint,
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
    expiresInDays,
    hasPrivateKey,
    devCertOidPresent,
    devCertVersion,
    isValidDevCert: isValidDevCert(cert),
    sans: sansAll,
    nonLocalSans: localCheck.nonLocalEntries.map((entry) => ({
      type: entry.type,
      value: entry.value,
    })),
    warnings,
  };
}

function formatTextReport(report: InspectReport): string {
  const lines: string[] = [];
  lines.push(`File:                 ${report.path}`);
  lines.push(`Format:               ${report.format.toUpperCase()}`);
  lines.push(`Subject CN:           ${report.subjectCN ?? "(none)"}`);
  lines.push(`Thumbprint (SHA-1):   ${report.thumbprintSha1}`);
  lines.push(`Thumbprint (SHA-256): ${report.thumbprintSha256}`);
  lines.push(`Valid from:           ${report.notBefore}`);
  lines.push(`Valid until:          ${report.notAfter}`);
  lines.push(`Expires in:           ${report.expiresInDays} day(s)`);
  lines.push(`Has private key:      ${report.hasPrivateKey ? "yes" : "no"}`);
  lines.push(`ASP.NET dev-cert OID: ${report.devCertOidPresent ? "yes" : "no"}`);
  if (report.devCertVersion !== null) {
    lines.push(`  Version byte:       ${report.devCertVersion}`);
  }
  lines.push(`Valid as dev cert:    ${report.isValidDevCert ? "yes" : "no"}`);
  lines.push(`SANs:`);
  if (report.sans.length === 0) {
    lines.push(`  (none)`);
  } else {
    for (const san of report.sans) {
      const flag = report.nonLocalSans.some(
        (n) => n.type === san.type && n.value === san.value
      )
        ? " [non-local]"
        : "";
      lines.push(`  ${san.type}:${san.value}${flag}`);
    }
  }
  if (report.warnings.length > 0) {
    lines.push(`Warnings:`);
    for (const w of report.warnings) lines.push(`  - ${w}`);
  }
  return lines.join("\n") + "\n";
}
