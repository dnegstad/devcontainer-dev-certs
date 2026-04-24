import type { DestFormat } from "@devcontainer-dev-certs/shared";

export interface ExtraDestination {
  /** Absolute directory path, with any trailing slash stripped. */
  path: string;
  format: DestFormat;
}

export interface ParsedDestinations {
  destinations: ExtraDestination[];
  errors: string[];
}

const VALID_FORMATS: readonly DestFormat[] = [
  "pem",
  "key",
  "pem-bundle",
  "pfx",
  "all",
];

/**
 * Parse the extraCertDestinations grammar:
 *   <abs-dir>[=<format>]        (comma-separated)
 *   format ∈ pem|key|pem-bundle|pfx|all   (default: all)
 *
 * Every entry is a directory: each synced cert is written as
 * `${cert.name}.${ext}` (or `${cert.name}-bundle.pem` for pem-bundle) under
 * that directory. Trailing slashes are accepted but not required.
 */
export function parseExtraCertDestinations(
  raw: string | undefined | null
): ParsedDestinations {
  const destinations: ExtraDestination[] = [];
  const errors: string[] = [];

  if (!raw) return { destinations, errors };

  const entries = raw
    .split(",")
    .map((e) => e.trim())
    .filter((e) => e.length > 0);

  for (const entry of entries) {
    const eqIdx = entry.indexOf("=");
    let pathPart = entry;
    let formatPart = "all";
    if (eqIdx >= 0) {
      pathPart = entry.slice(0, eqIdx).trim();
      formatPart = entry.slice(eqIdx + 1).trim() || "all";
    }

    if (!pathPart.startsWith("/")) {
      errors.push(
        `extraCertDestinations entry '${entry}' is not an absolute path.`
      );
      continue;
    }

    if (!VALID_FORMATS.includes(formatPart as DestFormat)) {
      errors.push(
        `extraCertDestinations entry '${entry}' has unknown format '${formatPart}'.`
      );
      continue;
    }

    destinations.push({
      path: pathPart.replace(/\/+$/, "") || "/",
      format: formatPart as DestFormat,
    });
  }

  return { destinations, errors };
}
