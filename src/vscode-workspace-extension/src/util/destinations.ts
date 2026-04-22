import type { DestFormat } from "@devcontainer-dev-certs/shared";

export type TargetKind = "directory" | "file-template" | "file-single";

export interface ExtraDestination {
  /** Original path as configured (normalized — trailing slash preserved for directory targets). */
  path: string;
  format: DestFormat;
  kind: TargetKind;
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
 *   <abs-path>[=<format>]        (comma-separated)
 *   format ∈ pem|key|pem-bundle|pfx|all   (default: all)
 *
 * Path rules:
 *   - Trailing `/` → directory target. Files are written as `${name}.${ext}`.
 *   - Else if basename contains `${name}` → per-cert file template.
 *   - Else → single-file target (valid only when the bundle has exactly one
 *     cert; the caller enforces that at write time).
 */
export function parseExtraCertDestinations(raw: string | undefined | null): ParsedDestinations {
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
    const format = formatPart as DestFormat;

    let kind: TargetKind;
    if (pathPart.endsWith("/")) {
      kind = "directory";
    } else {
      const basename = pathPart.slice(pathPart.lastIndexOf("/") + 1);
      kind = basename.includes("${name}") ? "file-template" : "file-single";
    }

    destinations.push({ path: pathPart, format, kind });
  }

  return { destinations, errors };
}
