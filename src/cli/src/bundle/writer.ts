import * as fs from "fs";
import * as path from "path";

/**
 * Schema URL the manual-setup example references. Including `$schema` in the
 * generated bundle.json lets editors like VS Code (and language servers like
 * jsonls / coc-jsonls) pick up validation + autocomplete automatically.
 */
export const BUNDLE_SCHEMA_URL =
  "https://raw.githubusercontent.com/dnegstad/devcontainer-dev-certs/main/schema/bundle.schema.json";

export interface BundleCertEntry {
  /** Filename stem (e.g. `aspnetcore-dev`). */
  name: string;
  /** SHA-1 thumbprint, uppercase hex, no separators. */
  thumbprint: string;
  /** `dotnet-dev` (auto-generated) or `user` (user-supplied). */
  kind: "dotnet-dev" | "user";
  /** Host filesystem absolute path to the PFX, or null if not produced. */
  hostPfxPath: string | null;
  /** Host filesystem absolute path to the PEM cert. */
  hostPemPath: string;
  /** Host filesystem absolute path to the PEM key, or null if not produced. */
  hostPemKeyPath: string | null;
  /**
   * Whether the in-container installer should plant this cert into the OS
   * trust store (CA bundle + .NET root) inside the container. `true` for
   * default `dotnet-dev` certs.
   */
  trustInContainer: boolean;
}

export interface WriteBundleOptions {
  /** Absolute path to the host out-dir holding the cert files. */
  hostOutDir: string;
  /**
   * Container-side path the host out-dir bind-mounts to (e.g.
   * `/host-dev-certs`). Bundle paths are rewritten to this prefix because the
   * in-container installer is what reads bundle.json — not anything on the
   * host.
   */
  containerMount: string;
  entries: BundleCertEntry[];
  /**
   * Extra destinations to write into bundle.json — directories inside the
   * container that the installer will additionally drop artifacts into
   * (e.g. `/etc/nginx/certs`). Optional; mirrors the existing schema field.
   */
  extraDestinations?: Array<{ path: string; format?: string }>;
}

/**
 * Write `bundle.json` into the host out-dir. The on-disk JSON references
 * the *container-side* paths (mount target + filename), because that file is
 * consumed by the in-container `devcontainer-dev-certs-install` script — not
 * by anything that sees the host filesystem.
 */
export function writeBundle(options: WriteBundleOptions): string {
  const bundlePath = path.join(options.hostOutDir, "bundle.json");

  const certs = options.entries.map((entry) => {
    const obj: Record<string, unknown> = {
      name: entry.name,
      kind: entry.kind,
      thumbprint: entry.thumbprint,
      pemPath: containerize(entry.hostPemPath, options),
      trustInContainer: entry.trustInContainer,
    };
    if (entry.hostPfxPath) {
      obj.pfxPath = containerize(entry.hostPfxPath, options);
    }
    if (entry.hostPemKeyPath) {
      obj.pemKeyPath = containerize(entry.hostPemKeyPath, options);
    }
    return obj;
  });

  const bundle: Record<string, unknown> = {
    $schema: BUNDLE_SCHEMA_URL,
    certs,
  };
  if (options.extraDestinations && options.extraDestinations.length > 0) {
    bundle.extraDestinations = options.extraDestinations;
  }

  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2) + "\n", {
    mode: 0o644,
  });
  return bundlePath;
}

/**
 * Translate a host-filesystem absolute path under `hostOutDir` into the
 * equivalent container-mount path. Paths outside the out-dir pass through
 * unchanged — the user may have crafted bundle entries that point at
 * already-in-container locations.
 */
function containerize(hostPath: string, options: WriteBundleOptions): string {
  const resolved = path.resolve(hostPath);
  const baseResolved = path.resolve(options.hostOutDir);
  if (resolved.startsWith(baseResolved + path.sep) || resolved === baseResolved) {
    const rel = path.relative(baseResolved, resolved);
    if (!rel) return options.containerMount;
    // Forward slashes always — the container is always POSIX even when the
    // host is Windows.
    const posixRel = rel.split(path.sep).join("/");
    const mount = options.containerMount.replace(/\/+$/, "");
    return `${mount}/${posixRel}`;
  }
  return hostPath;
}
