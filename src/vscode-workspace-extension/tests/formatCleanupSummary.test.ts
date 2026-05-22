import { describe, it, expect } from "vitest";
import { formatCleanupSummary } from "../src/extension";
import type {
  CleanupResult,
  StaleArtifact,
  StaleDevCert,
} from "../src/cleanupCerts";

// Minimal stale artifact/cert builders so the summary fixtures stay
// readable. None of the fields except the location are observed by
// `formatCleanupSummary`, so the rest is filler.
function artifact(location: StaleArtifact["location"]): StaleArtifact {
  return { location, fullPath: `/fake/${location}`, identifier: "X" };
}
function cert(): StaleDevCert {
  return {
    thumbprint: "ABCDEF".padEnd(40, "F"),
    artifacts: [artifact("my-store")],
  };
}

function result(overrides: Partial<CleanupResult> = {}): CleanupResult {
  return {
    removedCerts: [],
    removed: [],
    failed: [],
    rehashedTrustDir: false,
    ...overrides,
  };
}

describe("formatCleanupSummary", () => {
  it("reports zero removed when nothing was unlinked", () => {
    expect(formatCleanupSummary(result())).toBe(
      "Dev Certs: Removed 0 other dev certificate(s) from this Dev Container, preserving the extension-managed certificate."
    );
  });

  it("reports the count of fully-removed certs", () => {
    expect(
      formatCleanupSummary(result({ removedCerts: [cert(), cert()] }))
    ).toBe(
      "Dev Certs: Removed 2 other dev certificate(s) from this Dev Container, preserving the extension-managed certificate."
    );
  });

  it("appends the failed-files suffix only when failures are present", () => {
    expect(
      formatCleanupSummary(
        result({
          removedCerts: [cert()],
          failed: [{ thumbprint: "F", artifact: artifact("root-store"), error: "EACCES" }],
        })
      )
    ).toBe(
      "Dev Certs: Removed 1 other dev certificate(s) from this Dev Container, preserving the extension-managed certificate (1 file(s) failed)."
    );
  });

  it("appends the rehash suffix only when the trust dir was rehashed", () => {
    expect(
      formatCleanupSummary(
        result({ removedCerts: [cert()], rehashedTrustDir: true })
      )
    ).toBe(
      "Dev Certs: Removed 1 other dev certificate(s) from this Dev Container, preserving the extension-managed certificate, container trust directory rehashed."
    );
  });

  it("includes both suffixes when both apply", () => {
    expect(
      formatCleanupSummary(
        result({
          removedCerts: [cert(), cert()],
          failed: [
            { thumbprint: "F1", artifact: artifact("root-store"), error: "EACCES" },
            { thumbprint: "F2", artifact: artifact("trust-dir"), error: "EBUSY" },
          ],
          rehashedTrustDir: true,
        })
      )
    ).toBe(
      "Dev Certs: Removed 2 other dev certificate(s) from this Dev Container, preserving the extension-managed certificate (2 file(s) failed), container trust directory rehashed."
    );
  });
});
