import { describe, it, expect } from "vitest";
import { parseExtraCertDestinations } from "../src/util/destinations";

describe("parseExtraCertDestinations", () => {
  it("returns empty result for empty/undefined input", () => {
    expect(parseExtraCertDestinations("").destinations).toEqual([]);
    expect(parseExtraCertDestinations(undefined).destinations).toEqual([]);
    expect(parseExtraCertDestinations(null).destinations).toEqual([]);
  });

  it("parses trailing-slash directory targets with a format", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/etc/nginx/certs/=pem"
    );
    expect(errors).toEqual([]);
    expect(destinations).toEqual([
      { path: "/etc/nginx/certs/", format: "pem", kind: "directory" },
    ]);
  });

  it("defaults missing format to 'all'", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/var/myapp/"
    );
    expect(errors).toEqual([]);
    expect(destinations).toEqual([
      { path: "/var/myapp/", format: "all", kind: "directory" },
    ]);
  });

  it("detects ${name} file-template targets", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/var/app/${name}.pem=pem"
    );
    expect(errors).toEqual([]);
    expect(destinations[0].kind).toBe("file-template");
    expect(destinations[0].format).toBe("pem");
  });

  it("treats path without ${name} or trailing slash as single-file target", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/etc/app/bundle.pem=pem-bundle"
    );
    expect(errors).toEqual([]);
    expect(destinations[0].kind).toBe("file-single");
    expect(destinations[0].format).toBe("pem-bundle");
  });

  it("parses multi-entry csv", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/etc/nginx/certs/=pem, /etc/app/bundle.pem=pem-bundle,/var/myapp/"
    );
    expect(errors).toEqual([]);
    expect(destinations).toHaveLength(3);
    expect(destinations.map((d) => d.kind)).toEqual([
      "directory",
      "file-single",
      "directory",
    ]);
    expect(destinations.map((d) => d.format)).toEqual([
      "pem",
      "pem-bundle",
      "all",
    ]);
  });

  it("reports unknown format as an error and skips the entry", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/etc/app/=der"
    );
    expect(destinations).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("unknown format");
  });

  it("reports non-absolute paths as errors and skips them", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "relative/path=pem,/abs/=pem"
    );
    expect(destinations).toHaveLength(1);
    expect(destinations[0].path).toBe("/abs/");
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("not an absolute path");
  });
});
