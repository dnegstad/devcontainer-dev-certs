import { describe, it, expect } from "vitest";
import { parseExtraCertDestinations } from "../src/util/destinations";

describe("parseExtraCertDestinations", () => {
  it("returns empty result for empty/undefined/null input", () => {
    expect(parseExtraCertDestinations("").destinations).toEqual([]);
    expect(parseExtraCertDestinations(undefined).destinations).toEqual([]);
    expect(parseExtraCertDestinations(null).destinations).toEqual([]);
  });

  it("parses a directory entry with an explicit format", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/etc/nginx/certs=pem"
    );
    expect(errors).toEqual([]);
    expect(destinations).toEqual([
      { path: "/etc/nginx/certs", format: "pem" },
    ]);
  });

  it("defaults missing format to 'all'", () => {
    const { destinations, errors } = parseExtraCertDestinations("/var/myapp");
    expect(errors).toEqual([]);
    expect(destinations).toEqual([{ path: "/var/myapp", format: "all" }]);
  });

  it("strips trailing slashes from directory paths", () => {
    const { destinations } = parseExtraCertDestinations(
      "/etc/nginx/certs/=pem"
    );
    expect(destinations).toEqual([
      { path: "/etc/nginx/certs", format: "pem" },
    ]);
  });

  it("parses multi-entry csv", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "/etc/nginx/certs=pem, /etc/app=pem-bundle,/var/myapp"
    );
    expect(errors).toEqual([]);
    expect(destinations).toEqual([
      { path: "/etc/nginx/certs", format: "pem" },
      { path: "/etc/app", format: "pem-bundle" },
      { path: "/var/myapp", format: "all" },
    ]);
  });

  it("reports unknown format as an error and skips the entry", () => {
    const { destinations, errors } = parseExtraCertDestinations("/etc/app=der");
    expect(destinations).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("unknown format");
  });

  it("reports non-absolute paths as errors and skips them", () => {
    const { destinations, errors } = parseExtraCertDestinations(
      "relative/path=pem,/abs=pem"
    );
    expect(destinations).toEqual([{ path: "/abs", format: "pem" }]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("not an absolute path");
  });
});
