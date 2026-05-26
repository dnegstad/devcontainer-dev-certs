import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { writeBundle, type BundleCertEntry } from "../src/bundle/writer";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-writer-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function makeEntry(overrides: Partial<BundleCertEntry> = {}): BundleCertEntry {
  return {
    name: "aspnetcore-dev",
    thumbprint: "ABCDEF1234567890",
    kind: "dotnet-dev",
    hostPfxPath: path.join(tmpDir, "aspnetcore-dev.pfx"),
    hostPemPath: path.join(tmpDir, "aspnetcore-dev.pem"),
    hostPemKeyPath: path.join(tmpDir, "aspnetcore-dev.key"),
    trustInContainer: true,
    ...overrides,
  };
}

function readBundle(bundlePath: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(bundlePath, "utf-8")) as Record<string, unknown>;
}

describe("writeBundle", () => {
  it("writes a bundle.json with the schema URL and a $schema pointer", () => {
    const bundlePath = writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [makeEntry()],
    });
    expect(bundlePath).toBe(path.join(tmpDir, "bundle.json"));
    const bundle = readBundle(bundlePath);
    expect(bundle.$schema).toContain("bundle.schema.json");
    expect(Array.isArray(bundle.certs)).toBe(true);
  });

  it("rewrites host paths under the out-dir to container-mount paths", () => {
    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [makeEntry()],
    });
    const bundle = readBundle(path.join(tmpDir, "bundle.json"));
    const cert = (bundle.certs as Record<string, string>[])[0];
    expect(cert.pemPath).toBe("/host-dev-certs/aspnetcore-dev.pem");
    expect(cert.pfxPath).toBe("/host-dev-certs/aspnetcore-dev.pfx");
    expect(cert.pemKeyPath).toBe("/host-dev-certs/aspnetcore-dev.key");
  });

  it("leaves paths outside the out-dir untouched (no implicit copy assumed)", () => {
    const externalPath = path.join(os.tmpdir(), "elsewhere.pem");
    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [
        makeEntry({
          hostPemPath: externalPath,
          hostPfxPath: null,
          hostPemKeyPath: null,
        }),
      ],
    });
    const bundle = readBundle(path.join(tmpDir, "bundle.json"));
    const cert = (bundle.certs as Record<string, string>[])[0];
    expect(cert.pemPath).toBe(externalPath);
  });

  it("strips trailing slashes from containerMount so paths don't double-slash", () => {
    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs/",
      entries: [makeEntry()],
    });
    const bundle = readBundle(path.join(tmpDir, "bundle.json"));
    const cert = (bundle.certs as Record<string, string>[])[0];
    expect(cert.pemPath).toBe("/host-dev-certs/aspnetcore-dev.pem");
  });

  it("omits pfxPath / pemKeyPath when they're null (cert-only entries)", () => {
    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [
        makeEntry({
          hostPfxPath: null,
          hostPemKeyPath: null,
        }),
      ],
    });
    const bundle = readBundle(path.join(tmpDir, "bundle.json"));
    const cert = (bundle.certs as Record<string, unknown>[])[0];
    expect("pfxPath" in cert).toBe(false);
    expect("pemKeyPath" in cert).toBe(false);
    expect(cert.pemPath).toBeDefined();
  });

  it("emits each entry with its declared kind and trustInContainer flag", () => {
    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [
        makeEntry({ name: "corp-ca", kind: "user", trustInContainer: false }),
      ],
    });
    const bundle = readBundle(path.join(tmpDir, "bundle.json"));
    const cert = (bundle.certs as Record<string, unknown>[])[0];
    expect(cert.name).toBe("corp-ca");
    expect(cert.kind).toBe("user");
    expect(cert.trustInContainer).toBe(false);
  });

  it("includes extraDestinations when provided, omits the key when absent", () => {
    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [makeEntry()],
      extraDestinations: [{ path: "/etc/nginx/certs", format: "pem" }],
    });
    const withExtras = readBundle(path.join(tmpDir, "bundle.json"));
    expect(withExtras.extraDestinations).toEqual([
      { path: "/etc/nginx/certs", format: "pem" },
    ]);

    writeBundle({
      hostOutDir: tmpDir,
      containerMount: "/host-dev-certs",
      entries: [makeEntry()],
    });
    const withoutExtras = readBundle(path.join(tmpDir, "bundle.json"));
    expect("extraDestinations" in withoutExtras).toBe(false);
  });
});
