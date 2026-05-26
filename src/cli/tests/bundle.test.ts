import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
} from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { generateCertificate, exportPfx, exportPem, VALIDITY_DAYS } from "@devcontainer-dev-certs/shared";
import { runBundle } from "../src/commands/bundle";

/**
 * `dcdc bundle` is supposed to flag the silent-broken-bundle case: cert
 * files referenced by the bundle live outside the `--out-dir`, so the
 * containerize step in the writer leaves their absolute host paths
 * verbatim — and the in-container installer (which only ever sees the
 * mount target, not the host filesystem) will fail to read them.
 *
 * These tests drive the warning by spying on stderr and asserting on
 * what the bundle command wrote there.
 */

async function makeCertFilesIn(dir: string): Promise<void> {
  const now = new Date();
  const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400_000);
  const { cert, key } = await generateCertificate(now, expiry);
  await exportPfx(cert, key, dir);
  exportPem(cert, key, dir);
}

const cleanupDirs: string[] = [];

beforeEach(() => {
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of cleanupDirs) fs.rmSync(dir, { recursive: true, force: true });
  cleanupDirs.length = 0;
});

function collectStderr(): string {
  const writeMock = vi.mocked(process.stderr.write);
  return writeMock.mock.calls.map((c) => String(c[0])).join("");
}

describe("dcdc bundle out-of-dir warning", () => {
  it("does not warn when cert files live inside --out-dir", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-test-in-"));
    cleanupDirs.push(dir);
    await makeCertFilesIn(dir);

    await runBundle(path.join(dir, "aspnetcore-dev.pfx"), {
      outDir: dir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const stderr = collectStderr();
    expect(stderr).not.toContain("[warn]");
    expect(stderr).not.toContain("outside --out-dir");
  });

  it("warns when cert files are NOT under --out-dir", async () => {
    const certDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-test-cert-"));
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-test-out-"));
    cleanupDirs.push(certDir, outDir);
    await makeCertFilesIn(certDir);

    await runBundle(path.join(certDir, "aspnetcore-dev.pfx"), {
      outDir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const stderr = collectStderr();
    expect(stderr).toContain("[warn]");
    expect(stderr).toContain("outside --out-dir");
    // The warning should name the actual offending paths so the user
    // can act on it without re-running with --verbose.
    expect(stderr).toContain(path.join(certDir, "aspnetcore-dev.pfx"));
    expect(stderr).toContain(path.join(certDir, "aspnetcore-dev.pem"));
  });

  it("flags every out-of-dir file, not just the first one", async () => {
    const certDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-test-cert-multi-"));
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-test-out-multi-"));
    cleanupDirs.push(certDir, outDir);
    await makeCertFilesIn(certDir);

    await runBundle(path.join(certDir, "aspnetcore-dev.pfx"), {
      outDir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const stderr = collectStderr();
    // All three artifact fields (pfx, pem, key) live in certDir, so
    // each should appear in the warning detail lines.
    expect(stderr).toContain("pfxPath:");
    expect(stderr).toContain("pemPath:");
    expect(stderr).toContain("pemKeyPath:");
  });

  it("does not warn for the cert path itself when it's the same as the out-dir base", async () => {
    // Regression guard: a cert at exactly $OUT_DIR/cert.pfx and outDir
    // = $OUT_DIR should not trip the "outside" check.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-test-exact-"));
    cleanupDirs.push(dir);
    await makeCertFilesIn(dir);

    await runBundle(path.join(dir, "aspnetcore-dev.pfx"), {
      outDir: dir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const stderr = collectStderr();
    expect(stderr).not.toContain("outside --out-dir");
  });
});

describe("ddc bundle sibling-file discovery", () => {
  it("finds a sibling .p12 (openssl convention) next to a .pem", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-p12-"));
    cleanupDirs.push(dir);
    await makeCertFilesIn(dir);
    // Rename the .pfx → .p12 to simulate the openssl naming convention.
    fs.renameSync(
      path.join(dir, "aspnetcore-dev.pfx"),
      path.join(dir, "aspnetcore-dev.p12")
    );

    await runBundle(path.join(dir, "aspnetcore-dev.pem"), {
      outDir: dir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const bundle = JSON.parse(
      fs.readFileSync(path.join(dir, "bundle.json"), "utf-8")
    ) as Record<string, unknown>;
    const cert = (bundle.certs as Array<Record<string, string>>)[0];
    expect(cert.pfxPath).toBe("/host-dev-certs/aspnetcore-dev.p12");
  });

  it("finds a sibling key with the dotnet `.pem.key` naming", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-pemkey-"));
    cleanupDirs.push(dir);
    await makeCertFilesIn(dir);
    // Simulate `dotnet dev-certs --format PEM --export-path foo.pem`
    // by renaming aspnetcore-dev.key → aspnetcore-dev.pem.key. The
    // .pfx is removed so the key naming is what the test exercises.
    fs.renameSync(
      path.join(dir, "aspnetcore-dev.key"),
      path.join(dir, "aspnetcore-dev.pem.key")
    );
    fs.unlinkSync(path.join(dir, "aspnetcore-dev.pfx"));

    await runBundle(path.join(dir, "aspnetcore-dev.pem"), {
      outDir: dir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const bundle = JSON.parse(
      fs.readFileSync(path.join(dir, "bundle.json"), "utf-8")
    ) as Record<string, unknown>;
    const cert = (bundle.certs as Array<Record<string, string>>)[0];
    expect(cert.pemKeyPath).toBe("/host-dev-certs/aspnetcore-dev.pem.key");
  });

  it("prefers the stem-based key naming when both conventions exist", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-bundle-bothkeys-"));
    cleanupDirs.push(dir);
    await makeCertFilesIn(dir);
    // Add a dotnet-style key alongside the our-convention one. Probe
    // order favors the stem form so an our-exporter cert wins.
    fs.copyFileSync(
      path.join(dir, "aspnetcore-dev.key"),
      path.join(dir, "aspnetcore-dev.pem.key")
    );

    await runBundle(path.join(dir, "aspnetcore-dev.pem"), {
      outDir: dir,
      containerMount: "/host-dev-certs",
      kind: "user",
    });

    const bundle = JSON.parse(
      fs.readFileSync(path.join(dir, "bundle.json"), "utf-8")
    ) as Record<string, unknown>;
    const cert = (bundle.certs as Array<Record<string, string>>)[0];
    expect(cert.pemKeyPath).toBe("/host-dev-certs/aspnetcore-dev.key");
  });
});
