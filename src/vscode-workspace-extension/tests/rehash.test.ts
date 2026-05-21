import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { createHashSymlink, rehashDirectory } from "../src/util/rehash";

// Self-signed test cert; only used to give computeSubjectHash something real
// to chew on. The actual hash value doesn't matter — only that creating the
// symlink twice produces one entry, not two.
const SAMPLE_PEM_A =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBkTCB+wIJANSsAUOhwHK7MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n" +
  "Y2FsaG9zdDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBQxEjAQBgNV\n" +
  "BAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAyx0qMlYa\n" +
  "PEzL0c9XBYNcQ6KAjMjbDLp6FrW+lWZHCKf8/aSJW7CnH2tQHrPiU8r6QYBSWQ7c\n" +
  "VTrA8h8wYy7eRdQk31uLR7tGzZ5JxBz2DYxcuxR1RJ/+QbR1m6Z5w9p5UqxQ4l3+\n" +
  "AbsmPwy3J7t4cqo3PVPmF6mPiK7M+M0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQAt\n" +
  "-----END CERTIFICATE-----\n";

const cleanupDirs: string[] = [];
afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

function tmp(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-rehash-"));
  cleanupDirs.push(dir);
  return dir;
}

function listHashSymlinks(dir: string): string[] {
  return fs
    .readdirSync(dir)
    .filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f))
    .sort();
}

describe.skipIf(process.platform === "win32")("createHashSymlink idempotency", () => {
  it("does not create a second symlink when called twice with the same PEM", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);

    createHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const before = listHashSymlinks(dir);
    expect(before.length).toBeGreaterThanOrEqual(1);

    createHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const after = listHashSymlinks(dir);
    expect(after).toEqual(before);
  });

  it("rehashDirectory + createHashSymlink for the same PEM yields exactly one symlink", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);

    rehashDirectory(dir);
    createHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);

    const links = listHashSymlinks(dir);
    expect(links).toHaveLength(1);
    // The single slot must still be {hash}.0, not {hash}.1.
    expect(links[0].endsWith(".0")).toBe(true);
    expect(fs.readlinkSync(path.join(dir, links[0]))).toBe("mycert.pem");
  });

  it("allocates a fresh slot when the existing one points at a different target", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);
    createHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const first = listHashSymlinks(dir);
    expect(first).toHaveLength(1);

    // A second PEM with the same subject (so the same hash slot collides).
    // Use the same content but a different filename — c_rehash collisions
    // are about the hash, not the file contents.
    fs.writeFileSync(path.join(dir, "other.pem"), SAMPLE_PEM_A);
    createHashSymlink(dir, "other.pem", SAMPLE_PEM_A);

    const links = listHashSymlinks(dir);
    expect(links).toHaveLength(2);
    expect(links[0].endsWith(".0")).toBe(true);
    expect(links[1].endsWith(".1")).toBe(true);
    const targets = new Set(
      links.map((l) => fs.readlinkSync(path.join(dir, l)))
    );
    expect(targets).toEqual(new Set(["mycert.pem", "other.pem"]));
  });
});
