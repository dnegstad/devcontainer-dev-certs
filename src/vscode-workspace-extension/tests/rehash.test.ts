import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ensureHashSymlink, rehashDirectory } from "../src/util/rehash";

// Self-signed test cert; only used to give computeSubjectHash something real
// to chew on. The actual hash value doesn't matter — only the symlink shape.
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

describe.skipIf(process.platform === "win32")("ensureHashSymlink", () => {
  it("does not create a second symlink when called twice with the same PEM", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);

    ensureHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const before = listHashSymlinks(dir);
    expect(before.length).toBeGreaterThanOrEqual(1);

    ensureHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const after = listHashSymlinks(dir);
    expect(after).toEqual(before);
  });

  it("rehashDirectory followed by ensureHashSymlink for the same PEM yields exactly one symlink", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);

    rehashDirectory(dir);
    ensureHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);

    const links = listHashSymlinks(dir);
    expect(links).toHaveLength(1);
    // The single slot must still be {hash}.0, not {hash}.1.
    expect(links[0].endsWith(".0")).toBe(true);
    expect(fs.readlinkSync(path.join(dir, links[0]))).toBe("mycert.pem");
  });

  it("allocates a fresh slot when the existing one points at a different target", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const first = listHashSymlinks(dir);
    expect(first).toHaveLength(1);

    // A second PEM with the same subject (so the same hash slot collides).
    // Use the same content but a different filename — c_rehash collisions
    // are about the hash, not the file contents.
    fs.writeFileSync(path.join(dir, "other.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "other.pem", SAMPLE_PEM_A);

    const links = listHashSymlinks(dir);
    expect(links).toHaveLength(2);
    expect(links[0].endsWith(".0")).toBe(true);
    expect(links[1].endsWith(".1")).toBe(true);
    const targets = new Set(
      links.map((l) => fs.readlinkSync(path.join(dir, l)))
    );
    expect(targets).toEqual(new Set(["mycert.pem", "other.pem"]));
  });

  it("leaves pre-existing hash symlinks for OTHER PEMs untouched", () => {
    const dir = tmp();
    // Pre-existing PEM the user (or a prior rotation) put in the trust dir,
    // along with its hash symlink. Our install path must not touch this.
    fs.writeFileSync(path.join(dir, "stranger.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "stranger.pem", SAMPLE_PEM_A);
    const strangerLinks = listHashSymlinks(dir);
    expect(strangerLinks).toHaveLength(1);
    const strangerLinkStat = fs.lstatSync(path.join(dir, strangerLinks[0]));

    // Now install our own PEM under a different filename. Because
    // SAMPLE_PEM_A's subject hash is identical, the next free slot for that
    // hash should be `{hash}.1` — and the stranger's `{hash}.0` symlink must
    // remain bit-for-bit identical (same inode, same mtime).
    fs.writeFileSync(path.join(dir, "ours.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "ours.pem", SAMPLE_PEM_A);

    const all = listHashSymlinks(dir);
    expect(all).toHaveLength(2);

    const strangerAfter = fs.lstatSync(path.join(dir, strangerLinks[0]));
    expect(strangerAfter.ino).toBe(strangerLinkStat.ino);
    expect(strangerAfter.mtimeMs).toBe(strangerLinkStat.mtimeMs);
    expect(fs.readlinkSync(path.join(dir, strangerLinks[0]))).toBe(
      "stranger.pem"
    );
  });
});
