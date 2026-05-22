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

  it("reclaims a dangling hash symlink whose target PEM was deleted externally", () => {
    // Prior install created {hash}.0 → OLD; the PEM was then deleted
    // externally, leaving a dangling symlink at slot 0.
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "old.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "old.pem", SAMPLE_PEM_A);
    const slotsBefore = listHashSymlinks(dir);
    expect(slotsBefore).toHaveLength(1);
    expect(slotsBefore[0].endsWith(".0")).toBe(true);

    // External tool removes the PEM but not the symlink — `{hash}.0` is
    // now a dangling symlink.
    fs.unlinkSync(path.join(dir, "old.pem"));
    expect(fs.existsSync(path.join(dir, slotsBefore[0]))).toBe(false); // follows symlink
    expect(fs.lstatSync(path.join(dir, slotsBefore[0])).isSymbolicLink()).toBe(true);

    // Next install writes a new PEM with the same subject (so the same
    // hash). We expect the broken `{hash}.0` to be reclaimed, not
    // bypassed.
    fs.writeFileSync(path.join(dir, "new.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "new.pem", SAMPLE_PEM_A);

    const slotsAfter = listHashSymlinks(dir);
    expect(slotsAfter).toHaveLength(1);
    expect(slotsAfter[0]).toBe(slotsBefore[0]); // same {hash}.0 path
    expect(fs.readlinkSync(path.join(dir, slotsAfter[0]))).toBe("new.pem");
  });

  it("skips a slot occupied by a non-symlink and uses the next one", () => {
    // A regular file sitting at {hash}.0 — not ours, never ours to delete.
    // Function must move on, allocate {hash}.1 for our PEM, and leave the
    // squatter intact.
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "mycert.pem"), SAMPLE_PEM_A);
    // We don't know the exact hash without exposing computeSubjectHash, so
    // pre-allocate the slot indirectly: install once, read the slot name,
    // delete the symlink, drop a regular file in its place.
    ensureHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);
    const slot0 = listHashSymlinks(dir)[0];
    expect(slot0.endsWith(".0")).toBe(true);
    fs.unlinkSync(path.join(dir, slot0));
    fs.writeFileSync(path.join(dir, slot0), "not-a-symlink");

    ensureHashSymlink(dir, "mycert.pem", SAMPLE_PEM_A);

    // {hash}.0 stays as our planted regular file; the new symlink lands
    // in {hash}.1. `listHashSymlinks` filters by filename only, so further
    // narrow to entries that are actually symbolic links to avoid
    // counting the squatter.
    expect(fs.lstatSync(path.join(dir, slot0)).isFile()).toBe(true);
    expect(fs.lstatSync(path.join(dir, slot0)).isSymbolicLink()).toBe(false);
    const actualSymlinks = listHashSymlinks(dir).filter((f) =>
      fs.lstatSync(path.join(dir, f)).isSymbolicLink()
    );
    expect(actualSymlinks).toHaveLength(1);
    expect(actualSymlinks[0]).toBe(slot0.replace(/\.0$/, ".1"));
    expect(fs.readlinkSync(path.join(dir, actualSymlinks[0]))).toBe(
      "mycert.pem"
    );
  });

  it("returns silently when all 10 hash slots are taken by different PEMs", () => {
    // Defensive bound check: 11th install must not throw and must not
    // allocate slot 10+ (there's no slot 10 in c_rehash).
    const dir = tmp();
    // Same content under 10 distinct filenames → same subject hash.
    for (let i = 0; i < 10; i++) {
      const name = `collide${i}.pem`;
      fs.writeFileSync(path.join(dir, name), SAMPLE_PEM_A);
      ensureHashSymlink(dir, name, SAMPLE_PEM_A);
    }
    const before = listHashSymlinks(dir);
    expect(before).toHaveLength(10);

    // 11th attempt — must NOT throw and must NOT create an 11th symlink.
    fs.writeFileSync(path.join(dir, "overflow.pem"), SAMPLE_PEM_A);
    expect(() =>
      ensureHashSymlink(dir, "overflow.pem", SAMPLE_PEM_A)
    ).not.toThrow();

    const after = listHashSymlinks(dir);
    expect(after).toEqual(before);
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
