import { describe, it, expect, afterEach } from "vitest";
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  computeSubjectHash,
  ensureHashSymlink,
  rehashDirectory,
} from "@devcontainer-dev-certs/shared";

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

  it("keeps allocating slots past 10 — every dev cert shares one subject hash", () => {
    // This used to assert the opposite: that an 11th same-subject PEM was
    // silently refused a slot. That bound was reachable in ordinary use rather
    // than pathological, because every ASP.NET dev cert is CN=localhost, so
    // slots are consumed by cert COUNT, not by real hash collisions. A
    // container minting a fresh cert per rebuild — the default for most dotnet
    // devcontainer base images, and not something this extension can enforce
    // otherwise — exhausted all ten in ten rebuilds, after which the LIVE cert
    // got no symlink while ten dead ones kept theirs, and `openssl verify
    // -CApath` failed for the only cert that mattered. OpenSSL's `by_dir` has
    // no such limit; it walks `{hash}.{n}` until a file is missing.
    const dir = tmp();
    for (let i = 0; i < 10; i++) {
      const name = `collide${i}.pem`;
      fs.writeFileSync(path.join(dir, name), SAMPLE_PEM_A);
      ensureHashSymlink(dir, name, SAMPLE_PEM_A);
    }
    expect(listHashSymlinks(dir)).toHaveLength(10);

    fs.writeFileSync(path.join(dir, "eleventh.pem"), SAMPLE_PEM_A);
    ensureHashSymlink(dir, "eleventh.pem", SAMPLE_PEM_A);

    const links = listHashSymlinks(dir);
    expect(links).toHaveLength(11);
    // The newcomer is the one that has to be reachable.
    const mine = links.filter(
      (l) => fs.readlinkSync(path.join(dir, l)) === "eleventh.pem"
    );
    expect(mine).toHaveLength(1);
  });

  it("allocates slots contiguously from 0, which is what OpenSSL requires", () => {
    // `by_dir` stops at the first missing `{hash}.{n}`, so a gap makes every
    // later slot unreachable. Anything that prunes entries must re-densify
    // via rehashDirectory rather than unlink in place.
    const dir = tmp();
    for (let i = 0; i < 12; i++) {
      const name = `c${i}.pem`;
      fs.writeFileSync(path.join(dir, name), SAMPLE_PEM_A);
      ensureHashSymlink(dir, name, SAMPLE_PEM_A);
    }
    const suffixes = listHashSymlinks(dir)
      .map((l) => Number(l.split(".")[1]))
      .sort((a, b) => a - b);
    expect(suffixes).toEqual([...Array(12).keys()]);
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

/**
 * The symlink names only do anything if they match what OpenSSL's `by_dir`
 * lookup (SSL_CERT_DIR / -CApath) actually searches for. That value is
 * `X509_NAME_hash`: SHA-1 over the *canonical* name encoding — attribute
 * values re-tagged UTF8String, ASCII-lowercased, space runs collapsed, and
 * the RDN `SET OF` encodings concatenated WITHOUT the Name's outer
 * `SEQUENCE`. Hashing the raw subject DER instead yields a plausible-looking
 * `{hash}.0` that nothing ever opens, silently disabling container trust.
 *
 * The expected values below were produced by `openssl x509 -hash -noout`
 * (OpenSSL 3.0.13). `CN=localhost` is the shape every dev cert we install
 * has; the multi-RDN fixture pins the normalization rules (PrintableString
 * plus UTF8String, uppercase letters, a doubled internal space, a trailing
 * space).
 */
describe("computeSubjectHash", () => {
  // subject=CN = localhost
  const PEM_LOCALHOST =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIDCTCCAfGgAwIBAgIUKqotkm31fbIEbOVcgrem0favrgQwDQYJKoZIhvcNAQEL\n" +
    "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgyODAwMDM1OFoXDTM2MDgy\n" +
    "NTAwMDM1OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n" +
    "AAOCAQ8AMIIBCgKCAQEAjgGYX2B2v2F5mSgDK2skLTZ7WtkYEJXZ/dD3i4Io5ZuQ\n" +
    "5z4nt6VPSnCZFe8jBcDqcgdnCWUOG8yo7BP0pMQHMNRcqmyfMssIKWenPSPWU3U1\n" +
    "qMkah8hJbzQkuPlL88yBRDGlHI5ioE6YJKkvwaXBEpaj7xwL0IeOg7ODBz/C6lev\n" +
    "KGqfh8180tJ2/SJc6Hpgi0aaWFmkaYyB2/xZnxGTOaXlYtaU1WLVHSG0pJUdYEAm\n" +
    "m8S/oaofwPNEG/GStb+X5NVQKxQS2ZhsPcrv55EoZ43ukRwvUCeE1jN0xAVx9KO6\n" +
    "1PzYWxGwrneCv45VV+698LstLLn9tWL0FAe0MWxfcwIDAQABo1MwUTAdBgNVHQ4E\n" +
    "FgQUszuVse2bqDyPBDxDgwodnoWFiSowHwYDVR0jBBgwFoAUszuVse2bqDyPBDxD\n" +
    "gwodnoWFiSowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAd8fg\n" +
    "cVxi0bb27kpCjCBBkWGJkfu2SpY8D345PPvsQfxEoaBmvmPSo+V0uO5vPM6VQkMb\n" +
    "nwOyGytTYM+uVWADA3YJ+gYpToRfWE+06hKh2ziCDves8rObymLHApFosU0ulT35\n" +
    "HWw7S1Sv68k4Wqh7Q7neaYdKGjXWIpMbQ/aDUkUSRYYdmCyidmxAJFi71ROmkl0N\n" +
    "SutU65eZyiU8Rh6GSn1u3iPn+DHtcI/3npplew/kXUSliw4gpI7lipD31uBHVJc+\n" +
    "k8ge6yTGRi5QppCpiSYcpv0MJ1+DdaadFkYjOV4DPXid9xeJ7ZwQX2rK6Zbkj36Z\n" +
    "dW1E/BkFPJeKGPofjA==\n" +
    "-----END CERTIFICATE-----\n";

  // subject=C = US, O = "Example  Org ", CN = Mixed Case Name
  const PEM_MULTI_RDN =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIDXzCCAkegAwIBAgIUbKzt8uWkwdhKI7QVANKvuaAuga4wDQYJKoZIhvcNAQEL\n" +
    "BQAwPzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUV4YW1wbGUgIE9yZyAxGDAWBgNV\n" +
    "BAMMD01peGVkIENhc2UgTmFtZTAeFw0yNjA4MjgwMDAzNThaFw0zNjA4MjUwMDAz\n" +
    "NThaMD8xCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1FeGFtcGxlICBPcmcgMRgwFgYD\n" +
    "VQQDDA9NaXhlZCBDYXNlIE5hbWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
    "AoIBAQDLuNsJ2dI5mBGcGeK5lfzKA/8dY5Dunjl10gZybeKcLCUuBwIecUg4rHFR\n" +
    "5OoH9s5UIIvOLA+aGR1gNxx4Jai3IUJtcGS67oh9Gz7F1w6hswO2y0rzXPVq0W+N\n" +
    "mAXmEqDpRjqmS6sGHFqtQkKNtc3WRhxc42RD4FiuMuWDkq5//fEEPClg/16i16uF\n" +
    "u/17fwq3rnJPQQbxMpxlJp/wJgJdfTNN0eypuvqRMc+4HYELcagtjOX0rBkIO3SG\n" +
    "xXqm2uJOCyPMoxWCVZax3+tuZY4onqajxtaz1ztURlbLejxXw4DfEH2CI6VPIc7X\n" +
    "bK/Ec5UBnyo1OVOaEcGNLIoQNjxFAgMBAAGjUzBRMB0GA1UdDgQWBBTLRAf/8wQx\n" +
    "YLYQMDUW/g+HiamzSDAfBgNVHSMEGDAWgBTLRAf/8wQxYLYQMDUW/g+HiamzSDAP\n" +
    "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAbc3i28qmW6cbOwpIR\n" +
    "OzSgg0BlyK9dOyGrfwRI44i1NEyZGM9Y8ced4AS7DgnZpuKfy54QiibCKxMzENOX\n" +
    "kogGgoDriLdDdGfdz2zrFQvHfYa2ccieJ6NV5Bi8Mgnnx+s/DGxZN6Yz76n5/Qic\n" +
    "eqmw7pgOMeeqGB5spiOw28INsZK5bxZEcpTyhgPUbhC3EjFp0UMNd7SFstfY7zGo\n" +
    "H6t+jC75hgl0PivQC97LrBpzNn0EZCdzoyCUomilR5XEk+L5WIC5H8Z+LxU1hBOS\n" +
    "ziEyIosRJFOAv0D4KYNITnCe6km2AzD+AAC5juMXFwaaDYtzmfKUsTFzGGIvC3C8\n" +
    "9l5Y\n" +
    "-----END CERTIFICATE-----\n";

  it("matches OpenSSL's subject hash for a CN=localhost dev cert", () => {
    expect(computeSubjectHash(PEM_LOCALHOST)).toBe("ce275665");
  });

  it("matches OpenSSL's subject hash for a multi-RDN subject needing canonicalization", () => {
    expect(computeSubjectHash(PEM_MULTI_RDN)).toBe("90c9c9f3");
  });

  it("returns null for input that isn't a certificate", () => {
    expect(computeSubjectHash("not a pem")).toBeNull();
  });

  // Belt-and-braces: when the machine running the suite has openssl, verify
  // the pinned values above still reflect what OpenSSL computes today rather
  // than what it computed when they were recorded.
  const hasOpenssl = (() => {
    try {
      execFileSync("openssl", ["version"], { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  })();

  it.runIf(hasOpenssl)(
    "agrees with the local openssl binary",
    () => {
      const dir = tmp();
      for (const pem of [PEM_LOCALHOST, PEM_MULTI_RDN]) {
        const p = path.join(dir, "cert.pem");
        fs.writeFileSync(p, pem);
        const expected = execFileSync("openssl", [
          "x509",
          "-hash",
          "-noout",
          "-in",
          p,
        ])
          .toString()
          .trim();
        expect(computeSubjectHash(pem)).toBe(expected);
      }
    }
  );
});
