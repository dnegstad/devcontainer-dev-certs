import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ensureSslCertDir } from "../src/util/sslCertDir";

// ensureSslCertDir is the non-devcontainer counterpart to the feature's
// install.sh: for SSH remoting / WSL / other remotes (where there's no
// install.sh to write the profile scripts), it composes SSL_CERT_DIR =
// trustDir + system CA dirs, sets it on the current process, and best-effort
// writes a profile script + ~/.bashrc so new shells inherit it.
//
// These tests pin the observable contract via process.env (fully hermetic):
//   - pruning drops non-existent system dirs ONLY when asked (defaults path)
//   - an explicit override is honored verbatim (no pruning)
//   - empty-safe composition (no trailing `:` when pruning empties the list)
//   - early-return when the trust dir is already present
//   - unsafe input is rejected without mutating the environment
//
// The trust dir is steered via DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY
// (honored by getOpenSslTrustDir), and HOME is redirected to a temp dir so the
// best-effort ~/.bashrc write never touches the real home.

const cleanupDirs: string[] = [];
function tmpDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanupDirs.push(dir);
  return dir;
}

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {
    SSL_CERT_DIR: process.env["SSL_CERT_DIR"],
    DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY:
      process.env["DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY"],
    HOME: process.env["HOME"],
  };
  delete process.env["SSL_CERT_DIR"];
});

afterEach(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
  // The function may best-effort-write this when running as root. Clean it up so
  // tests don't leak state into the host or into each other.
  try {
    fs.rmSync("/etc/profile.d/devcerts-ssl-cert-dir.sh", { force: true });
  } catch {
    // ignore
  }
});

/** Point the trust dir at a real temp dir and redirect HOME away from the real home. */
function setupTrustDir(): string {
  const trust = tmpDir("devcerts-trust-");
  process.env["DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY"] = trust;
  process.env["HOME"] = tmpDir("devcerts-home-");
  return trust;
}

describe("ensureSslCertDir", () => {
  it("prunes non-existent system dirs when pruneMissingDirs is set", () => {
    const trust = setupTrustDir();
    const present = tmpDir("devcerts-present-");
    const absent = "/devcerts/definitely/missing-xyz";

    const result = ensureSslCertDir(`${present}:${absent}`, true);

    expect(result).toEqual({
      outcome: "configured",
      value: `${trust}:${present}`,
    });
    expect(process.env["SSL_CERT_DIR"]).toBe(`${trust}:${present}`);
  });

  it("honors an explicit override verbatim (no pruning) when pruneMissingDirs is false", () => {
    const trust = setupTrustDir();
    const present = tmpDir("devcerts-present-");
    const absent = "/devcerts/definitely/missing-xyz";

    const result = ensureSslCertDir(`${present}:${absent}`, false);

    expect(result).toEqual({
      outcome: "configured",
      value: `${trust}:${present}:${absent}`,
    });
    expect(process.env["SSL_CERT_DIR"]).toBe(`${trust}:${present}:${absent}`);
  });

  it("composes empty-safe (trust dir alone, no trailing colon) when pruning empties the list", () => {
    const trust = setupTrustDir();

    const result = ensureSslCertDir(
      "/devcerts/missing-a:/devcerts/missing-b",
      true
    );

    expect(result).toEqual({ outcome: "configured", value: trust });
    expect(process.env["SSL_CERT_DIR"]).toBe(trust);
    expect(process.env["SSL_CERT_DIR"]).not.toContain(":");
  });

  it("reports already-present without changing SSL_CERT_DIR when the trust dir is already there", () => {
    const trust = setupTrustDir();
    const existing = `${trust}:/some/preexisting/dir`;
    process.env["SSL_CERT_DIR"] = existing;

    const result = ensureSslCertDir("/etc/ssl/certs", true);

    expect(result).toEqual({ outcome: "already-present", value: existing });
    expect(process.env["SSL_CERT_DIR"]).toBe(existing);
  });

  it("refuses unsafe system-dir input without mutating the environment", () => {
    setupTrustDir();

    // Command substitution / non-absolute / metacharacters must be refused.
    const result = ensureSslCertDir("/etc/ssl/certs:$(rm -rf /)", true);

    expect(result).toEqual({ outcome: "refused" });
    expect(process.env["SSL_CERT_DIR"]).toBeUndefined();
  });

  it("writes the composed value into the redirected ~/.bashrc for new shells", () => {
    const trust = setupTrustDir();
    const present = tmpDir("devcerts-present-");

    ensureSslCertDir(present, true);

    const bashrcPath = path.join(os.homedir(), ".bashrc");
    // The function only appends if ~/.bashrc already exists; create it empty so
    // we can observe the append in this hermetic home.
    // (Re-run after creating the file.)
    fs.writeFileSync(bashrcPath, "");
    delete process.env["SSL_CERT_DIR"];
    ensureSslCertDir(present, true);

    const bashrc = fs.readFileSync(bashrcPath, "utf8");
    expect(bashrc).toContain("# devcerts-ssl-cert-dir");
    expect(bashrc).toContain(`export SSL_CERT_DIR='${trust}:${present}'`);
  });
});
