import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  ensureSslCertDir,
  type SslCertDirEnvSink,
} from "../src/util/sslCertDir";

// ensureSslCertDir configures SSL_CERT_DIR for VS Code-scoped processes only:
// the EnvironmentVariableCollection (terminals/tasks) and process.env (this
// run's child spawns). It deliberately does NOT touch /etc/profile.d, ~/.bashrc,
// or any other persistent file — those are the devcontainer feature's job.
//
// These tests pin the observable contract: which collection op is issued
// (replace when we own the value, prepend when an inherited value exists),
// the composed/pruned value, the resulting process.env, and the returned
// outcome. The trust dir is steered via the
// DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY override.

type Op = { op: "replace" | "prepend"; variable: string; value: string };

function fakeSink(): SslCertDirEnvSink & { ops: Op[] } {
  const ops: Op[] = [];
  return {
    ops,
    replace: (variable, value) => ops.push({ op: "replace", variable, value }),
    prepend: (variable, value) => ops.push({ op: "prepend", variable, value }),
  };
}

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
});

/** Point the trust dir at a real temp dir so getOpenSslTrustDir is deterministic. */
function setupTrustDir(): string {
  const trust = tmpDir("devcerts-trust-");
  process.env["DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY"] = trust;
  return trust;
}

describe("ensureSslCertDir", () => {
  it("replaces with the composed value (pruning absent system dirs) when nothing is inherited", () => {
    const trust = setupTrustDir();
    const present = tmpDir("devcerts-present-");
    const absent = "/devcerts/definitely/missing-xyz";
    const sink = fakeSink();

    const result = ensureSslCertDir(sink, `${present}:${absent}`, true);

    const expected = `${trust}:${present}`;
    expect(result).toEqual({ outcome: "configured", value: expected });
    expect(sink.ops).toEqual([
      { op: "replace", variable: "SSL_CERT_DIR", value: expected },
    ]);
    expect(process.env["SSL_CERT_DIR"]).toBe(expected);
  });

  it("honors an explicit override verbatim (no pruning) when pruneMissingDirs is false", () => {
    const trust = setupTrustDir();
    const present = tmpDir("devcerts-present-");
    const absent = "/devcerts/definitely/missing-xyz";
    const sink = fakeSink();

    const result = ensureSslCertDir(sink, `${present}:${absent}`, false);

    const expected = `${trust}:${present}:${absent}`;
    expect(result).toEqual({ outcome: "configured", value: expected });
    expect(sink.ops).toEqual([
      { op: "replace", variable: "SSL_CERT_DIR", value: expected },
    ]);
    expect(process.env["SSL_CERT_DIR"]).toBe(expected);
  });

  it("composes empty-safe (trust dir alone, no trailing colon) when pruning empties the list", () => {
    const trust = setupTrustDir();
    const sink = fakeSink();

    const result = ensureSslCertDir(
      sink,
      "/devcerts/missing-a:/devcerts/missing-b",
      true
    );

    expect(result).toEqual({ outcome: "configured", value: trust });
    expect(sink.ops).toEqual([
      { op: "replace", variable: "SSL_CERT_DIR", value: trust },
    ]);
    expect(process.env["SSL_CERT_DIR"]).toBe(trust);
    expect(process.env["SSL_CERT_DIR"]).not.toContain(":");
  });

  it("prepends only the trust dir onto an inherited value (no clobber, no re-injected system dirs)", () => {
    const trust = setupTrustDir();
    const inherited = "/etc/ssl/certs:/usr/lib/ssl/certs";
    process.env["SSL_CERT_DIR"] = inherited;
    const sink = fakeSink();

    const result = ensureSslCertDir(sink, "/some/configured/dir", true);

    expect(result).toEqual({
      outcome: "configured",
      value: `${trust}:${inherited}`,
    });
    expect(sink.ops).toEqual([
      { op: "prepend", variable: "SSL_CERT_DIR", value: `${trust}:` },
    ]);
    expect(process.env["SSL_CERT_DIR"]).toBe(`${trust}:${inherited}`);
  });

  it("reports already-present and issues no collection op when the trust dir is already there", () => {
    const trust = setupTrustDir();
    const existing = `${trust}:/some/preexisting/dir`;
    process.env["SSL_CERT_DIR"] = existing;
    const sink = fakeSink();

    const result = ensureSslCertDir(sink, "/etc/ssl/certs", true);

    expect(result).toEqual({ outcome: "already-present", value: existing });
    expect(sink.ops).toEqual([]);
    expect(process.env["SSL_CERT_DIR"]).toBe(existing);
  });

  it("refuses unsafe system-dir input without touching the env or the collection", () => {
    setupTrustDir();
    const sink = fakeSink();

    // Command substitution / non-absolute / metacharacters must be refused.
    const result = ensureSslCertDir(sink, "/etc/ssl/certs:$(rm -rf /)", true);

    expect(result).toEqual({ outcome: "refused" });
    expect(sink.ops).toEqual([]);
    expect(process.env["SSL_CERT_DIR"]).toBeUndefined();
  });
});
