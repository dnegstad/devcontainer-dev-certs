// Polyfill must load before any module that pulls in @peculiar/x509 (via
// shared). tsyringe — a transitive dep of @peculiar/x509 — wires up
// `@injectable` decorators against `Reflect.metadata` at module init.
import "reflect-metadata";

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  Extension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import type * as Shared from "@devcontainer-dev-certs/shared";
import type { CertBundleV3, CertMaterialV3 } from "@devcontainer-dev-certs/shared";
import {
  DevCert,
  DevKey,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
  buildPfx,
} from "@devcontainer-dev-certs/shared";

cryptoProvider.set(webcrypto as unknown as Crypto);

let storeDir: string;
let rootStoreDir: string;
let trustDir: string;

vi.mock("@devcontainer-dev-certs/shared", async (importOriginal) => {
  const original = await importOriginal<typeof Shared>();
  return {
    ...original,
    getDotNetStorePath: () => storeDir,
    getDotNetRootStorePath: () => rootStoreDir,
    getOpenSslTrustDir: () => trustDir,
  };
});

import {
  buildManagedMyStoreThumbprints,
  bundleHasManagedDevCert,
  cleanupStaleDevCerts,
  findStaleDevCerts,
} from "../src/cleanupCerts";

const cleanupDirs: string[] = [];

beforeEach(() => {
  storeDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-cleanup-my-"));
  rootStoreDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-cleanup-root-"));
  trustDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-cleanup-trust-"));
  cleanupDirs.push(storeDir, rootStoreDir, trustDir);
});

afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

// 40-character SHA-1 hex thumbprints used as FILENAME stems on disk. The
// in-file thumbprint of the cached PFX bytes below is unrelated — cleanup
// keys on the filename only (managedBundle.thumbprint must match the
// filename stem to be filtered out), so we keep these constants stable
// across tests for clarity.
const MANAGED_THUMB = "A".repeat(40);
const STALE_THUMB = "B".repeat(40);
const ORPHAN_THUMB = "C".repeat(40);

// One real dev-cert PFX shared across every test that needs "is a dev
// cert" bytes on disk. Building this once in beforeAll keeps the suite
// fast — generateKey is the dominant cost.
let CACHED_DEV_PFX: Buffer | null = null;

beforeAll(async () => {
  CACHED_DEV_PFX = await buildRealDevCertPfx();
}, 30_000);

async function buildRealDevCertPfx(): Promise<Buffer> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
  const now = new Date();
  const exp = new Date(now.getTime() + 30 * 86400_000);
  const cert = await X509CertificateGenerator.create({
    serialNumber: "01",
    subject: "CN=localhost",
    issuer: "CN=localhost",
    notBefore: now,
    notAfter: exp,
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    extensions: [
      new SubjectAlternativeNameExtension(
        [
          ...SAN_DNS_NAMES.map((d) => ({ type: "dns" as const, value: d })),
          ...SAN_IP_ADDRESSES.map((ip) => ({ type: "ip" as const, value: ip })),
        ],
        true
      ),
      new Extension(
        ASPNET_HTTPS_OID,
        false,
        new Uint8Array([CURRENT_CERTIFICATE_VERSION]).buffer
      ),
    ],
  });
  const devCert = new DevCert(cert);
  const devKey = await DevKey.fromCryptoKey(keyPair.privateKey);
  return buildPfx({ cert: devCert, key: devKey });
}

function devCertPfx(): Buffer {
  if (!CACHED_DEV_PFX) {
    throw new Error("devCertPfx() called before beforeAll completed");
  }
  return CACHED_DEV_PFX;
}

function nonDevCertPfx(): Buffer {
  // Random bytes — parsePfx fails to parse them, isAspNetDevCertPfx
  // returns false (fail-closed).
  return Buffer.from("NOT-A-DEV-CERT");
}

function managedBundle(): CertBundleV3 {
  const dev: CertMaterialV3 = {
    kind: "dotnet-dev",
    name: "aspnetcore-dev",
    thumbprint: MANAGED_THUMB,
    pemCertBase64: Buffer.from(
      "-----BEGIN CERTIFICATE-----\nDEV\n-----END CERTIFICATE-----\n"
    ).toString("base64"),
    pfxBase64: devCertPfx().toString("base64"),
    rootPfxBase64: Buffer.from("ROOT").toString("base64"),
    trustInContainer: true,
    installToDotNetStore: true,
    dotNetStorePfxBase64: devCertPfx().toString("base64"),
  };
  return { certs: [dev] };
}

describe("bundleHasManagedDevCert", () => {
  it("is true when the bundle contains a dotnet-dev cert", () => {
    expect(bundleHasManagedDevCert(managedBundle())).toBe(true);
  });

  it("is false when no dotnet-dev cert is in the bundle (empty or user-cert-only)", () => {
    const userOnly: CertBundleV3 = {
      certs: [
        {
          kind: "user",
          name: "corp",
          thumbprint: STALE_THUMB,
          pemCertBase64: Buffer.from("PEM").toString("base64"),
          trustInContainer: true,
          installToDotNetStore: false,
        },
      ],
    };
    expect(bundleHasManagedDevCert({ certs: [] })).toBe(false);
    expect(bundleHasManagedDevCert(userOnly)).toBe(false);
  });

  // Regression guard for the "generation disabled" scenario: without this
  // check, the cleanup command would classify every dev cert in My as
  // "other" because nothing is "ours" and would offer to delete them all.
  it("guards against the bug it exists for: empty-managed scan flags every dev cert in My", async () => {
    fs.writeFileSync(path.join(storeDir, `${MANAGED_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    const empty = buildManagedMyStoreThumbprints({ certs: [] });
    const stale = await findStaleDevCerts(empty);
    expect(stale.length).toBe(2);
  });
});

describe.skipIf(process.platform === "win32")("buildManagedMyStoreThumbprints", () => {
  it("includes the dotnet-dev cert", () => {
    const m = buildManagedMyStoreThumbprints(managedBundle());
    expect(m.has(MANAGED_THUMB)).toBe(true);
  });

  it("only adds a user cert when opted in AND store bytes are present", () => {
    const base: CertMaterialV3 = {
      kind: "user",
      name: "corp",
      thumbprint: STALE_THUMB,
      pemCertBase64: Buffer.from("PEM").toString("base64"),
      trustInContainer: false,
      installToDotNetStore: false,
    };
    expect(buildManagedMyStoreThumbprints({ certs: [base] }).size).toBe(0);
    expect(
      buildManagedMyStoreThumbprints({
        certs: [{ ...base, installToDotNetStore: true }],
      }).size
    ).toBe(0);
    expect(
      buildManagedMyStoreThumbprints({
        certs: [
          {
            ...base,
            installToDotNetStore: true,
            dotNetStorePfxBase64: Buffer.from("X").toString("base64"),
          },
        ],
      }).has(STALE_THUMB)
    ).toBe(true);
  });
});

describe.skipIf(process.platform === "win32")("findStaleDevCerts", () => {
  it("returns empty when the My store directory is missing or empty", async () => {
    // beforeEach left us with an empty My store; first call exercises
    // the "exists but contains nothing" branch.
    expect(
      await findStaleDevCerts(buildManagedMyStoreThumbprints(managedBundle()))
    ).toEqual([]);
    fs.rmSync(storeDir, { recursive: true });
    expect(
      await findStaleDevCerts(buildManagedMyStoreThumbprints(managedBundle()))
    ).toEqual([]);
  });

  it("detects stale dev-cert PFXs in My, preserves managed and non-dev-cert files", async () => {
    fs.writeFileSync(path.join(storeDir, `${MANAGED_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    // Lacks the OID — must be left alone even though the filename matches.
    fs.writeFileSync(path.join(storeDir, `${ORPHAN_THUMB}.pfx`), nonDevCertPfx());
    // Wrong filename pattern — must be left alone.
    fs.writeFileSync(path.join(storeDir, "random.pfx"), devCertPfx());

    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    expect(stale).toHaveLength(1);
    expect(stale[0].thumbprint).toBe(STALE_THUMB);
    // No associated Root / trust files exist, so only the My PFX is gathered.
    expect(stale[0].artifacts).toHaveLength(1);
    expect(stale[0].artifacts[0].location).toBe("my-store");
  });

  it("gathers associated Root-store and trust-dir files for a stale My-store cert", async () => {
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(rootStoreDir, `${STALE_THUMB}.pfx`), devCertPfx());
    const stalePem = `aspnetcore-localhost-${STALE_THUMB}.pem`;
    fs.writeFileSync(path.join(trustDir, stalePem), "stale");

    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    expect(stale).toHaveLength(1);
    const locations = stale[0].artifacts.map((a) => a.location).sort();
    expect(locations).toEqual(["my-store", "root-store", "trust-dir"]);
  });

  it("does NOT proactively scan Root or the trust dir — a file only there is ignored", async () => {
    // Cert exists ONLY in Root + trust dir; nothing in My. Should be invisible
    // to findStaleDevCerts — My is the discovery driver.
    fs.writeFileSync(path.join(rootStoreDir, `${STALE_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(
      path.join(trustDir, `aspnetcore-localhost-${STALE_THUMB}.pem`),
      "orphan"
    );

    expect(
      await findStaleDevCerts(buildManagedMyStoreThumbprints(managedBundle()))
    ).toEqual([]);
  });

  it("gathers associated files even when the producer used lowercase thumbprint filenames", async () => {
    // Sibling lookups must preserve on-disk casing or they'll miss
    // lowercase artifacts on a case-sensitive filesystem.
    const lower = STALE_THUMB.toLowerCase();
    fs.writeFileSync(path.join(storeDir, `${lower}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(rootStoreDir, `${lower}.pfx`), devCertPfx());
    fs.writeFileSync(
      path.join(trustDir, `aspnetcore-localhost-${lower}.pem`),
      "lc-pem"
    );

    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    expect(stale).toHaveLength(1);
    // Thumbprint is normalised to uppercase for display/comparison.
    expect(stale[0].thumbprint).toBe(STALE_THUMB);
    const locations = stale[0].artifacts.map((a) => a.location).sort();
    expect(locations).toEqual(["my-store", "root-store", "trust-dir"]);
    // Every gathered file path must match the on-disk (lowercase) casing
    // so the subsequent `unlinkSync` actually hits the file.
    for (const a of stale[0].artifacts) {
      expect(fs.existsSync(a.fullPath)).toBe(true);
    }
  });

  it("does not report associated files that don't exist on disk", async () => {
    // Stale PFX in My but no matching Root PFX and no matching PEM.
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    expect(stale).toHaveLength(1);
    expect(stale[0].artifacts).toHaveLength(1);
    expect(stale[0].artifacts[0].location).toBe("my-store");
  });
});

describe.skipIf(process.platform === "win32")("cleanupStaleDevCerts", () => {
  it("removes the My PFX and all associated Root/trust files, then rehashes", async () => {
    fs.writeFileSync(path.join(storeDir, `${MANAGED_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(rootStoreDir, `${MANAGED_THUMB}.pfx`), devCertPfx());
    fs.writeFileSync(path.join(rootStoreDir, `${STALE_THUMB}.pfx`), devCertPfx());

    const managedPem = `aspnetcore-localhost-${MANAGED_THUMB}.pem`;
    const stalePem = `aspnetcore-localhost-${STALE_THUMB}.pem`;
    // Real PEM bytes so rehashDirectory's c_rehash pass doesn't blow up.
    fs.writeFileSync(
      path.join(trustDir, managedPem),
      "-----BEGIN CERTIFICATE-----\nMANAGED\n-----END CERTIFICATE-----\n"
    );
    fs.writeFileSync(
      path.join(trustDir, stalePem),
      "-----BEGIN CERTIFICATE-----\nSTALE\n-----END CERTIFICATE-----\n"
    );

    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    const result = cleanupStaleDevCerts(stale);

    expect(result.removedCerts).toHaveLength(1);
    expect(result.removedCerts[0].thumbprint).toBe(STALE_THUMB);
    expect(result.failed).toEqual([]);
    expect(result.rehashedTrustDir).toBe(true);

    // Managed files untouched; stale cert's three files all gone.
    expect(fs.existsSync(path.join(storeDir, `${MANAGED_THUMB}.pfx`))).toBe(true);
    expect(fs.existsSync(path.join(storeDir, `${STALE_THUMB}.pfx`))).toBe(false);
    expect(fs.existsSync(path.join(rootStoreDir, `${MANAGED_THUMB}.pfx`))).toBe(true);
    expect(fs.existsSync(path.join(rootStoreDir, `${STALE_THUMB}.pfx`))).toBe(false);
    expect(fs.existsSync(path.join(trustDir, managedPem))).toBe(true);
    expect(fs.existsSync(path.join(trustDir, stalePem))).toBe(false);
  });

  it("does not rehash when no trust-dir PEM was removed", async () => {
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    // No PEM for the stale cert; managed PEM is unrelated.
    const managedPem = `aspnetcore-localhost-${MANAGED_THUMB}.pem`;
    fs.writeFileSync(
      path.join(trustDir, managedPem),
      "-----BEGIN CERTIFICATE-----\nMANAGED\n-----END CERTIFICATE-----\n"
    );

    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    const result = cleanupStaleDevCerts(stale);

    expect(result.rehashedTrustDir).toBe(false);
    expect(fs.existsSync(path.join(trustDir, managedPem))).toBe(true);
  });

  // If a downstream file can't be unlinked, the My PFX must survive so
  // the cert is re-discoverable on the next attempt.
  it("keeps the My PFX when a downstream Root unlink fails — cert remains discoverable", async () => {
    fs.writeFileSync(path.join(storeDir, `${STALE_THUMB}.pfx`), devCertPfx());
    // Non-empty directory at the Root path → unlinkSync throws
    // (EISDIR / ENOTEMPTY) without needing chmod tricks that don't work as
    // root in CI test containers.
    const rootCandidate = path.join(rootStoreDir, `${STALE_THUMB}.pfx`);
    fs.mkdirSync(rootCandidate);
    fs.writeFileSync(path.join(rootCandidate, "blocker"), "x");
    const stalePem = `aspnetcore-localhost-${STALE_THUMB}.pem`;
    fs.writeFileSync(
      path.join(trustDir, stalePem),
      "-----BEGIN CERTIFICATE-----\nSTALE\n-----END CERTIFICATE-----\n"
    );

    const stale = await findStaleDevCerts(
      buildManagedMyStoreThumbprints(managedBundle())
    );
    expect(stale).toHaveLength(1);
    const result = cleanupStaleDevCerts(stale);

    expect(result.removedCerts).toEqual([]);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].thumbprint).toBe(STALE_THUMB);
    expect(result.failed[0].artifact.location).toBe("root-store");

    // Trust-dir PEM unlink succeeded — must show up in `removed` so the
    // log reflects partial state.
    expect(
      result.removed.some(
        (r) => r.artifact.location === "trust-dir" && r.thumbprint === STALE_THUMB
      )
    ).toBe(true);
    expect(fs.existsSync(path.join(trustDir, stalePem))).toBe(false);

    // My PFX is preserved → next cleanup pass can re-discover the cert and
    // retry the downstream sweep after the user fixes the failing path.
    expect(fs.existsSync(path.join(storeDir, `${STALE_THUMB}.pfx`))).toBe(true);
    expect(
      result.removed.some((r) => r.artifact.location === "my-store")
    ).toBe(false);
    // The blocker dir is still there because the unlink failed.
    expect(fs.existsSync(rootCandidate)).toBe(true);
  });
});
