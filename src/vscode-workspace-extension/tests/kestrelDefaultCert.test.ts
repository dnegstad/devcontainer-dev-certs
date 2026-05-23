import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type * as Shared from "@devcontainer-dev-certs/shared";
import type { CertMaterialV3 } from "@devcontainer-dev-certs/shared";

// Sandbox the well-known Kestrel default path under a temp dir so the test
// can assert against an isolated filesystem location.
let kestrelDir: string;
let kestrelPath: string;

vi.mock("@devcontainer-dev-certs/shared", async (importOriginal) => {
  const original = await importOriginal<typeof Shared>();
  return {
    ...original,
    getKestrelDefaultCertPath: () => kestrelPath,
  };
});

import {
  writeKestrelDefaultCert,
  removeKestrelDefaultCert,
} from "../src/certInstaller";

const cleanupDirs: string[] = [];

beforeEach(() => {
  kestrelDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-kestrel-"));
  kestrelPath = path.join(kestrelDir, "nested", "kestrel-default.pfx");
  cleanupDirs.push(kestrelDir);
});

afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

function userMaterial(pfxBase64: string | undefined): CertMaterialV3 {
  return {
    kind: "user",
    name: "corp-ca",
    thumbprint: "AABBCCDDEEFF",
    pemCertBase64: Buffer.from(
      "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
    ).toString("base64"),
    pfxBase64,
    trustInContainer: true,
    installToDotNetStore: false,
  };
}

describe.skipIf(process.platform === "win32")("writeKestrelDefaultCert", () => {
  it("writes the PFX bytes to the well-known path with 0o600", () => {
    const bytes = Buffer.from("VERBATIM-PFX-BYTES");
    const material = userMaterial(bytes.toString("base64"));

    const written = writeKestrelDefaultCert(material);
    expect(written).toBe(kestrelPath);
    expect(fs.readFileSync(kestrelPath).equals(bytes)).toBe(true);
    const mode = fs.statSync(kestrelPath).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("creates the parent directory if it doesn't exist", () => {
    const bytes = Buffer.from("X");
    expect(fs.existsSync(path.dirname(kestrelPath))).toBe(false);
    writeKestrelDefaultCert(userMaterial(bytes.toString("base64")));
    expect(fs.existsSync(kestrelPath)).toBe(true);
  });

  it("overwrites an existing PFX (re-application is idempotent)", () => {
    writeKestrelDefaultCert(
      userMaterial(Buffer.from("OLD").toString("base64"))
    );
    writeKestrelDefaultCert(
      userMaterial(Buffer.from("NEW").toString("base64"))
    );
    expect(fs.readFileSync(kestrelPath).toString()).toBe("NEW");
  });

  it("throws when the material carries no PFX bytes", () => {
    expect(() => writeKestrelDefaultCert(userMaterial(undefined))).toThrow(
      /no PFX bytes/
    );
    expect(fs.existsSync(kestrelPath)).toBe(false);
  });
});

describe("removeKestrelDefaultCert", () => {
  it("removes the file when present", () => {
    fs.mkdirSync(path.dirname(kestrelPath), { recursive: true });
    fs.writeFileSync(kestrelPath, "stale");
    expect(fs.existsSync(kestrelPath)).toBe(true);

    removeKestrelDefaultCert();
    expect(fs.existsSync(kestrelPath)).toBe(false);
  });

  it("is a no-op when the file is absent", () => {
    expect(() => removeKestrelDefaultCert()).not.toThrow();
  });
});
