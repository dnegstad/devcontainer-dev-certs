import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { writeExtraDestination } from "../src/certInstaller";
import { parseExtraCertDestinations } from "../src/util/destinations";
import type { CertMaterialV2 } from "@devcontainer-dev-certs/shared";

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-ws-test-"));
}

const cleanupDirs: string[] = [];
afterEach(() => {
  for (const dir of cleanupDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  cleanupDirs.length = 0;
});

function fakeMaterial(name: string): CertMaterialV2 {
  const pemCert = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n";
  const pemKey = "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEY\n-----END RSA PRIVATE KEY-----\n";
  return {
    kind: "user",
    name,
    thumbprint: "ABCDEF",
    pemCertBase64: Buffer.from(pemCert).toString("base64"),
    pemKeyBase64: Buffer.from(pemKey).toString("base64"),
    pfxBase64: Buffer.from("PFXBYTES").toString("base64"),
    trustInContainer: true,
  };
}

describe("writeExtraDestination", () => {
  it("writes pem/key/pfx/bundle into a directory for format=all (default)", () => {
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { destinations } = parseExtraCertDestinations(dir);
    expect(destinations).toHaveLength(1);
    const result = writeExtraDestination(destinations[0], fakeMaterial("corp"));
    expect(result.errors).toEqual([]);
    expect(result.rehashDir).toBe(dir);

    expect(fs.readdirSync(dir).sort()).toEqual(
      ["corp-bundle.pem", "corp.key", "corp.pem", "corp.pfx"].sort()
    );
  });

  it("respects format=pem by writing only the cert", () => {
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { destinations } = parseExtraCertDestinations(`${dir}=pem`);
    writeExtraDestination(destinations[0], fakeMaterial("corp"));

    expect(fs.readdirSync(dir)).toEqual(["corp.pem"]);
  });

  it("writes a pem-bundle containing cert + key", () => {
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { destinations } = parseExtraCertDestinations(`${dir}=pem-bundle`);
    writeExtraDestination(destinations[0], fakeMaterial("corp"));

    const bundle = fs.readFileSync(path.join(dir, "corp-bundle.pem"), "utf-8");
    expect(bundle).toContain("BEGIN CERTIFICATE");
    expect(bundle).toContain("BEGIN RSA PRIVATE KEY");
  });

  it("skips key + pfx output when material has no private key", () => {
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const material: CertMaterialV2 = {
      ...fakeMaterial("ca-only"),
      pemKeyBase64: undefined,
      pfxBase64: undefined,
    };
    const { destinations } = parseExtraCertDestinations(dir);
    writeExtraDestination(destinations[0], material);

    const files = fs.readdirSync(dir).sort();
    expect(files).toContain("ca-only.pem");
    expect(files).toContain("ca-only-bundle.pem");
    expect(files).not.toContain("ca-only.key");
    expect(files).not.toContain("ca-only.pfx");
  });

  it("tolerates a trailing slash on the destination path", () => {
    const dir = tmpDir();
    cleanupDirs.push(dir);

    const { destinations } = parseExtraCertDestinations(`${dir}/=pem`);
    const result = writeExtraDestination(
      destinations[0],
      fakeMaterial("corp")
    );
    expect(result.rehashDir).toBe(dir);
    expect(fs.readdirSync(dir)).toEqual(["corp.pem"]);
  });
});
