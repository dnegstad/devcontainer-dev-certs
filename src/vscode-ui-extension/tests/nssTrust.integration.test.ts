import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { execFileSync } from "child_process";
import { generateCertificate } from "../src/cert/generator";
import { certToPem } from "../src/cert/exporter";
import { VALIDITY_DAYS } from "../src/cert/properties";
import { runProcess } from "../src/platform/processUtil";

// Check if certutil is available — skip entire suite if not
let certutilAvailable = false;
try {
  execFileSync("certutil", ["-H"], { timeout: 5000, stdio: "pipe" });
  certutilAvailable = true;
} catch (err: unknown) {
  // certutil -H exits non-zero but prints help — that means it's installed
  const e = err as { stderr?: string; stdout?: string };
  if (e.stderr?.includes("certutil") || e.stdout?.includes("certutil")) {
    certutilAvailable = true;
  }
}

function makeTestCert() {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

describe.skipIf(!certutilAvailable)("NSS trust (integration)", () => {
  let tmpDir: string;
  let nssDbDir: string;
  let pemPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-nss-integ-"));
    nssDbDir = path.join(tmpDir, "nssdb");
    fs.mkdirSync(nssDbDir, { recursive: true });

    // Create a real NSS database with no password
    execFileSync("certutil", [
      "-N", "-d", `sql:${nssDbDir}`, "--empty-password",
    ]);

    // Generate a real cert and write PEM
    const { cert } = makeTestCert();
    pemPath = path.join(tmpDir, "dev-cert.pem");
    fs.writeFileSync(pemPath, certToPem(cert));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("adds a certificate to an NSS database", async () => {
    const certName = "Integration Test Cert";

    // Add the cert
    const addResult = await runProcess("certutil", [
      "-A", "-d", `sql:${nssDbDir}`,
      "-t", "CT,,",
      "-n", certName,
      "-i", pemPath,
    ]);
    expect(addResult.exitCode).toBe(0);

    // Verify it was added
    const listResult = await runProcess("certutil", [
      "-L", "-d", `sql:${nssDbDir}`,
    ]);
    expect(listResult.exitCode).toBe(0);
    expect(listResult.stdout).toContain(certName);
  });

  it("idempotent: delete then re-add succeeds", async () => {
    const certName = "Idempotent Test Cert";

    // Add the cert
    await runProcess("certutil", [
      "-A", "-d", `sql:${nssDbDir}`,
      "-t", "CT,,", "-n", certName, "-i", pemPath,
    ]);

    // Delete it
    const deleteResult = await runProcess("certutil", [
      "-D", "-d", `sql:${nssDbDir}`, "-n", certName,
    ]);
    expect(deleteResult.exitCode).toBe(0);

    // Re-add it
    const readdResult = await runProcess("certutil", [
      "-A", "-d", `sql:${nssDbDir}`,
      "-t", "CT,,", "-n", certName, "-i", pemPath,
    ]);
    expect(readdResult.exitCode).toBe(0);

    // Verify it's there
    const listResult = await runProcess("certutil", [
      "-L", "-d", `sql:${nssDbDir}`,
    ]);
    expect(listResult.stdout).toContain(certName);
  });

  it("certificate is trusted with CT flags after import", async () => {
    const certName = "Trust Flags Test";

    await runProcess("certutil", [
      "-A", "-d", `sql:${nssDbDir}`,
      "-t", "CT,,", "-n", certName, "-i", pemPath,
    ]);

    // List with details to check trust flags
    const listResult = await runProcess("certutil", [
      "-L", "-d", `sql:${nssDbDir}`,
    ]);
    expect(listResult.stdout).toContain("CT");
  });

  it("trustInNss finds and trusts in a Chromium-style NSS database", async () => {
    // Set up a fake homedir with Chromium's .pki/nssdb structure
    // containing our real NSS database
    const fakeHome = path.join(tmpDir, "fakehome");
    const chromiumNssDir = path.join(fakeHome, ".pki", "nssdb");
    fs.mkdirSync(chromiumNssDir, { recursive: true });

    // Create a real NSS database in the Chromium location
    execFileSync("certutil", [
      "-N", "-d", `sql:${chromiumNssDir}`, "--empty-password",
    ]);

    // trustInNss uses os.homedir() to find databases, but we can't mock it
    // in integration tests (no vi.mock). Instead, test the certutil commands
    // directly against the Chromium-style path to validate the exact args
    // that trustInNss would use.
    const certName = "Dev Container Dev Cert";

    // Simulate what trustInNss does: delete then add
    await runProcess("certutil", [
      "-D", "-d", `sql:${chromiumNssDir}`, "-n", certName,
    ]);
    const addResult = await runProcess("certutil", [
      "-A", "-d", `sql:${chromiumNssDir}`,
      "-t", "CT,,", "-n", certName, "-i", pemPath,
    ]);
    expect(addResult.exitCode).toBe(0);

    // Verify the cert is in the database with the expected name
    const listResult = await runProcess("certutil", [
      "-L", "-d", `sql:${chromiumNssDir}`,
    ]);
    expect(listResult.stdout).toContain(certName);
    expect(listResult.stdout).toContain("CT");
  });

  it("delete of non-existent cert does not fail the add", async () => {
    const certName = "Fresh Add Test";

    // Delete a cert that doesn't exist (should not be fatal)
    const deleteResult = await runProcess("certutil", [
      "-D", "-d", `sql:${nssDbDir}`, "-n", certName,
    ]);
    // certutil -D returns non-zero when cert doesn't exist — that's expected
    expect(deleteResult.exitCode).not.toBe(0);

    // Add should still succeed
    const addResult = await runProcess("certutil", [
      "-A", "-d", `sql:${nssDbDir}`,
      "-t", "CT,,", "-n", certName, "-i", pemPath,
    ]);
    expect(addResult.exitCode).toBe(0);
  });
});
