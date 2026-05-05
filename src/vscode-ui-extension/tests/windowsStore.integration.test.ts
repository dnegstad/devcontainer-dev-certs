import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { execFileSync } from "child_process";
import { WindowsCertificateStore } from "../src/platform/windowsStore";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

const enabled =
  process.platform === "win32" &&
  process.env["DEVCERTS_WINDOWS_STORE_INTEGRATION"] === "1";

let pwsh = "powershell";
const importedThumbprints: string[] = [];

function psString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function runPowerShell(script: string): string {
  return execFileSync(pwsh, ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
  }).trim();
}

function resolvePowerShell(): string {
  try {
    execFileSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", "'ok'"], {
      stdio: "ignore",
      timeout: 10_000,
    });
    return "pwsh";
  } catch {
    return "powershell";
  }
}

function removeLocalMachineCert(thumbprint: string): void {
  const quotedThumbprint = psString(thumbprint);
  runPowerShell(`
    $ErrorActionPreference = 'SilentlyContinue'
    foreach ($storeName in @('My', 'Root')) {
      $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'LocalMachine')
      $store.Open('ReadWrite')
      foreach ($cert in @($store.Certificates | Where-Object { $_.Thumbprint -eq ${quotedThumbprint} })) {
        $store.Remove($cert)
      }
      $store.Close()
    }
  `);
}

async function makeTestCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
  return generateCertificate(now, expiry);
}

describe.skipIf(!enabled)(
  "WindowsCertificateStore LocalMachine integration",
  () => {
    beforeAll(() => {
      pwsh = resolvePowerShell();
      const isAdmin = runPowerShell(`
        $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
      `);
      if (isAdmin !== "True") {
        throw new Error(
          "DEVCERTS_WINDOWS_STORE_INTEGRATION requires an elevated Windows process for LocalMachine store writes."
        );
      }
    });

    afterEach(() => {
      for (const thumbprint of importedThumbprints.splice(0)) {
        removeLocalMachineCert(thumbprint);
      }
    });

    it("imports the generated PFX with a private key and trusts it via LocalMachine stores", async () => {
      const store = new WindowsCertificateStore("LocalMachine");
      const { cert, key, thumbprint } = await makeTestCert();
      importedThumbprints.push(thumbprint);

      await store.saveCertificate(cert, key, thumbprint);
      await store.trustCertificate(cert);

      const quotedThumbprint = psString(thumbprint);
      const hasPrivateKey = runPowerShell(`
        $cert = Get-ChildItem Cert:\\LocalMachine\\My\\${thumbprint}
        if (-not $cert) { throw "Missing LocalMachine\\My cert ${thumbprint}" }
        $cert.HasPrivateKey
      `);
      const trusted = runPowerShell(`
        $cert = Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Thumbprint -eq ${quotedThumbprint} }
        if ($cert) { 'True' } else { 'False' }
      `);
      const status = await store.checkStatus();

      expect(hasPrivateKey).toBe("True");
      expect(trusted).toBe("True");
      expect(status.exists).toBe(true);
      expect(status.isTrusted).toBe(true);
      expect(status.thumbprint).toBe(thumbprint);
    }, 120_000);
  }
);
