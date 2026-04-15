import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { runProcess, runInTerminal } from "./processUtil";
import { isValidDevCert, computeThumbprint } from "../cert/generator";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { certToDer } from "../cert/exporter";

/** Cached PowerShell executable name — prefers pwsh (PowerShell 7+) over powershell (5.1). */
let resolvedPwsh: string | null = null;

async function getPowerShell(): Promise<string> {
  if (resolvedPwsh) return resolvedPwsh;

  const pwshResult = await runProcess("pwsh", ["-NoProfile", "-Command", "echo ok"]);
  if (pwshResult.exitCode === 0) {
    resolvedPwsh = "pwsh";
  } else {
    resolvedPwsh = "powershell";
  }
  return resolvedPwsh;
}

/**
 * Windows certificate store implementation.
 *
 * Uses PowerShell to interact with the Windows Certificate Store:
 * - CurrentUser\My: stores cert with private key
 * - CurrentUser\Root: trusts the public cert
 *
 * Prefers pwsh (PowerShell 7+) when available, falls back to powershell (5.1).
 */
export class WindowsCertificateStore extends BaseCertificateStore {
  async findExistingDevCert(): Promise<{
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
  } | null> {
    // Use PowerShell to find dev certs in CurrentUser\My and export the best one as PFX
    const script = `
      $ErrorActionPreference = 'Stop'
      $oid = '${ASPNET_HTTPS_OID}'
      $certs = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {
        $_.Extensions | Where-Object { $_.Oid.Value -eq $oid }
      } | Sort-Object NotAfter -Descending
      if ($certs.Count -eq 0) { exit 1 }
      $best = $certs[0]
      $tmpPfx = Join-Path $env:TEMP ("devcert-" + [guid]::NewGuid().ToString("N") + ".pfx")
      $pwd = ConvertTo-SecureString -String "export" -Force -AsPlainText
      Export-PfxCertificate -Cert $best -FilePath $tmpPfx -Password $pwd | Out-Null
      Write-Output $tmpPfx
    `;

    const pwsh = await getPowerShell();
    const result = await runProcess(pwsh, [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    if (result.exitCode !== 0) return null;

    const pfxPath = result.stdout.trim();
    try {
      const loaded = this.loadPfx(pfxPath, "export");
      if (!loaded || !isValidDevCert(loaded.cert)) return null;
      return loaded;
    } finally {
      try {
        fs.unlinkSync(pfxPath);
      } catch {
        // best effort cleanup
      }
    }
  }

  async saveCertificate(
    cert: forge.pki.Certificate,
    key: forge.pki.rsa.PrivateKey,
    _thumbprint: string
  ): Promise<void> {
    // Export to temp PFX, then import via X509Store API (more reliable than Import-PfxCertificate)
    const tmpPfx = path.join(
      os.tmpdir(),
      `devcert-save-${Date.now()}.pfx`
    );
    this.writePfx(cert, key, tmpPfx, "import");

    const script =
      `$ErrorActionPreference = 'Stop'; ` +
      `$pfxBytes = [System.IO.File]::ReadAllBytes('${tmpPfx.replace(/'/g, "''")}'); ` +
      `$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(` +
        `$pfxBytes, 'import', ` +
        `[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor ` +
        `[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet); ` +
      `$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser'); ` +
      `$store.Open('ReadWrite'); ` +
      `$store.Add($cert); ` +
      `$store.Close(); ` +
      `Remove-Item '${tmpPfx.replace(/'/g, "''")}'`;

    const pwsh = await getPowerShell();
    const result = await runProcess(pwsh, [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    if (result.exitCode !== 0) {
      // Clean up temp file if PowerShell didn't
      try { fs.unlinkSync(tmpPfx); } catch { /* ignore */ }
      throw new Error(`Failed to save certificate to Windows store: ${result.stderr}`);
    }
  }

  async trustCertificate(cert: forge.pki.Certificate): Promise<void> {
    // Export public cert as DER, import to CurrentUser\Root via PowerShell in a visible terminal
    const tmpCert = path.join(
      os.tmpdir(),
      `devcert-trust-${Date.now()}.cer`
    );
    fs.writeFileSync(tmpCert, certToDer(cert));

    const script =
      `$ErrorActionPreference = 'Stop'; ` +
      `$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('${tmpCert.replace(/'/g, "''")}'); ` +
      `$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser'); ` +
      `$store.Open('ReadWrite'); ` +
      `$store.Add($cert); ` +
      `$store.Close(); ` +
      `Remove-Item '${tmpCert.replace(/'/g, "''")}'`;

    const pwsh = await getPowerShell();
    const exitCode = await runInTerminal("Dev Certs: Trust Certificate", pwsh, [
      "-NoProfile",
      "-NoExit",
      "-Command",
      script,
    ]);

    if (exitCode !== 0) {
      try { fs.unlinkSync(tmpCert); } catch { /* ignore */ }
      throw new Error("Failed to trust certificate on Windows. Check the terminal output for details.");
    }
  }

  async removeCertificates(): Promise<void> {
    const script = `
      $ErrorActionPreference = 'SilentlyContinue'
      $oid = '${ASPNET_HTTPS_OID}'
      foreach ($storeName in @('My', 'Root')) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'CurrentUser')
        $store.Open('ReadWrite')
        $toRemove = $store.Certificates | Where-Object {
          $_.Extensions | Where-Object { $_.Oid.Value -eq $oid }
        }
        foreach ($cert in $toRemove) {
          $store.Remove($cert)
        }
        $store.Close()
      }
    `;

    const pwsh = await getPowerShell();
    await runProcess(pwsh, [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);
  }

  protected async isTrusted(
    _cert: forge.pki.Certificate,
    thumbprint: string
  ): Promise<boolean> {
    const script = `
      $cert = Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object { $_.Thumbprint -eq '${thumbprint}' }
      if ($cert) { Write-Output 'true' } else { Write-Output 'false' }
    `;

    const pwsh = await getPowerShell();
    const result = await runProcess(pwsh, [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    return result.stdout.trim() === "true";
  }
}
