import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { BaseCertificateStore } from "./baseStore";
import { runProcess } from "./processUtil";
import { isValidDevCert } from "../cert/generator";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { certToDer } from "../cert/exporter";
import { type DevCert, type DevKey } from "../cert/types";

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
    cert: DevCert;
    key: DevKey;
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
      # AES256_SHA256 forces a PBES2/AES PFX. The default (TripleDES_SHA1)
      # produces a legacy PKCS#12 PBE format that our pkijs-based parser
      # deliberately rejects (see cert/pfx.ts).
      Export-PfxCertificate -Cert $best -FilePath $tmpPfx -Password $pwd -CryptoAlgorithmOption AES256_SHA256 | Out-Null
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
      const loaded = await this.loadPfx(pfxPath, "export");
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
    cert: DevCert,
    key: DevKey,
    _thumbprint: string
  ): Promise<void> {
    // Export to temp PFX, then import via Import-PfxCertificate. We previously
    // used `new X509Certificate2(bytes, pwd, Exportable | PersistKeySet)` +
    // `X509Store.Add`, but that drives the legacy CryptoAPI PFXImportCertStore
    // path which fails with "An internal error occurred" on PBES2/AES PFXes
    // (the format pkijs emits). Import-PfxCertificate handles modern PKCS#12
    // formats correctly.
    const tmpPfx = path.join(os.tmpdir(), `devcert-save-${Date.now()}.pfx`);
    await this.writePfx(cert, key, tmpPfx, "import");

    const script =
      `$ErrorActionPreference = 'Stop'; ` +
      `$pwd = ConvertTo-SecureString -String 'import' -Force -AsPlainText; ` +
      `Import-PfxCertificate -FilePath '${tmpPfx.replace(/'/g, "''")}' -CertStoreLocation Cert:\\CurrentUser\\My -Password $pwd -Exportable | Out-Null; ` +
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
      try {
        fs.unlinkSync(tmpPfx);
      } catch {
        /* ignore */
      }
      throw new Error(
        `Failed to save certificate to Windows store: ${result.stderr}`
      );
    }
  }

  async trustCertificate(cert: DevCert): Promise<void> {
    // Export public cert as DER, import to CurrentUser\Root via X509Store API
    const tmpCert = path.join(os.tmpdir(), `devcert-trust-${Date.now()}.cer`);
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
    const result = await runProcess(pwsh, [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    if (result.exitCode !== 0) {
      try {
        fs.unlinkSync(tmpCert);
      } catch {
        /* ignore */
      }
      throw new Error(
        `Failed to trust certificate on Windows: ${result.stderr}`
      );
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
    _cert: DevCert,
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
