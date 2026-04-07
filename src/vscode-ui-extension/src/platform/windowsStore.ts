import * as forge from "node-forge";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { PlatformCertificateStore, CertificateStatus } from "./types";
import { runProcess } from "./processUtil";
import {
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
} from "../cert/generator";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { certToDer } from "../cert/exporter";

/**
 * Windows certificate store implementation.
 *
 * Uses PowerShell to interact with the Windows Certificate Store:
 * - CurrentUser\My: stores cert with private key
 * - CurrentUser\Root: trusts the public cert
 *
 * PFX import/export is done via PowerShell's Import-PfxCertificate and the
 * cert: drive for enumeration and removal.
 */
export class WindowsCertificateStore implements PlatformCertificateStore {
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

    const result = await runProcess("powershell", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    if (result.exitCode !== 0) return null;

    const pfxPath = result.stdout.trim();
    try {
      const pfxBytes = fs.readFileSync(pfxPath);
      const p12Der = forge.util.createBuffer(pfxBytes.toString("binary"));
      const p12Asn1 = forge.asn1.fromDer(p12Der);
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, "export");

      // Extract certificate
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
      const certBag = certBags[forge.pki.oids.certBag];
      if (!certBag || certBag.length === 0) return null;
      const cert = certBag[0].cert;
      if (!cert) return null;

      // Extract private key
      const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
      if (!keyBag || keyBag.length === 0) return null;
      const key = keyBag[0].key;
      if (!key) return null;

      if (!isValidDevCert(cert)) return null;

      const thumbprint = computeThumbprint(forge.pki.certificateToPem(cert));

      return { cert, key, thumbprint };
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
    thumbprint: string
  ): Promise<void> {
    // Export to temp PFX, then import via PowerShell
    const tmpPfx = path.join(
      os.tmpdir(),
      `devcert-save-${Date.now()}.pfx`
    );
    try {
      const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], "import", {
        algorithm: "3des",
      });
      const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
      fs.writeFileSync(tmpPfx, Buffer.from(p12Der, "binary"));

      const script = `
        $ErrorActionPreference = 'Stop'
        $pwd = ConvertTo-SecureString -String "import" -Force -AsPlainText
        Import-PfxCertificate -FilePath '${tmpPfx.replace(/'/g, "''")}' -CertStoreLocation Cert:\\CurrentUser\\My -Password $pwd -Exportable | Out-Null
      `;

      const result = await runProcess("powershell", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
      ]);

      if (result.exitCode !== 0) {
        throw new Error(
          `Failed to save certificate to Windows store: ${result.stderr}`
        );
      }
    } finally {
      try {
        fs.unlinkSync(tmpPfx);
      } catch {
        // best effort cleanup
      }
    }
  }

  async trustCertificate(cert: forge.pki.Certificate): Promise<void> {
    // Export public cert as DER, import to CurrentUser\Root via PowerShell
    const tmpCert = path.join(
      os.tmpdir(),
      `devcert-trust-${Date.now()}.cer`
    );
    try {
      const derBytes = certToDer(cert);
      fs.writeFileSync(tmpCert, derBytes);

      const script = `
        $ErrorActionPreference = 'Stop'
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('${tmpCert.replace(/'/g, "''")}')
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
        $store.Open('ReadWrite')
        $store.Add($cert)
        $store.Close()
      `;

      const result = await runProcess("powershell", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
      ]);

      if (result.exitCode !== 0) {
        throw new Error(
          `Failed to trust certificate on Windows: ${result.stderr}`
        );
      }
    } finally {
      try {
        fs.unlinkSync(tmpCert);
      } catch {
        // best effort cleanup
      }
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

    await runProcess("powershell", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);
  }

  async checkStatus(): Promise<CertificateStatus> {
    const found = await this.findExistingDevCert();
    if (!found) {
      return {
        exists: false,
        isTrusted: false,
        thumbprint: null,
        notBefore: null,
        notAfter: null,
        version: -1,
      };
    }

    const { cert, thumbprint } = found;
    const isTrusted = await this.isTrustedInRootStore(thumbprint);
    const version = getCertificateVersion(cert);

    return {
      exists: true,
      isTrusted,
      thumbprint,
      notBefore: cert.validity.notBefore.toISOString(),
      notAfter: cert.validity.notAfter.toISOString(),
      version,
    };
  }

  private async isTrustedInRootStore(thumbprint: string): Promise<boolean> {
    const script = `
      $cert = Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object { $_.Thumbprint -eq '${thumbprint}' }
      if ($cert) { Write-Output 'true' } else { Write-Output 'false' }
    `;

    const result = await runProcess("powershell", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    return result.stdout.trim() === "true";
  }
}
