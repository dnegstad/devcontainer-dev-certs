import { randomUUID } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  BaseCertificateStore,
  classifyCandidate,
  selectBestDevCert,
  type UsableDevCert,
} from "./baseStore";
import { runProcess } from "./processUtil";
import { ASPNET_HTTPS_OID } from "../cert/properties";
import { certToDer } from "../cert/exporter";
import { type DevCert, type DevKey } from "../cert/types";

/** Cached PowerShell executable name — prefers pwsh (PowerShell 7+) over powershell (5.1). */
let resolvedPwsh: string | null = null;

export type WindowsStoreLocation = "CurrentUser" | "LocalMachine";

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
 * Shape of one entry in the PowerShell enumeration script's `candidates`
 * array — a cert whose private key was successfully exported as a PFX.
 */
export interface PsCandidate {
  thumbprint: string;
  pfxPath: string;
  subjectCN: string | null;
  notBefore: string;
  notAfter: string;
}

/**
 * Shape of one entry in the PowerShell enumeration script's `skipped`
 * array — a cert that matched the dev-cert OID but couldn't be exported
 * (no private key, or key not exportable).
 */
export interface PsSkipped {
  thumbprint: string;
  subjectCN: string | null;
  notBefore: string;
  notAfter: string;
  reason: string;
}

export interface PsEnumeration {
  candidates: PsCandidate[];
  skipped: PsSkipped[];
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
  constructor(private readonly storeLocation: WindowsStoreLocation = "CurrentUser") {
    super();
  }

  async findExistingDevCert(): Promise<UsableDevCert | null> {
    // Enumerate every dev-cert candidate in the configured My store, then
    // attempt to export each as a PBES2/AES PFX. We hand selection back to
    // shared TS so the version-byte tiebreaker logic stays in one place.
    const script = `
      $ErrorActionPreference = 'Stop'
      $oid = '${ASPNET_HTTPS_OID}'
      $candidates = New-Object System.Collections.ArrayList
      $skipped = New-Object System.Collections.ArrayList
      $certs = Get-ChildItem Cert:\\${this.storeLocation}\\My | Where-Object {
        $_.Extensions | Where-Object { $_.Oid.Value -eq $oid }
      }
      foreach ($cert in $certs) {
        $thumb = $cert.Thumbprint
        $cn = $null
        try { $cn = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch {}
        $nbf = $cert.NotBefore.ToUniversalTime().ToString('o')
        $exp = $cert.NotAfter.ToUniversalTime().ToString('o')
        if (-not $cert.HasPrivateKey) {
          [void]$skipped.Add(@{ thumbprint = $thumb; subjectCN = $cn; notBefore = $nbf; notAfter = $exp; reason = 'no private key in store' })
          continue
        }
        try {
          $tmpPfx = Join-Path $env:TEMP ("devcert-" + [guid]::NewGuid().ToString("N") + ".pfx")
          $pwd = ConvertTo-SecureString -String 'export' -Force -AsPlainText
          # AES256_SHA256 forces a PBES2/AES PFX. The default (TripleDES_SHA1)
          # produces a legacy PKCS#12 PBE format that our pkijs-based parser
          # deliberately rejects (see cert/pfx.ts).
          Export-PfxCertificate -Cert $cert -FilePath $tmpPfx -Password $pwd -CryptoAlgorithmOption AES256_SHA256 | Out-Null
          [void]$candidates.Add(@{ thumbprint = $thumb; pfxPath = $tmpPfx; subjectCN = $cn; notBefore = $nbf; notAfter = $exp })
        } catch {
          $msg = $_.Exception.Message
          # $cert.PrivateKey.Key.ExportPolicy resolves only for RSA/CNG-backed
          # keys. Legacy CAPI keys and non-RSA algorithms surface the policy
          # at a different path (or not at all) — we treat the lookup as
          # best-effort and fall back to message-string matching when it
          # throws or returns null.
          $policy = $null
          try { $policy = $cert.PrivateKey.Key.ExportPolicy } catch {}
          if ($policy) {
            $reason = "private key not exportable (KeyExportPolicy=$policy)"
          } elseif ($msg -match 'not exportable' -or $msg -match 'cannot be exported') {
            $reason = 'private key not exportable'
          } else {
            $reason = "Export-PfxCertificate failed: $msg"
          }
          [void]$skipped.Add(@{ thumbprint = $thumb; subjectCN = $cn; notBefore = $nbf; notAfter = $exp; reason = $reason })
        }
      }
      $payload = @{ candidates = $candidates; skipped = $skipped }
      $payload | ConvertTo-Json -Compress -Depth 4
    `;

    const pwsh = await getPowerShell();
    const result = await runProcess(pwsh, [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      script,
    ]);

    if (result.exitCode !== 0) return null;

    const parsed = parseEnumeration(result.stdout);
    if (!parsed) return null;

    const tempPfxPaths: string[] = parsed.candidates.map((c) => c.pfxPath);
    try {
      const usable: UsableDevCert[] = [];
      const storeContext = `Windows ${this.storeLocation}\\My`;

      for (const cand of parsed.candidates) {
        const loaded = await this.loadPfxLenient(cand.pfxPath, "export");
        if (!loaded) {
          // PFX produced by Export-PfxCertificate failed to parse — surface
          // as an unusable warning so the user has visibility.
          classifyCandidate({
            kind: "forcedSkip",
            source: storeContext,
            reason:
              "Export-PfxCertificate produced a PFX that could not be parsed",
            metadata: {
              thumbprint: cand.thumbprint,
              subjectCN: cand.subjectCN,
              notBefore: parseDateOrNull(cand.notBefore),
              notAfter: parseDateOrNull(cand.notAfter),
            },
          });
          continue;
        }

        const classified = classifyCandidate({
          kind: "loaded",
          source: storeContext,
          loaded,
        });
        if (classified === null) continue;
        if (classified.kind === "usable") usable.push(classified);
      }

      for (const sk of parsed.skipped) {
        // Re-apply isValidDevCert gates against the metadata we received so
        // we don't emit the unusable warning for clearly-unrelated certs
        // that happened to share the OID but are e.g. expired.
        if (!metadataLooksLikeValidDevCert(sk)) continue;
        classifyCandidate({
          kind: "forcedSkip",
          source: storeContext,
          reason: sk.reason,
          metadata: {
            thumbprint: sk.thumbprint,
            subjectCN: sk.subjectCN,
            notBefore: parseDateOrNull(sk.notBefore),
            notAfter: parseDateOrNull(sk.notAfter),
          },
        });
      }

      return selectBestDevCert(usable, storeContext);
    } finally {
      for (const p of tempPfxPaths) {
        try {
          fs.unlinkSync(p);
        } catch {
          // best effort cleanup
        }
      }
    }
  }

  async saveCertificate(
    cert: DevCert,
    key: DevKey,
    _thumbprint: string
  ): Promise<void> {
    // Export to temp PFX, then import via Import-PfxCertificate. Our
    // hand-rolled DER PFX writer (cert/pfx.ts) emits a PFX that CryptoAPI's
    // PFXImportCertStore — the function this cmdlet wraps — accepts cleanly.
    // Unguessable filename + 0o600 keeps the PFX (with private key)
    // unreadable to other local users during the import window.
    const tmpPfx = path.join(os.tmpdir(), `devcert-save-${randomUUID()}.pfx`);
    await this.writePfx(cert, key, tmpPfx, "import", 0o600);

    const script =
      `$ErrorActionPreference = 'Stop'; ` +
      `$pwd = ConvertTo-SecureString -String 'import' -Force -AsPlainText; ` +
      `Import-PfxCertificate -FilePath '${tmpPfx.replace(/'/g, "''")}' -CertStoreLocation Cert:\\${this.storeLocation}\\My -Password $pwd -Exportable | Out-Null; ` +
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
    // Use certutil.exe — the built-in Windows CA admin tool from
    // %SystemRoot%\System32, present on every Windows install since XP — to
    // add the public cert to the configured Root store.
    //
    // We can't go back to `Import-Certificate` (the PowerShell PKI cmdlet
    // PR #36 switched to): when it targets Cert:\CurrentUser\Root the
    // underlying CryptoAPI call shows a "You are about to install a
    // certificate from a certification authority..." confirmation dialog,
    // which fails under `-NonInteractive` with "UI is not allowed in this
    // operation." We also intentionally avoid the older path of
    // `New-Object System.Security.Cryptography.X509Certificates.X509Store`
    // — the host extension is meant to work without taking on a .NET
    // dependency. certutil.exe uses CryptoAPI directly, skips the
    // confirmation dialog, and is the same tool mkcert and similar dev-cert
    // utilities use on Windows for the same reason.
    //
    // Public-cert only — no private key — but the random name still
    // prevents concurrent invocations from colliding on the same temp path.
    const tmpCert = path.join(os.tmpdir(), `devcert-trust-${randomUUID()}.cer`);
    fs.writeFileSync(tmpCert, certToDer(cert));

    const args = ["-f"];
    if (this.storeLocation === "CurrentUser") args.push("-user");
    args.push("-addstore", "Root", tmpCert);

    const result = await runProcess("certutil.exe", args);

    try {
      fs.unlinkSync(tmpCert);
    } catch {
      /* best effort */
    }

    if (result.exitCode !== 0) {
      throw new Error(
        `Failed to trust certificate on Windows: ${result.stderr || result.stdout}`
      );
    }
  }

  async removeCertificates(): Promise<void> {
    const script = `
      $ErrorActionPreference = 'SilentlyContinue'
      $oid = '${ASPNET_HTTPS_OID}'
      foreach ($storePath in @('Cert:\\${this.storeLocation}\\My', 'Cert:\\${this.storeLocation}\\Root')) {
        Get-ChildItem $storePath | Where-Object {
          $_.Extensions | Where-Object { $_.Oid.Value -eq $oid }
        } | ForEach-Object {
          Remove-Item -LiteralPath $_.PSPath -Force
        }
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
      $cert = Get-ChildItem Cert:\\${this.storeLocation}\\Root | Where-Object { $_.Thumbprint -eq '${thumbprint}' }
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

function parseEnumeration(stdout: string): PsEnumeration | null {
  const trimmed = stdout.trim();
  if (!trimmed) return { candidates: [], skipped: [] };

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }

  // PowerShell's ConvertTo-Json emits a hashtable with a single child as a
  // bare object rather than a 1-element array; coerce defensively.
  if (!parsed || typeof parsed !== "object") return null;
  const root = parsed as Record<string, unknown>;
  return {
    candidates: coerceArray<PsCandidate>(root.candidates),
    skipped: coerceArray<PsSkipped>(root.skipped),
  };
}

function coerceArray<T>(value: unknown): T[] {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value as T[];
  return [value as T];
}

function parseDateOrNull(s: string | null | undefined): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

function metadataLooksLikeValidDevCert(sk: PsSkipped): boolean {
  // The PS script already filtered by ASPNET_HTTPS_OID. We layer CN +
  // validity-window checks on top so we don't emit the unusable warning
  // for clearly-unrelated certs (e.g. expired or differently-named) that
  // happened to carry the same OID. We can't check the version byte from
  // TS without parsing the cert, so we skip that gate here.
  //
  // CN comparison is intentionally exact-match to mirror isValidDevCert
  // (see cert/generator.ts:isValidDevCert) — staying loose here while the
  // canonical gate is strict would just produce warnings for certs we'd
  // never accept downstream anyway.
  if (sk.subjectCN !== "localhost") return false;
  const nbf = parseDateOrNull(sk.notBefore);
  const exp = parseDateOrNull(sk.notAfter);
  if (!nbf || !exp) return false;
  const now = new Date();
  if (nbf > now || exp < now) return false;
  return true;
}
