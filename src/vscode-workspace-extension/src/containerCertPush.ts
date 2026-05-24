import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import {
  classifyCandidate,
  extractThumbprintHintFromFilename,
  getCertificateVersion,
  getDotNetStorePath,
  isValidDevCert,
  loadPfx,
  log,
  selectBestDevCert,
  type LoadedCert,
  type SkipReport,
  type UsableDevCert,
} from "@devcontainer-dev-certs/shared";

/**
 * Outcome of a single accept-container-cert call to the host. Matches
 * the contract documented in `acceptContainerDevCert` on the host side.
 */
export interface AcceptContainerCertResult {
  accepted: boolean;
  /**
   * Failure code. `host-setting-disabled` means the user hasn't opted in
   * on the host; `user-declined` means the consent prompt was rejected;
   * `non-local-sans` / `parse-failed` / `not-valid-dev-cert` describe
   * server-side validation outcomes.
   */
  reason?:
    | "host-setting-disabled"
    | "user-declined"
    | "parse-failed"
    | "not-valid-dev-cert"
    | "non-local-sans";
  /** Free-form supplemental detail (e.g. the offending SAN entries). */
  detail?: string;
}

const ACCEPT_COMMAND = "devcontainer-dev-certs.acceptContainerDevCert";

interface ScanResult {
  pfxPath: string;
  loaded: LoadedCert;
}

/**
 * Locate the best ASP.NET HTTPS dev certificate inside the container's
 * .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) using
 * the same classify-+-select-best rules the host uses on its own platform
 * stores. Returns null when no usable candidate is present.
 *
 * Logs the same multi-candidate warning the host emits — if a developer
 * has more than one valid dev cert in the container we pick the
 * highest-version / latest-notAfter and log which ones we considered, so
 * they can understand why a specific thumbprint won.
 */
export async function findBestContainerDevCert(): Promise<ScanResult | null> {
  const dir = getDotNetStorePath();
  if (!fs.existsSync(dir)) {
    log(
      `Container cert sync: .NET X509 store directory ${dir} not found; nothing to scan.`
    );
    return null;
  }

  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".pfx"))
    .map((f) => path.join(dir, f));

  if (files.length === 0) {
    log(`Container cert sync: no .pfx files under ${dir}.`);
    return null;
  }

  const usable: { scan: ScanResult; usable: UsableDevCert }[] = [];

  for (const filePath of files) {
    const fileName = path.basename(filePath);
    const thumbprintHint = extractThumbprintHintFromFilename(fileName);

    let loaded: LoadedCert;
    try {
      // Container-side dev certs are passwordless (the X509Store on Linux
      // opens with a null password and can't accept per-file passwords),
      // so no password is supplied.
      loaded = await loadPfx(filePath, "");
    } catch (err: unknown) {
      // Match the host's parse-failure path: only emit a warning if the
      // filename looks canonical (the cert is plausibly one of ours), so
      // unrelated tooling's .pfx files stay silent.
      classifyCandidate(
        { kind: "parseFailure", source: filePath, thumbprintHint },
        { onSkipped: (r) => logSkipReport(r) }
      );
      const message = err instanceof Error ? err.message : String(err);
      log(
        `Container cert sync: could not parse ${filePath}: ${message}`
      );
      continue;
    }

    const classified = classifyCandidate(
      {
        kind: "loaded",
        source: filePath,
        loaded: {
          cert: loaded.cert,
          key: loaded.key,
          thumbprint: loaded.thumbprint,
        },
      },
      { onSkipped: (r) => logSkipReport(r) }
    );

    if (classified === null) continue;
    if (classified.kind === "skipped") continue;

    usable.push({
      scan: { pfxPath: filePath, loaded },
      usable: {
        cert: classified.cert,
        key: classified.key,
        thumbprint: classified.thumbprint,
      },
    });
  }

  const selected = selectBestDevCert(
    usable.map((u) => u.usable),
    dir,
    {
      onMultipleCandidates: ({ selected: sel, candidates }) => {
        const header = vscode.l10n.t(
          "Container cert sync: multiple valid ASP.NET dev certs in {0}; selected {1}.",
          dir,
          sel.thumbprint
        );
        const lines = [
          header,
          vscode.l10n.t("  Candidates:"),
          ...candidates.map((c, i) =>
            vscode.l10n.t(
              "    {0} thumbprint={1} version={2} notBefore={3} notAfter={4}",
              i === 0
                ? vscode.l10n.t("[selected]")
                : vscode.l10n.t("[skipped] "),
              c.thumbprint,
              getCertificateVersion(c.cert),
              c.cert.notBefore.toISOString(),
              c.cert.notAfter.toISOString()
            )
          ),
        ];
        log(lines.join("\n"));
      },
    }
  );

  if (!selected) {
    log(
      `Container cert sync: no usable dev certs found in ${dir} (scanned ${files.length} file(s)).`
    );
    return null;
  }

  const match = usable.find((u) => u.usable === selected);
  return match?.scan ?? null;
}

/**
 * Render a localized log line for one skipped candidate during the
 * container-side scan. Mirrors the host's emitHostSkipLog but with
 * "Container cert sync:" prefixed phrasing so the workspace logs are
 * self-explanatory in the Remote output channel.
 */
function logSkipReport(report: SkipReport): void {
  let reason: string;
  switch (report.reasonCode) {
    case "missing-private-key":
      reason = vscode.l10n.t(
        "PFX contains certificate without matching private key"
      );
      break;
    case "parse-failed":
      reason = vscode.l10n.t(
        "failed to parse PFX (corrupt or wrong password)"
      );
      break;
    case "forced":
      reason = report.forcedReason ?? "";
      break;
  }
  const unknown = vscode.l10n.t("(unknown)");
  const meta = report.metadata;
  const subjectCN = meta.subjectCN ?? unknown;
  const version =
    meta.version === undefined || meta.version === null
      ? unknown
      : String(meta.version);
  const notBefore = meta.notBefore ? meta.notBefore.toISOString() : unknown;
  const notAfter = meta.notAfter ? meta.notAfter.toISOString() : unknown;
  log(
    vscode.l10n.t(
      "Container cert sync: skipping ASP.NET dev cert {0} ({1}): {2}.\n  subjectCN={3} version={4} notBefore={5} notAfter={6}",
      meta.thumbprint ?? unknown,
      report.source,
      reason,
      subjectCN,
      version,
      notBefore,
      notAfter
    )
  );
}

/**
 * Drive the full reverse-sync flow: scan for the best container cert,
 * independently re-validate it, send it to the host, and surface the
 * outcome. Returns the result for tests; in production the caller only
 * needs the side effects (notifications, logs).
 */
export async function pushContainerCertToHost(): Promise<
  AcceptContainerCertResult | null
> {
  const scan = await findBestContainerDevCert();
  if (!scan) {
    log(
      "Container cert sync: no valid dev cert found in container; nothing to push."
    );
    return null;
  }

  // Defense-in-depth: independently re-validate before sending. The
  // classifier already enforced isValidDevCert via classifyCandidate, but
  // the issue requires both sides to verify the cert independently and
  // a future change to the scanner shouldn't be able to silently push a
  // non-dev cert.
  if (!isValidDevCert(scan.loaded.cert)) {
    log(
      `Container cert sync: pre-push validation rejected ${scan.loaded.thumbprint}; not sending.`
    );
    return null;
  }

  // Public cert only on the wire. The host's job is to trust the cert,
  // not to act as a server for it — Kestrel keeps using its own copy of
  // the private key inside the container. Not sending the key keeps it
  // off the host's disk and out of the cross-host IPC channel entirely.
  const payload = {
    thumbprint: scan.loaded.thumbprint,
    pemCertBase64: Buffer.from(scan.loaded.cert.pem, "utf-8").toString(
      "base64"
    ),
  };

  log(
    `Container cert sync: pushing ${scan.loaded.thumbprint} to host extension...`
  );

  let result: AcceptContainerCertResult | undefined;
  try {
    result = await vscode.commands.executeCommand<AcceptContainerCertResult>(
      ACCEPT_COMMAND,
      payload
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes(`command '${ACCEPT_COMMAND}' not found`)) {
      log(
        "Container cert sync: host extension doesn't support container cert sync; the syncContainerCert option requires the matching host extension version. Update the host extension or disable syncContainerCert on this container."
      );
      void vscode.window.showWarningMessage(
        vscode.l10n.t(
          "Dev Certs: Container cert sync requires a newer host extension. Update the host extension or set syncContainerCert to false on this container."
        )
      );
      return null;
    }
    log(`Container cert sync: error pushing to host: ${message}`);
    void vscode.window.showErrorMessage(
      vscode.l10n.t(
        "Dev Certs: Failed to push the container dev certificate to the host. Check the Dev Container Dev Certs output for details."
      )
    );
    return null;
  }

  if (!result) {
    log(
      "Container cert sync: host returned no result; treating as decline."
    );
    return null;
  }

  reportAcceptOutcome(result, scan.loaded.thumbprint);
  return result;
}

function reportAcceptOutcome(
  result: AcceptContainerCertResult,
  thumbprint: string
): void {
  if (result.accepted) {
    log(`Container cert sync: host accepted and trusted ${thumbprint}.`);
    void vscode.window.showInformationMessage(
      vscode.l10n.t(
        "Dev Certs: Container development certificate trusted on host."
      )
    );
    return;
  }

  const detail = result.detail ? ` (${result.detail})` : "";
  switch (result.reason) {
    case "host-setting-disabled":
      log(
        `Container cert sync: host rejected ${thumbprint} — host has disabled managed dotnet dev certs (devcontainerDevCerts.generateDotNetCert) or automatic provisioning (devcontainer-dev-certs.autoProvision).`
      );
      // No toast — the user disabled the host setting deliberately.
      return;
    case "user-declined":
      log(
        `Container cert sync: user declined trusting ${thumbprint} on host.`
      );
      return;
    case "parse-failed":
      log(
        `Container cert sync: host could not parse the certificate we sent${detail}.`
      );
      void vscode.window.showWarningMessage(
        vscode.l10n.t(
          "Dev Certs: The host could not parse the container's dev certificate."
        )
      );
      return;
    case "not-valid-dev-cert":
      log(
        `Container cert sync: host rejected ${thumbprint} — failed isValidDevCert (CN, validity, OID, or version)${detail}.`
      );
      void vscode.window.showWarningMessage(
        vscode.l10n.t(
          "Dev Certs: The container's certificate does not look like a valid ASP.NET HTTPS dev cert and was not trusted on the host."
        )
      );
      return;
    case "non-local-sans":
      log(
        `Container cert sync: host rejected ${thumbprint} — certificate has non-local SAN entries${detail}. To override, set devcontainerDevCerts.allowNonLocalContainerCertSans to true in host VS Code settings.`
      );
      void vscode.window.showWarningMessage(
        vscode.l10n.t(
          "Dev Certs: The container's certificate covers non-local addresses ({0}); the host refused to trust it. Override with devcontainerDevCerts.allowNonLocalContainerCertSans in host settings if you really mean to trust it.",
          result.detail ?? ""
        )
      );
      return;
    default:
      log(
        `Container cert sync: host rejected ${thumbprint} for an unknown reason${detail}.`
      );
  }
}
