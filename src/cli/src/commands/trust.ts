import * as fs from "fs";
import {
  createPlatformStore,
  loadPfx,
  loadPemPair,
  type DevCert,
} from "@devcontainer-dev-certs/shared";
import { installCliLogger } from "../logger";
import { stderrNssTrustReporter } from "../nssReporter";

export interface TrustCommandOptions {
  verbose?: boolean;
}

/**
 * `dcdc trust <cert-path>` — add an existing cert to the host's OS trust
 * store. Useful when the user already has a cert (generated elsewhere) and
 * just needs the host trust step. Goes through the shared
 * `PlatformCertificateStore.trustCertificate` — same hook the host
 * extension uses, including the Linux NSS browser-trust step (whose
 * outcome is reported on stderr so failures don't pass silently).
 */
export async function runTrust(
  certPath: string,
  options: TrustCommandOptions
): Promise<void> {
  installCliLogger(Boolean(options.verbose));

  if (!fs.existsSync(certPath)) {
    throw new Error(`File not found: ${certPath}`);
  }

  let cert: DevCert;
  const lower = certPath.toLowerCase();
  if (lower.endsWith(".pfx") || lower.endsWith(".p12")) {
    const loaded = await loadPfx(certPath);
    cert = loaded.cert;
  } else {
    const loaded = loadPemPair(certPath);
    cert = loaded.cert;
  }

  const store = await createPlatformStore({
    linuxNssTrustReporter: stderrNssTrustReporter,
  });

  if (await store.isCertTrusted(cert)) {
    process.stderr.write(
      `Certificate ${cert.thumbprintSha1} is already trusted on this host; nothing to do.\n`
    );
    return;
  }

  process.stderr.write(
    `Trusting certificate ${cert.thumbprintSha1} on this host...\n`
  );
  await store.trustCertificate(cert);
  process.stderr.write("Trust step complete.\n");
}
