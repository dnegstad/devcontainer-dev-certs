import type { LinuxNssTrustReporter } from "@devcontainer-dev-certs/shared";

/**
 * Stderr-backed NSS trust reporter for the CLI surfaces. Wire this into
 * any backend call that runs the trust step (`dcdc generate`,
 * `dcdc trust`) so Linux NSS browser-trust failures don't pass silently —
 * the user gets one line that names the trust dir / NSS DB and tells
 * them what to install if `certutil` was missing.
 *
 * No-op on macOS and Windows (the shared layer never calls this on
 * non-Linux platforms; this is a defensive belt-and-suspenders).
 */
export const stderrNssTrustReporter: LinuxNssTrustReporter = (result, pemPath) => {
  if (result.success) {
    process.stderr.write(
      `Linux NSS browser trust: ok (${result.message}; cert at ${pemPath})\n`
    );
    return;
  }
  process.stderr.write(
    `Linux NSS browser trust: WARN (${result.message}; cert at ${pemPath})\n` +
      `       Firefox / Chromium may not trust the cert until this is resolved.\n` +
      `       If certutil is missing, install libnss3-tools (Debian / Ubuntu)\n` +
      `       or nss-tools (Fedora / RHEL) and re-run.\n`
  );
};
