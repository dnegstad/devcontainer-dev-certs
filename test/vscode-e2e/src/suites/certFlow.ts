/**
 * The vertical slice: drive `getAllCertMaterialV3` from the workspace
 * extension to the UI extension inside one real VS Code window, then assert
 * the workspace side actually installed the material on disk.
 *
 * Why a *user* certificate rather than the auto-generated dotnet dev cert:
 * generating the dev cert makes the UI extension put a certificate into the
 * runner's real OS trust store and, on first run, raises a modal consent
 * dialog that nothing in a headless test can dismiss. A user cert
 * (`devcontainerDevCerts.userCertificates`) takes a completely different path
 * on the host — `resolveDotnetProvisioning` short-circuits before any prompt,
 * and user-managed certs are never added to the host trust store — while
 * exercising the identical wire contract and the identical container-side
 * installer. `generateDotNetCert` is set to false for the run so the dev-cert
 * branch is off entirely.
 *
 * Everything the workspace side writes is redirected into a sandbox: `HOME`
 * points at a temp dir (`getDotNetStorePath`, `getDotNetRootStorePath` and
 * `getKestrelDefaultCertPath` are all `os.homedir()`-relative, and Node's
 * `os.homedir()` honors `$HOME` on POSIX) and
 * `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY` redirects the OpenSSL
 * trust dir. Nothing touches the runner's real `~/.aspnet` or `~/.dotnet`.
 */
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import {
  computeSubjectHash,
  getDotNetRootStorePath,
  getDotNetStorePath,
  getPemFileNameForUser,
  getPfxFileName,
  hasHashSymlink,
} from "@devcontainer-dev-certs/shared";
import type { CertBundleV3, CertMaterialV3 } from "@devcontainer-dev-certs/shared";
import { assert, assertEqual, test } from "../runner";
import { sandbox } from "../env";
import { activateBoth } from "./activation";

/**
 * True when `candidate` sits inside `root`. Uses path.relative rather than
 * startsWith so it survives Windows separators and drive-letter casing, and
 * so `/tmp/sandbox-evil` isn't read as being inside `/tmp/sandbox`.
 */
function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/** Strip PEM armor and whitespace, leaving the base64 DER body. */
function pemBody(pem: string): string {
  const begin = pem.indexOf("-----BEGIN CERTIFICATE-----");
  const end = pem.indexOf("-----END CERTIFICATE-----", begin);
  assert(begin >= 0 && end > begin, "input should contain a PEM certificate");
  return pem
    .slice(begin + "-----BEGIN CERTIFICATE-----".length, end)
    .replace(/\s/g, "");
}

export async function fetchBundle(): Promise<CertBundleV3> {
  await activateBoth();
  const bundle = await vscode.commands.executeCommand<CertBundleV3>(
    "devcontainer-dev-certs.getAllCertMaterialV3",
    { includeDotNetDev: false, includeUserCerts: true }
  );
  assert(bundle !== undefined && bundle !== null, "host returned no bundle");
  return bundle;
}

function userCert(bundle: CertBundleV3, name: string): CertMaterialV3 {
  const material = bundle.certs.find((c) => c.name === name);
  assert(
    material !== undefined,
    `bundle should carry the configured user cert '${name}' ` +
      `(got: ${bundle.certs.map((c) => c.name).join(", ") || "nothing"})`
  );
  return material;
}

export function registerCertFlowTests(): void {
  const { home, trustDir, userCertName, userCertPemPath } = sandbox();

  test("host serves the configured user cert over getAllCertMaterialV3", async () => {
    const bundle = await fetchBundle();
    const material = userCert(bundle, userCertName);

    assertEqual(material.kind, "user", "cert kind");
    assertEqual(material.trustInContainer, true, "trustInContainer");
    assert(
      material.pemCertBase64.length > 0,
      "bundle should carry PEM certificate bytes"
    );
    assertEqual(
      pemBody(Buffer.from(material.pemCertBase64, "base64").toString("utf-8")),
      pemBody(fs.readFileSync(userCertPemPath, "utf-8")),
      "the certificate on the wire should be the one configured on the host"
    );
  });

  test("workspace extension installs the material into the sandbox", async () => {
    const bundle = await fetchBundle();
    const material = userCert(bundle, userCertName);

    // Precondition, checked BEFORE anything is written. These three
    // directories are where the install lands, and two of them are derived
    // from os.homedir() — which reads $HOME on POSIX but %USERPROFILE% on
    // Windows. If the redirect ever fails, the install would plant a
    // certificate in the developer's real profile and a check made afterwards
    // would report the damage rather than prevent it.
    for (const [label, dir] of [
      [".NET My store", getDotNetStorePath()],
      [".NET Root store", getDotNetRootStorePath()],
      ["OpenSSL trust dir", trustDir],
    ] as const) {
      assert(
        isInside(home, dir),
        `refusing to run: ${label} resolves to ${dir}, which is outside the ` +
          `sandbox ${home}. The HOME/USERPROFILE redirect did not take effect.`
      );
    }

    // This is the command the activation path calls; auto-inject is turned
    // off for the run so the flow is driven explicitly rather than racing
    // startup.
    await vscode.commands.executeCommand("devcontainer-dev-certs.injectCert");

    // --- PEM is present and is the right certificate ---
    const pemFileName = getPemFileNameForUser(userCertName);
    const pemPath = path.join(trustDir, pemFileName);
    assert(fs.existsSync(pemPath), `${pemPath} should exist after inject`);

    const onDisk = fs.readFileSync(pemPath, "utf-8");
    assertEqual(
      pemBody(onDisk),
      pemBody(fs.readFileSync(userCertPemPath, "utf-8")),
      "installed PEM should be the certificate the host was configured with"
    );

    // --- the hash symlink OpenSSL would actually follow ---
    // Resolved with plain fs rather than only via `hasHashSymlink`, so the
    // assertion doesn't depend on the same helper the installer used. A link
    // under the wrong hash is indistinguishable from an untrusted cert at the
    // point of use, which is exactly the bug class worth catching here.
    const hash = computeSubjectHash(onDisk);
    assert(hash !== null, "subject hash should be computable for the PEM");

    let linked: string | null = null;
    for (let i = 0; i < 16; i++) {
      const candidate = path.join(trustDir, `${hash}.${i}`);
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(candidate);
      } catch {
        break; // real gap — OpenSSL stops walking here too
      }
      if (stat.isSymbolicLink() && fs.readlinkSync(candidate) === pemFileName) {
        linked = candidate;
        break;
      }
    }
    assert(
      linked !== null,
      `no ${hash}.N symlink in ${trustDir} resolves to ${pemFileName}; ` +
        "OpenSSL would not find this certificate via SSL_CERT_DIR"
    );
    assertEqual(
      fs.readFileSync(linked, "utf-8"),
      onDisk,
      "reading through the hash symlink should yield the installed PEM"
    );
    assertEqual(
      hasHashSymlink(trustDir, pemFileName, onDisk),
      true,
      "hasHashSymlink should agree that the cert is reachable"
    );

    // --- .NET Root store got the public-cert-only PFX ---
    const rootPfx = path.join(
      getDotNetRootStorePath(),
      getPfxFileName(material.thumbprint)
    );
    assert(
      fs.existsSync(rootPfx),
      `${rootPfx} should exist — trustInContainer is true, so .NET should ` +
        "consider this certificate trusted inside the container"
    );

    // --- and the My store did NOT, because the cert never opted in ---
    // `installUserCertsToDotNetStore` is false by default; that flag is the
    // one that strips the PFX password, so a regression here would be a
    // security regression rather than a cosmetic one.
    assertEqual(
      material.installToDotNetStore,
      false,
      "user cert should not opt into the .NET My store by default"
    );
    const myPfx = path.join(
      getDotNetStorePath(),
      getPfxFileName(material.thumbprint)
    );
    assertEqual(
      fs.existsSync(myPfx),
      false,
      `${myPfx} should NOT exist — the cert did not opt into the My store`
    );
  });
}
