/**
 * Hermetic behavioral test for the devcontainer feature's install.sh,
 * focused on SSL_CERT_DIR management. Unlike validate-feature.mjs (which makes
 * static string assertions about the script), this actually RUNS install.sh
 * under a temporary DEVCERTS_SYSROOT and inspects the files it produces:
 *
 *   - /etc/profile.d/devcontainer-dev-certs.sh  (login shells)
 *   - /etc/environment                          (pam_env)
 *   - /etc/bash.bashrc                          (interactive non-login shells)
 *
 * Run from the repository root: node test/install-sh.test.mjs
 *
 * It exercises the two regressions this script previously had:
 *   1. Absent default CA dirs were never pruned, because the devcontainer CLI
 *      exports SSLCERTDIRS set to the default even when the user didn't set the
 *      option, so the old `-z` guard never fired.
 *   2. `docker exec bash` (interactive non-login) saw no SSL_CERT_DIR because
 *      nothing wrote to the interactive bashrc.
 */
import { execFileSync } from "child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
  existsSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";

const INSTALL_SH = path.resolve(
  "src/devcontainer-feature/src/devcontainer-dev-certs/install.sh"
);

let failures = 0;
function check(label, ok, detail) {
  if (ok) {
    console.log(`  ✓ ${label}`);
  } else {
    console.log(`  ✗ ${label}: ${detail}`);
    failures++;
  }
}

/**
 * Run install.sh in a sandbox.
 *
 * @param {object} opts
 * @param {Record<string,string>} opts.env  feature-option env vars (e.g. SSLCERTDIRS)
 * @param {string[]} opts.presentDirs  absolute CA dirs to create inside the sandbox
 *   so the script's `[ -d ... ]` existence checks see them. Paths are created
 *   under the sysroot AND symlinked-in style is unnecessary because the script
 *   tests the real absolute paths — so we instead point the defaults at dirs we
 *   actually create under the sandbox.
 */
function runInstall({ env = {}, sysrootSeed = () => {} } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), "devcerts-install-"));
  const sysroot = path.join(root, "sysroot");
  const home = path.join(root, "home");
  mkdirSync(path.join(sysroot, "etc"), { recursive: true });
  mkdirSync(home, { recursive: true });
  sysrootSeed({ root, sysroot, home });

  execFileSync("bash", [INSTALL_SH], {
    env: {
      ...process.env,
      DEVCERTS_SYSROOT: sysroot,
      // A user that doesn't exist so the chown block is skipped; home points at
      // a temp dir we own.
      _REMOTE_USER: "devcerts-test-nouser",
      _REMOTE_USER_HOME: home,
      ...env,
    },
    stdio: "pipe",
  });

  const read = (rel) => {
    const p = path.join(sysroot, rel);
    return existsSync(p) ? readFileSync(p, "utf8") : null;
  };
  return {
    root,
    sysroot,
    home,
    profile: read("etc/profile.d/devcontainer-dev-certs.sh"),
    environment: read("etc/environment"),
    bashrc: read("etc/bash.bashrc"),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

// The feature default; some of these exist on a typical CI host, some don't.
const DEFAULT =
  "/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl";

console.log("install.sh: SSL_CERT_DIR management\n");

// --- Pruning runs by default (pruneMissingCertDirs unset => true) -------------
//
// Simulate the real devcontainer-CLI invocation: the user left sslCertDirs at
// its default, so the CLI exports SSLCERTDIRS set to the full default string,
// and pruneMissingCertDirs is unset (defaults true). The pruning must drop
// whichever of those dirs don't exist on this host.
{
  console.log("Pruning on by default (pruneMissingCertDirs unset):");
  const r = runInstall({ env: { SSLCERTDIRS: DEFAULT } });
  try {
    const present = DEFAULT.split(":").filter((d) => existsSync(d));
    const absent = DEFAULT.split(":").filter((d) => !existsSync(d));

    // The profile.d line is `export SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:"'...'`.
    const line =
      (r.profile || "")
        .split("\n")
        .find((l) => l.includes("SSL_CERT_DIR=")) || "";

    check(
      "at least one default dir is absent on this host (otherwise test is vacuous)",
      absent.length > 0,
      "every default CA dir exists here, so pruning can't be observed; test is inconclusive"
    );
    for (const d of absent) {
      check(
        `absent default dir pruned from profile.d: ${d}`,
        !line.includes(d),
        `expected ${d} to be dropped, got line: ${line}`
      );
    }
    for (const d of present) {
      check(
        `present default dir kept in profile.d: ${d}`,
        line.includes(d),
        `expected ${d} to be retained, got line: ${line}`
      );
    }
    // /etc/environment must reflect the same pruned set.
    const envLine =
      (r.environment || "")
        .split("\n")
        .find((l) => l.startsWith("SSL_CERT_DIR=")) || "";
    for (const d of absent) {
      check(
        `absent default dir pruned from /etc/environment: ${d}`,
        !envLine.includes(d),
        `expected ${d} dropped from /etc/environment, got: ${envLine}`
      );
    }
  } finally {
    r.cleanup();
  }
}

// --- Pruning applies to an explicit list too (toggle, not override-inference) -
//
// Unlike the old behavior, an explicit sslCertDirs override is ALSO pruned when
// pruneMissingCertDirs is on (the default) — pruning is a behavior toggle, not
// something inferred from whether the value differs from the default.
{
  console.log("\nPruning applies to an explicit list when the toggle is on:");
  const override = "/etc/ssl/certs:/does/not/exist/anywhere-xyz";
  const r = runInstall({
    env: { SSLCERTDIRS: override, PRUNEMISSINGCERTDIRS: "true" },
  });
  try {
    const line =
      (r.profile || "")
        .split("\n")
        .find((l) => l.includes("SSL_CERT_DIR=")) || "";
    check(
      "non-existent dir in an explicit list is pruned when toggle on",
      !line.includes("/does/not/exist/anywhere-xyz"),
      `expected the absent dir to be dropped; got line: ${line}`
    );
    check(
      "existing dir in the explicit list is kept",
      line.includes("/etc/ssl/certs"),
      `expected /etc/ssl/certs retained; got line: ${line}`
    );
  } finally {
    r.cleanup();
  }
}

// --- pruneMissingCertDirs=false uses the list verbatim ------------------------
{
  console.log("\npruneMissingCertDirs=false keeps the list verbatim:");
  const override = "/etc/ssl/certs:/does/not/exist/anywhere-xyz";
  const r = runInstall({
    env: { SSLCERTDIRS: override, PRUNEMISSINGCERTDIRS: "false" },
  });
  try {
    const line =
      (r.profile || "")
        .split("\n")
        .find((l) => l.includes("SSL_CERT_DIR=")) || "";
    check(
      "non-existent dir is retained when pruneMissingCertDirs=false",
      line.includes("/does/not/exist/anywhere-xyz"),
      `expected verbatim pass-through; got line: ${line}`
    );
  } finally {
    r.cleanup();
  }
}

// --- Bug 2: interactive non-login bridge --------------------------------------
{
  console.log("\nInteractive non-login shell bridge (docker exec bash):");
  const r = runInstall({ env: { SSLCERTDIRS: DEFAULT } });
  try {
    check(
      "/etc/bash.bashrc is written",
      r.bashrc !== null,
      "expected install.sh to create/append /etc/bash.bashrc under the sysroot"
    );
    check(
      "bashrc sources the profile.d script",
      (r.bashrc || "").includes(
        "if [ -r /etc/profile.d/devcontainer-dev-certs.sh ]; then . /etc/profile.d/devcontainer-dev-certs.sh; fi"
      ),
      `expected the bridge line; got:\n${r.bashrc}`
    );

    // Idempotency: a second run (feature reinstall / rebuild) must not duplicate
    // the bridge block.
    execFileSync("bash", [INSTALL_SH], {
      env: {
        ...process.env,
        DEVCERTS_SYSROOT: r.sysroot,
        _REMOTE_USER: "devcerts-test-nouser",
        _REMOTE_USER_HOME: r.home,
        SSLCERTDIRS: DEFAULT,
      },
      stdio: "pipe",
    });
    const bashrc2 = readFileSync(
      path.join(r.sysroot, "etc/bash.bashrc"),
      "utf8"
    );
    const occurrences = bashrc2.split(
      "# devcontainer-dev-certs: cert env for interactive non-login shells"
    ).length - 1;
    check(
      "bridge block is not duplicated on reinstall",
      occurrences === 1,
      `expected exactly 1 bridge marker after a second run, found ${occurrences}`
    );
  } finally {
    r.cleanup();
  }
}

// --- Prefers an existing /etc/bashrc (RPM/SUSE family) ------------------------
{
  console.log("\nPrefers existing /etc/bashrc when present (RPM/SUSE family):");
  const r = runInstall({
    env: { SSLCERTDIRS: DEFAULT },
    sysrootSeed: ({ sysroot }) => {
      // Seed an existing /etc/bashrc (and NO /etc/bash.bashrc) like Fedora/RHEL.
      writeFileSync(path.join(sysroot, "etc", "bashrc"), "# distro bashrc\n");
    },
  });
  try {
    const bashrcRpm = (() => {
      const p = path.join(r.sysroot, "etc/bashrc");
      return existsSync(p) ? readFileSync(p, "utf8") : null;
    })();
    check(
      "appends to existing /etc/bashrc",
      (bashrcRpm || "").includes(
        "# devcontainer-dev-certs: cert env for interactive non-login shells"
      ),
      `expected the bridge appended to /etc/bashrc; got:\n${bashrcRpm}`
    );
    check(
      "does not also create /etc/bash.bashrc when /etc/bashrc exists",
      r.bashrc === null,
      "expected the script to target the existing /etc/bashrc rather than creating /etc/bash.bashrc"
    );
  } finally {
    r.cleanup();
  }
}

// --- Fallback installer honors the sysroot ------------------------------------
//
// The physical `install` destination must be prefixed with DEVCERTS_SYSROOT
// like every other system path — otherwise this very test suite mutates (or
// fails on) the host's real /usr/local/bin. The exported runtime path in
// /etc/environment stays unprefixed: inside a real container the sysroot is
// empty and the two are the same path.
{
  console.log("\nFallback installer delivery under sysroot:");
  const r = runInstall({ env: { SSLCERTDIRS: DEFAULT } });
  try {
    const delivered = path.join(
      r.sysroot,
      "usr/local/bin/devcontainer-dev-certs-install"
    );
    check(
      "installer is delivered under the sysroot",
      existsSync(delivered),
      `expected ${delivered} to exist`
    );
    check(
      "exported INSTALL_BIN path stays unprefixed",
      (r.environment || "").includes(
        'DEVCONTAINER_DEV_CERTS_INSTALL_BIN="/usr/local/bin/devcontainer-dev-certs-install"'
      ),
      `expected the runtime path in /etc/environment to stay /usr/local/bin/...; got:\n${r.environment}`
    );
  } finally {
    r.cleanup();
  }
}

console.log("");
if (failures > 0) {
  console.error(`install.sh tests FAILED: ${failures} check(s) failed.`);
  process.exit(1);
}
console.log("install.sh tests passed.");
