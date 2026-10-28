#!/usr/bin/env node
/**
 * Launcher for the devcontainer level of the VS Code E2E suite.
 *
 * Where `runTests.mjs` loads both extensions into ONE local window and opens
 * the workspace extension's remote gate with a test-only seam, this one gives
 * the workspace extension a real remote:
 *
 *   1. Stage a workspace under .out/devcontainer-e2e/ whose devcontainer.json
 *      uses the feature from THIS checkout, plus the built workspace
 *      extension, the remote suite bundle and the expected-cert fixture.
 *   2. `devcontainer up` it with the open-source Dev Containers CLI, so the
 *      feature's install.sh runs for real.
 *   3. Download a desktop VS Code and the VS Code server for the SAME commit,
 *      and start the server inside the container with `devcontainer exec`,
 *      which applies the same userEnvProbe the Dev Containers extension does.
 *   4. Launch desktop VS Code on `vscode-remote://devcerts-e2e+e2e/...`. A
 *      tiny test-only resolver extension (test/vscode-e2e/resolver/) answers
 *      that authority with the server's published port. The UI extension and
 *      the resolver load locally; the workspace extension and the suite load
 *      from the container via vscode-remote:// development/test paths.
 *
 * Nothing here uses the Dev Containers extension: it is closed-source, can't
 * be driven headlessly in a supported way, and would install the marketplace
 * builds the feature names in customizations.vscode.extensions over the
 * checkout under test.
 *
 * Usage (from the repo root, Linux + Docker):
 *   npm run build -w src/vscode-ui-extension
 *   npm run build -w src/vscode-workspace-extension
 *   npm run build:e2e
 *   npm run test:e2e:devcontainer -- --container-only   # no VS Code download
 *   xvfb-run -a npm run test:e2e:devcontainer
 *
 * `--container-only` stops after step 2 plus an environment probe. It needs
 * Docker but no VS Code, so it is the cheap check for "does the feature build
 * and does its environment reach a devcontainer exec'd process".
 *
 * The container is removed on success and left running on failure, with its
 * id printed, so it can be inspected with `docker exec`.
 */
import { downloadAndUnzipVSCode, runTests } from "@vscode/test-electron";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import {
  FIXTURE_PEM,
  USER_CERT_NAME,
  buildSandbox,
  ensureFixture,
  here,
  repoRoot,
  requireBuilt,
} from "./launcherCommon.mjs";

const AUTHORITY = "devcerts-e2e";
const RESOLVER_ID = "dnegstad.devcerts-e2e-resolver";
const SERVER_PORT = 8123;
const STAGE = join(repoRoot, ".out", "devcontainer-e2e");
const containerOnly = process.argv.includes("--container-only");

const require = createRequire(import.meta.url);
const devcontainerCli = join(
  dirname(require.resolve("@devcontainers/cli/package.json")),
  "devcontainer.js"
);

/** `devcontainer <subcommand> --workspace-folder STAGE ...rest`; options must precede an exec'd command. */
function devcontainer(subcommand, rest = []) {
  const result = spawnSync(
    process.execPath,
    [devcontainerCli, subcommand, "--workspace-folder", STAGE, ...rest],
    { cwd: repoRoot, encoding: "utf-8" }
  );
  if (result.status !== 0) {
    throw new Error(
      `devcontainer ${subcommand} failed (exit ${result.status})\n${result.stderr ?? ""}`
    );
  }
  return result.stdout ?? "";
}

/** `devcontainer up` prints log lines, then one JSON result line. */
function lastJsonLine(stdout) {
  const line = stdout.trim().split("\n").reverse().find((l) => l.startsWith("{"));
  if (!line) throw new Error(`no JSON result from devcontainer up:\n${stdout}`);
  return JSON.parse(line);
}

function stage(workspaceExtension) {
  rmSync(STAGE, { recursive: true, force: true });
  cpSync(join(here, "devcontainer"), STAGE, { recursive: true });
  cpSync(
    join(repoRoot, "src", "devcontainer-feature", "src", "devcontainer-dev-certs"),
    join(STAGE, ".devcontainer", "devcontainer-dev-certs"),
    { recursive: true }
  );

  // Everything the container needs from the host goes under .e2e/, inside the
  // workspace folder the CLI bind-mounts. No docker cp.
  const e2e = join(STAGE, ".e2e");
  const remoteExt = join(e2e, "ext-remote");
  mkdirSync(remoteExt, { recursive: true });
  for (const entry of ["package.json", "package.nls.json", "dist", "l10n"]) {
    const from = join(workspaceExtension, entry);
    if (existsSync(from)) cpSync(from, join(remoteExt, entry), { recursive: true });
  }
  for (const file of ["remote-suite.cjs", "remote-suite.cjs.map"]) {
    cpSync(join(repoRoot, ".out", "vscode-e2e", file), join(e2e, file));
  }
  cpSync(FIXTURE_PEM, join(e2e, "expected.pem"));
  return e2e;
}

/** Proves the feature's env sinks reach a process started the way the server will be. */
function probeEnvironment() {
  const out = devcontainer("exec", [
    "sh",
    "-c",
    'printf "%s\\n%s\\n" "$HOME" "$SSL_CERT_DIR"',
  ]);
  const [home, sslCertDir] = out.trim().split("\n");
  const trustDir = `${home}/.aspnet/dev-certs/trust`;
  if (!(sslCertDir ?? "").split(":").includes(trustDir)) {
    throw new Error(
      `SSL_CERT_DIR in the container does not include ${trustDir} (got '${sslCertDir}'). ` +
        "The feature's environment sinks are not reaching devcontainer exec."
    );
  }
  console.log(`Container env OK: SSL_CERT_DIR=${sslCertDir}`);
}

function containerArch() {
  const machine = devcontainer("exec", ["uname", "-m"]).trim();
  if (machine === "x86_64") return "x64";
  if (machine === "aarch64") return "arm64";
  throw new Error(`unsupported container architecture: ${machine}`);
}

function productCommit(productJson) {
  return JSON.parse(readFileSync(productJson, "utf-8")).commit;
}

/**
 * Desktop and server must be the same commit or the server refuses the
 * connection. Resolve "stable" to a concrete version once and download both
 * by that version, then check the commits rather than trusting the naming.
 */
async function downloadMatchingBuilds(arch) {
  const version = process.env.DEVCERTS_E2E_VSCODE_VERSION ?? "stable";
  const desktopExe = await downloadAndUnzipVSCode({ version });
  const desktopRoot = findUp(desktopExe, "resources");
  const desktopProduct = join(desktopRoot, "resources", "app", "product.json");
  const desktopVersion = JSON.parse(
    readFileSync(join(desktopRoot, "resources", "app", "package.json"), "utf-8")
  ).version;

  const serverBin = await downloadAndUnzipVSCode({
    version: desktopVersion,
    platform: `server-linux-${arch}`,
  });
  const serverRoot = dirname(dirname(serverBin));
  const desktopCommit = productCommit(desktopProduct);
  const serverCommit = productCommit(join(serverRoot, "product.json"));
  if (desktopCommit !== serverCommit) {
    throw new Error(
      `VS Code desktop (${desktopCommit}) and server (${serverCommit}) commits differ`
    );
  }
  console.log(`VS Code ${desktopVersion} (${desktopCommit})`);
  return { desktopExe, serverRoot };
}

function findUp(start, marker) {
  let dir = dirname(start);
  while (dir !== dirname(dir)) {
    if (existsSync(join(dir, marker))) return dir;
    dir = dirname(dir);
  }
  throw new Error(`could not find '${marker}' above ${start}`);
}

/**
 * Starts the server in the container and resolves once it is listening.
 * Runs through `devcontainer exec` so the server inherits the probed user
 * environment, exactly as a server the Dev Containers extension starts would.
 */
function startServer({ remoteE2e, token }) {
  const child = spawn(
    process.execPath,
    [
      devcontainerCli,
      "exec",
      "--workspace-folder",
      STAGE,
      "--remote-env",
      `DEVCERTS_E2E_USER_CERT_NAME=${USER_CERT_NAME}`,
      "--remote-env",
      `DEVCERTS_E2E_EXPECTED_PEM=${remoteE2e}/expected.pem`,
      `${remoteE2e}/server/bin/code-server`,
      "--host",
      "0.0.0.0",
      "--port",
      String(SERVER_PORT),
      "--connection-token",
      token,
      "--accept-server-license-terms",
      "--telemetry-level",
      "off",
      "--server-data-dir",
      "/tmp/devcerts-e2e-server",
    ],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] }
  );

  return new Promise((resolvePromise, reject) => {
    // On timeout the caller never receives `child`, so its finally can't kill
    // it; a live child and open pipes would keep Node running until CI's job
    // limit. Kill it and drop the pipes here before rejecting.
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      child.stdout.destroy();
      child.stderr.destroy();
      reject(new Error("VS Code server did not start listening within 60s"));
    }, 60_000);
    const onData = (chunk) => {
      const text = chunk.toString();
      process.stdout.write(`[server] ${text}`);
      if (text.includes(`listening on ${SERVER_PORT}`)) {
        clearTimeout(timer);
        resolvePromise(child);
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`VS Code server exited early (code ${code})`));
    });
  });
}

function publishedPort(containerId) {
  const out = spawnSync("docker", ["port", containerId, `${SERVER_PORT}/tcp`], {
    encoding: "utf-8",
  });
  const first = (out.stdout ?? "").trim().split("\n")[0] ?? "";
  const match = /^(.+):(\d+)$/.exec(first);
  if (out.status !== 0 || !match) {
    throw new Error(`could not read the published port for ${SERVER_PORT}: ${out.stderr}`);
  }
  return { host: match[1], port: match[2] };
}

async function main() {
  ensureFixture();

  const uiExtension = resolve(repoRoot, "src", "vscode-ui-extension");
  const workspaceExtension = resolve(repoRoot, "src", "vscode-workspace-extension");
  requireBuilt("UI extension bundle", join(uiExtension, "dist", "extension.js"));
  requireBuilt("workspace extension bundle", join(workspaceExtension, "dist", "extension.js"));
  requireBuilt(
    "remote suite bundle",
    resolve(repoRoot, ".out", "vscode-e2e", "remote-suite.cjs")
  );

  const localE2e = stage(workspaceExtension);

  console.log("Building and starting the dev container...");
  const up = lastJsonLine(devcontainer("up", ["--remove-existing-container"]));
  if (up.outcome !== "success") throw new Error(`devcontainer up: ${JSON.stringify(up)}`);
  const { containerId, remoteWorkspaceFolder } = up;
  console.log(`Container: ${containerId} (workspace ${remoteWorkspaceFolder})`);

  let exitCode = 0;
  try {
    probeEnvironment();
    if (containerOnly) {
      console.log("--container-only: skipping the VS Code run.");
    } else {
      await runVsCode({ containerId, remoteWorkspaceFolder, localE2e, uiExtension });
    }
  } catch (err) {
    exitCode = 1;
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
  }

  if (exitCode === 0) {
    spawnSync("docker", ["rm", "-f", containerId], { stdio: "ignore" });
  } else {
    console.error(`Container left running for inspection: ${containerId}`);
  }
  process.exitCode = exitCode;
}

async function runVsCode({ containerId, remoteWorkspaceFolder, localE2e, uiExtension }) {
  let server;
  const sandbox = buildSandbox();
  let ok = false;
  try {
    const { desktopExe, serverRoot } = await downloadMatchingBuilds(containerArch());
    cpSync(serverRoot, join(localE2e, "server"), { recursive: true });

    const remoteE2e = `${remoteWorkspaceFolder}/.e2e`;
    const token = randomBytes(16).toString("hex");
    server = await startServer({ remoteE2e, token });
    const { host, port } = publishedPort(containerId);

    const remote = (p) => `vscode-remote://${AUTHORITY}+e2e${p}`;
    await runTests({
      vscodeExecutablePath: desktopExe,
      extensionDevelopmentPath: [
        uiExtension,
        join(here, "resolver"),
        remote(`${remoteE2e}/ext-remote`),
      ],
      extensionTestsPath: remote(`${remoteE2e}/remote-suite.cjs`),
      launchArgs: [
        `--folder-uri=${remote(remoteWorkspaceFolder)}`,
        `--enable-proposed-api=${RESOLVER_ID}`,
        "--user-data-dir",
        sandbox.userDataDir,
        "--extensions-dir",
        sandbox.extensionsDir,
        "--disable-extensions",
        "--disable-gpu",
      ],
      extensionTestsEnv: {
        // Host side only. The UI extension writes nothing for a user cert, but
        // keep its os.homedir() in a sandbox anyway, as runTests.mjs does.
        HOME: sandbox.home,
        USERPROFILE: sandbox.home,
        DEVCERTS_E2E_SERVER_HOST: host,
        DEVCERTS_E2E_SERVER_PORT: port,
        DEVCERTS_E2E_SERVER_TOKEN: token,
      },
    });
    ok = true;
  } finally {
    server?.kill();
    if (ok) rmSync(sandbox.root, { recursive: true, force: true });
    else console.error(`Host sandbox left in place: ${sandbox.root}`);
  }
}

await main();
