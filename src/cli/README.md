# ddc

`ddc` is the host-side CLI for [devcontainer-dev-certs](https://github.com/dnegstad/devcontainer-dev-certs). It generates ASP.NET-compatible HTTPS development certificates, trusts them on the host, inspects existing cert files, and emits the `bundle.json` the in-container installer reads — without VS Code being involved.

## Why this exists

The host extension automates everything when you use VS Code. Outside of VS Code (JetBrains, Vim, raw CLI, CI), the canonical path to the same trust state is:

1. Generate a cert.
2. Trust it on the host OS.
3. Hand-write a `bundle.json` referencing the cert files inside the container's bind-mount.
4. Hand-compute the SHA-1 thumbprint and paste it into the bundle.

`ddc generate` is one command that does all four. The other commands (`inspect`, `bundle`, `trust`, `doctor`) cover the rest of the lifecycle.

`ddc` uses the same shared cert + platform code the VS Code host extension uses — same trust paths, same SAN list, same OID marker — so a cert produced by `ddc` is interchangeable with one produced by the extension.

## Install

There is no published binary yet. To use `ddc` today, build it from this repository:

```bash
git clone https://github.com/dnegstad/devcontainer-dev-certs.git
cd devcontainer-dev-certs
npm install
cd src/cli && node esbuild.mjs
```

That produces `dist/ddc.js`, an executable Node script. Invoke it directly:

```bash
node dist/ddc.js --help
```

Or symlink it onto your PATH:

```bash
chmod +x dist/ddc.js
ln -s "$(pwd)/dist/ddc.js" ~/.local/bin/ddc
ddc --help
```

Node 18 or newer is required.

## Quick start

```bash
mkdir -p ~/.dev-certs
ddc generate --out-dir ~/.dev-certs
```

That produces in `~/.dev-certs`:

- `aspnetcore-dev.pfx` — cert + private key in PKCS#12, passwordless
- `aspnetcore-dev.pem` — cert in PEM
- `aspnetcore-dev.key` — private key in PEM
- `bundle.json` — manifest the in-container installer reads, with paths rewritten to the container's bind-mount target (`/host-dev-certs` by default)

The cert is also added to your host OS trust store (Linux NSS DB / macOS keychain / Windows cert store) so browsers accept forwarded ports.

Bind-mount the directory into the container and have the in-container installer consume the bundle — see [`examples/manual-setup/`](../../examples/manual-setup/) for the full devcontainer.json.

## Commands

### `ddc generate`

Generate a dev cert, trust it on the host, and emit `bundle.json`.

```
ddc generate [--out-dir <path>] [--backend auto|native|dotnet]
             [--no-trust] [--container-mount <path>] [--no-bundle] [--verbose]
```

| Flag | Default | Notes |
|------|---------|-------|
| `--out-dir <path>` | `~/.dev-certs` | Directory to write artifacts to. |
| `--backend <mode>` | `auto` | Cert generator backend. `auto` prefers `dotnet` on macOS when the `dotnet` CLI is on PATH (better keychain-trust UX via a signed binary); `native` everywhere else. |
| `--no-trust` | off | Skip the host OS trust step. PFX / PEM / `bundle.json` are still emitted. |
| `--container-mount <path>` | `/host-dev-certs` | Container-side mount target the out-dir bind-mounts to. Recorded into `bundle.json` so the in-container installer reads from the right path. |
| `--no-bundle` | off | Skip emitting `bundle.json`. |
| `--verbose` | off | Stream shared-layer log lines to stderr. |

### `ddc inspect <cert-path>`

Print details about a PFX or PEM certificate.

```
ddc inspect path/to/aspnetcore-dev.pfx
```

Reports the subject CN, both SHA-1 and SHA-256 thumbprints, validity window, ASP.NET dev-cert OID and version byte (so you can tell whether the cert is fresh enough for the current installer), every SAN entry (with `[non-local]` flags on any that aren't on the standard developer-cert allowlist), and warnings (cert without key, expiring soon, non-local SANs present).

Pass `--json` for machine-readable output:

```
ddc inspect --json path/to/cert.pfx
```

### `ddc bundle <cert-path>`

Emit a single-cert `bundle.json` referencing an already-existing cert file. Auto-discovers sibling `.pem` / `.key` / `.pfx` files by naming convention so a single PFX argument is usually enough.

```
ddc bundle path/to/cert.pfx [--out-dir <path>] [--container-mount <path>]
                            [--name <stem>] [--kind dotnet-dev|user]
                            [--no-trust-in-container]
```

| Flag | Default | Notes |
|------|---------|-------|
| `--out-dir <path>` | directory of cert-path | Where to write `bundle.json`. |
| `--container-mount <path>` | `/host-dev-certs` | Container-side mount target. |
| `--name <stem>` | basename of cert-path | Filename stem used in the bundle (`{name}.pem`, etc.). |
| `--kind <kind>` | `user` | `dotnet-dev` uses the historic `aspnetcore-localhost-{thumbprint}.pem` filename in the OpenSSL trust dir; `user` uses `{name}.pem`. |
| `--no-trust-in-container` | trust-in-container is on by default | Mark the entry as `trustInContainer: false` — cert is served only, not added to trust stores inside the container. |

Useful for wrapping a cert produced by something else (a corporate CA, a manual `dotnet dev-certs` invocation, a wildcard cert generated by another tool) into the bundle format the in-container installer expects.

If any cert file referenced by the bundle lives outside `--out-dir`, `ddc bundle` emits a stderr warning. The writer only rewrites paths under `--out-dir` to the container-mount target; paths outside are left verbatim, which means the in-container installer will try to read them at their host-filesystem location — something it can only do if you've also bind-mounted that location. Either copy the cert files into `--out-dir` and re-run, or arrange additional mounts so the referenced paths exist container-side.

### `ddc trust <cert-path>`

Add an existing cert to the host OS trust store via the same shared platform layer the VS Code host extension uses.

```
ddc trust path/to/cert.pfx
```

Short-circuits with an "already trusted" message when the cert is already in the trust store — repeated invocations don't re-prompt.

### `ddc doctor`

Read-only diagnostics: which backends are available, what `--backend auto` would pick, host platform-store state, and per-OS tool presence.

```
ddc doctor [--out-dir <path>]
```

Per-OS tool checks:

- **Linux**: `openssl` (native trust step) and `certutil` (NSS browser-trust step; missing means Firefox / Chromium won't auto-trust).
- **macOS**: `security` (the keychain CLI the native backend drives).
- **Windows**: `pwsh` *or* `powershell` (Windows store enumeration; PowerShell 7+ preferred, 5.1 accepted as fallback) and `certutil.exe` (Windows trust store).

Exits non-zero if any check reports `[fail]`. `[warn]` is informational and exits zero.

## Bundle JSON

The `bundle.json` written by `ddc generate` and `ddc bundle` conforms to the schema at [`schema/bundle.schema.json`](../../schema/bundle.schema.json) and is the same format the in-container `devcontainer-dev-certs-install --bundle-json` installer accepts.

For multi-cert setups (auto-generated dev cert + corporate CA + extra wildcard), the simplest workflow is `ddc generate` to seed the bundle and then hand-edit additional entries in. The bundle is a list — see the [root README](../../README.md#manual--non-vs-code-use) for the field reference.

## Backends

Two backends today; both produce certs the in-container installer accepts.

- **`native`** uses the bundled cert primitives (the same Node + `@peculiar/x509` + `pkijs` code path the VS Code host extension uses). No external runtime dependencies. Works on every platform.
- **`dotnet`** shells out to `dotnet dev-certs https`. Requires the dotnet SDK on PATH. On macOS this gives a more polished keychain trust prompt (the calling binary is Apple-notarized); on Windows / Linux it's functionally equivalent to native.

`--backend auto` (the default) picks dotnet on macOS when available, native everywhere else. The VS Code host extension has the same selection logic, controlled by the `devcontainerDevCerts.hostCertGenerator` setting.

On Windows, the dotnet backend (and any other shell-out in this tool) resolves its command through PATH before spawning, so a malicious binary planted in the working directory can't hijack the lookup.

## `--no-trust` semantics

The two backends honor `--no-trust` differently:

- **`--backend native --no-trust`** generates the cert purely in memory and writes only to `--out-dir`. The host's `.NET` X509 store and OS trust store are not touched. This is the right choice for "give me cert files to bind-mount into a container, don't install anything on my host."
- **`--backend dotnet --no-trust`** skips the OS trust prompt, but `dotnet dev-certs https` still persists the cert into the `.NET` X509 store as a side effect — that's how `dotnet dev-certs` itself works, regardless of `--trust`. If you want strict file-only output, use the native backend.

Without `--no-trust`, both backends write to the `.NET` X509 store and trust the cert in the OS — that's the host-trust contract (it's where `dotnet dev-certs --check`, host-running Kestrel, and the VS Code host extension all look for the cert).

## Limitations

- **No published binary yet.** Build from source as described above.
- **No reverse sync.** The VS Code workspace extension's `syncContainerCert` flow (pushing a container-side cert back to the host) needs the host extension's consent UI; there's no equivalent in the CLI.
