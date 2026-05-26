# manual-setup

End-to-end example for using `devcontainer-dev-certs` outside of VS Code (JetBrains, Vim, raw CLI, CI).

## What this gives you

The same canonical trust state the VS Code workspace extension produces — `~/.dotnet/corefx/cryptography/x509stores/{my,root}` populated with your dev cert and `~/.aspnet/dev-certs/trust/` populated with hash-symlinked PEMs — without VS Code being involved. Kestrel discovers the cert via its `X509Store` fallback; `curl`, `wget`, and other OpenSSL clients trust it via `SSL_CERT_DIR`.

## Prerequisites

- The `devcontainer-dev-certs` feature in your `devcontainer.json` with `installFallbackTools: true` (or `openssl` and `jq` already present in your base image).
- A directory on the host containing the cert files you want installed, plus a `bundle.json` describing them.

The host-side cert + `bundle.json` can be produced two ways. **The `dcdc` CLI is the simpler path** — one command does generation, host trust, and `bundle.json` emission. The manual path (still documented below) is what you'd reach for when `dcdc` isn't available, when you need a cert from a different source, or when you're sharing a specific cert with the VS Code host extension.

## One-time host setup (with `dcdc`)

`dcdc` is the host-side CLI shipped as [`@devcontainer-dev-certs/cli`](https://www.npmjs.com/package/@devcontainer-dev-certs/cli) on npm:

```bash
npm install -g @devcontainer-dev-certs/cli
```

Node 18 or newer is required. See [`src/cli/README.md`](../../src/cli/README.md) for the full command reference.

Pick a host directory to hold your certs and bundle file (the example below uses `~/.dev-certs`) and generate everything in one shot:

```bash
mkdir -p ~/.dev-certs
dcdc generate --out-dir ~/.dev-certs
```

This:

1. Generates an ASP.NET-compatible dev cert (RSA-2048, the standard `localhost` + `*.dev.localhost` + docker SANs, the ASP.NET dev-cert OID marker so Kestrel finds it).
2. Trusts it on the host (Linux/macOS/Windows — same backend the VS Code host extension uses, or `dotnet dev-certs --trust` on macOS when `dotnet` is on PATH).
3. Writes `aspnetcore-dev.pfx`, `aspnetcore-dev.pem`, `aspnetcore-dev.key`, and `bundle.json` into the out-dir, with `bundle.json` already wired to the container-mount path (`/host-dev-certs` by default).

Skip to "[Project setup](#project-setup)" — no other host steps required.

## One-time host setup (manually)

Pick a host directory to hold your certs and bundle file:

```bash
mkdir -p ~/.dev-certs
```

Generate the ASP.NET dev cert and export both forms:

```bash
dotnet dev-certs https --trust
dotnet dev-certs https --format Pfx --no-password \
    --export-path ~/.dev-certs/aspnetcore-dev.pfx
dotnet dev-certs https --format PEM --no-password \
    --export-path ~/.dev-certs/aspnetcore-dev.pem
```

Compute the SHA-1 fingerprint (this is what `bundle.json` calls `thumbprint`):

```bash
openssl x509 -in ~/.dev-certs/aspnetcore-dev.pem -noout -fingerprint -sha1 \
    | sed 's/^[^=]*=//' | tr -d ':'
```

Drop a copy of [`bundle.json`](./bundle.json) into `~/.dev-certs/` and replace `REPLACE_WITH_SHA1_FINGERPRINT_NO_COLONS` with the fingerprint you just computed.

> **Note on `dotnet dev-certs`-generated certs vs the host extension's certs.** This manual path uses `dotnet dev-certs https` for cert generation. The host extension produces functionally equivalent certs with the same OID marker and SAN entries — either source works against the same fallback installer in the container. If you need to share a *specific* cert with the host extension (e.g. a Windows developer also runs the extension), generate it once and have both flows consume the same PFX.

## Project setup

Copy the bits of [`devcontainer.json`](./devcontainer.json) you want into your own `.devcontainer/devcontainer.json`:

- the `devcontainer-dev-certs` feature reference with `installFallbackTools: true`
- the `mounts` entry that binds your host cert directory to `/host-dev-certs` read-only
- the `postStartCommand` that invokes the fallback installer

The fallback installer is delivered to `/usr/local/bin/devcontainer-dev-certs-install` by the feature.

Use `postStartCommand` (not `postCreateCommand`) so the install re-runs on every container start. That way regenerating the cert on the host (`dcdc generate` again, or the manual `dotnet dev-certs https --clean && …re-export…` ritual) takes effect the next time you start the container — no rebuild required. The `|| true` keeps container startup from blocking if the bundle is missing or malformed.

## Verifying

After the container starts, run:

```bash
devcontainer-dev-certs-install --doctor
```

You should see `[ok]` for every check. If you see `[fail]` or `[warn]`, the message tells you what to fix.

On the host, `dcdc doctor` gives equivalent diagnostics for the host side (which backends are available, whether the cert is in the host platform store and trusted):

```bash
dcdc doctor
```

You can also sanity-check from inside the container:

```bash
# Kestrel-style discovery
ls ~/.dotnet/corefx/cryptography/x509stores/my/

# OpenSSL trust (curl, wget, etc.)
echo "$SSL_CERT_DIR"
ls ~/.aspnet/dev-certs/trust/
```

## Adding more certs

The bundle is a list — add corporate CAs, wildcard certs, etc. as additional entries:

```jsonc
{
    "$schema": "https://raw.githubusercontent.com/dnegstad/devcontainer-dev-certs/main/schema/bundle.schema.json",
    "certs": [
        { "name": "aspnetcore-dev", "kind": "dotnet-dev", ... },
        {
            "name": "corp-ca",
            "thumbprint": "...",
            "pemPath": "/host-dev-certs/corp-ca.pem",
            "trustInContainer": true
        }
    ]
}
```

CA-only entries (no `pfxPath`, no `pemKeyPath`) are valid — they get planted in the trust store but no private key is synced.

`dcdc bundle <cert-path>` emits a single-cert `bundle.json` for an arbitrary cert file (auto-discovers sibling `.pem` / `.key` / `.pfx`, fills in the SHA-1 thumbprint, rewrites paths to the container mount). Merge its output into your existing bundle by hand to add a cert.

See the [bundle schema](../../schema/bundle.schema.json) for the full field reference.

## Limitations

- **Host trust is on you.** This script only handles the *container side*. Trusting the cert on your host so browsers accept forwarded ports requires `dcdc generate` (the example above does this — it runs the host trust step), `dotnet dev-certs https --trust` (the manual path above does this), an OS-specific dance (`security` on macOS, PowerShell on Windows, NSS / OpenSSL on Linux), or running the VS Code host extension once even if you don't use VS Code day-to-day.
- **No `defaultKestrelCertificate` equivalent.** The VS Code-only `defaultKestrelCertificate` setting writes `ASPNETCORE_Kestrel__Certificates__Default__Path/__Password` via VS Code's `EnvironmentVariableCollection`. To pin a custom Kestrel default outside VS Code, set those env vars yourself in `devcontainer.json` `containerEnv`.
- **No reverse sync (container → host).** The `syncContainerCert` flow needs a privileged host-side process to add the cert to the host OS trust store; without the host extension's UI there's nowhere to surface the consent prompt.
