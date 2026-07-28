# manual-setup

End-to-end example for using `devcontainer-dev-certs` outside of VS Code.

> [!IMPORTANT]
> Usage outside of VS Code is **unsupported**. This example exists as a working reference for a potential future non-VS Code effort, not as a workflow the project stands behind: the pieces it wires together are bare-bones, ship without support commitments, and may change or disappear without notice. The supported experience is the VS Code host + remote extension pair — if you're choosing between this and the extensions, pick the extensions.

## What this gives you

The same canonical trust state the VS Code workspace extension produces — `~/.dotnet/corefx/cryptography/x509stores/{my,root}` populated with your dev cert and `~/.aspnet/dev-certs/trust/` populated with hash-symlinked PEMs — without VS Code being involved. Kestrel discovers the cert via its `X509Store` fallback; `curl`, `wget`, and other OpenSSL clients trust it via `SSL_CERT_DIR`.

What this does **not** give you: automated host-side cert generation, automated OS trust on the host, the reverse-sync flow (`syncContainerCert`), or `defaultKestrelCertificate`. Those all require the VS Code host extension.

## Prerequisites

- The `devcontainer-dev-certs` feature in your `devcontainer.json` with `installFallbackTools: true` (or `openssl` and `jq` already present in your base image).
- A directory on the host containing the cert files you want installed, plus a `bundle.json` describing them.

## One-time host setup

Pick a host directory to hold your certs and bundle file:

```bash
mkdir -p ~/.dev-certs
```

Generate the ASP.NET dev cert and export both forms:

```bash
dotnet dev-certs https --trust
dotnet dev-certs https --format PEM --no-password \
    --export-path ~/.dev-certs/aspnetcore-dev.pem
dotnet dev-certs https --export-path ~/.dev-certs/aspnetcore-dev.pfx --password ""
```

The PEM export writes the private key alongside as `aspnetcore-dev.key` (older SDKs used `aspnetcore-dev.pem.key` — rename it if yours does). Two PFX flag traps to avoid: `--format Pfx --no-password` is rejected as an incompatible flag combination, and a bare `--export-path x.pfx` *without* `--password ""` silently exports only the public certificate (DER, no private key) despite the `.pfx` extension — Kestrel can't serve TLS from that. The explicit `--password ""` form above produces a real passwordless PKCS#12 with the key included.

Compute the SHA-1 fingerprint (this is what `bundle.json` calls `thumbprint`):

```bash
openssl x509 -in ~/.dev-certs/aspnetcore-dev.pem -noout -fingerprint -sha1 \
    | sed 's/^[^=]*=//' | tr -d ':'
```

Drop a copy of [`bundle.json`](./bundle.json) into `~/.dev-certs/` and replace `REPLACE_WITH_SHA1_FINGERPRINT_NO_COLONS` with the fingerprint you just computed.

> **Note on `dotnet dev-certs`-generated certs vs the host extension's certs.** This path uses `dotnet dev-certs https` for cert generation. The VS Code host extension produces functionally equivalent certs with the same OID marker and SAN entries — either source works against the same fallback installer in the container. If you need to share a *specific* cert with the host extension (e.g. a Windows developer also runs the extension), generate it once and have both flows consume the same PFX.

## Project setup

Copy the bits of [`devcontainer.json`](./devcontainer.json) you want into your own `.devcontainer/devcontainer.json`:

- the `devcontainer-dev-certs` feature reference with `installFallbackTools: true`
- the `mounts` entry that binds your host cert directory to `/host-dev-certs` read-only
- the `postStartCommand` that invokes the fallback installer

The fallback installer is delivered to `/usr/local/bin/devcontainer-dev-certs-install` by the feature.

Use `postStartCommand` (not `postCreateCommand`) so the install re-runs on every container start. That way regenerating the cert on the host (`dotnet dev-certs https --clean && …re-export…`) takes effect the next time you start the container — no rebuild required. The `|| true` keeps container startup from blocking if the bundle is missing or malformed.

## Verifying

After the container starts, run:

```bash
devcontainer-dev-certs-install --doctor
```

You should see `[ok]` for every check. If you see `[fail]` or `[warn]`, the message tells you what to fix.

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

See the [bundle schema](../../schema/bundle.schema.json) for the full field reference.

## Limitations

- **Host trust is on you.** This script only handles the *container side*. Trusting the cert on your host so browsers accept forwarded ports requires `dotnet dev-certs https --trust`, an OS-specific dance (`security` on macOS, PowerShell on Windows, NSS / OpenSSL on Linux), or running the VS Code host extension once even if you don't use VS Code day-to-day.
- **No `defaultKestrelCertificate` equivalent.** The VS Code-only `defaultKestrelCertificate` setting writes `ASPNETCORE_Kestrel__Certificates__Default__Path/__Password` via VS Code's `EnvironmentVariableCollection`. To pin a custom Kestrel default outside VS Code, set those env vars yourself in `devcontainer.json` `containerEnv`.
- **No reverse sync (container → host).** The `syncContainerCert` flow needs a privileged host-side process to add the cert to the host OS trust store; without the host extension's UI there's nowhere to surface the consent prompt.
