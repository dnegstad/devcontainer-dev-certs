# Devcontainer Dev Certificates

Automatic HTTPS development certificate management for .NET or Aspire projects in devcontainers and VS Code remote environments.

## What This Does

When developing .NET applications or Aspire orchestration projects inside devcontainers, you need HTTPS certificates that are trusted on both sides: the host (so browsers accept forwarded ports) and the container (so servers can terminate HTTPS and allow inter-service calls work). This project automates the entire process.

Add the devcontainer feature to your `devcontainer.json` and everything works automatically:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {}
    }
}
```

No `dotnet dev-certs` commands, no manual PFX exports, no environment variable configuration.

## Getting Started

### Prerequisites

- VS Code 1.100 or later
- The [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
- Docker or a compatible container runtime

### Add the Feature

Add the dev container feature to your project's `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {}
    }
}
```

Then rebuild or reopen your project in the dev container. The feature declares both companion extensions, so VS Code installs the remote extension inside the container automatically. The host extension is installed on your local VS Code automatically as well; if it isn't, the remote extension prompts you with an **Install Host Extension** button on first use.

On first use:

1. The host extension shows a one-time consent prompt, then generates a development certificate and trusts it in your OS certificate store. On Windows this triggers a system dialog; on macOS the keychain may prompt for a password.
2. The remote extension receives the certificate and installs it in the container's .NET X509 store and OpenSSL trust directory.
3. ASP.NET, Aspire, and CLI tools like `curl` and `wget` trust the certificate automatically — no environment variables or manual configuration needed.
4. Your host browser trusts the certificate on forwarded ports.

### Installing the Host Extension Manually (Optional)

You normally don't need to do this — the feature handles it. If you'd rather install the host extension (`dnegstad.devcontainer-dev-certs-host`) ahead of time:

- **VS Code Marketplace:** [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host)
- **Extensions view:** search for `dnegstad.devcontainer-dev-certs-host`
- **CLI:** `code --install-extension dnegstad.devcontainer-dev-certs-host`

The remote extension (`dnegstad.devcontainer-dev-certs-remote`) runs inside the container and is installed by the feature. Don't install it on your local VS Code — it has no effect there.

## Verifying Release Provenance

Starting with **v1.0.0**, each release publishes [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestations that bind the artifact back to the GitHub Actions workflow run that produced it. Attestations are minted from short-lived OpenID Connect tokens — no long-lived publishing credentials are stored in the repository — and the publishing workflow runs in a protected `release` environment scoped to release tags. Earlier (`0.x`) releases predate this pipeline and are not attested.

You can verify any release artifact with the [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify) command:

- **Devcontainer feature.** The provenance attestation is pushed to GHCR alongside the OCI artifact:
  ```bash
  gh attestation verify \
      oci://ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:<version> \
      --repo dnegstad/devcontainer-dev-certs
  ```
- **Extension VSIXes.** Both `dnegstad.devcontainer-dev-certs-host` and `dnegstad.devcontainer-dev-certs-remote` VSIXes are attached as assets to each [GitHub Release](https://github.com/dnegstad/devcontainer-dev-certs/releases) with attestations stored on GitHub:
  ```bash
  gh attestation verify <path-to>.vsix --repo dnegstad/devcontainer-dev-certs
  ```

Verification confirms that the artifact was built from this repository, on the workflow run referenced in the attestation, and has not been modified since.

## How It Works

The solution has three components that work together:

1. **Devcontainer Feature** sets up the container's trust infrastructure: creates the .NET X509 store and OpenSSL trust directories, configures `SSL_CERT_DIR`, and requests installation of the two companion VS Code extensions.

2. **Host Extension** (`extensionKind: ["ui"]`) runs on your local machine. It generates certificates identical to `dotnet dev-certs https` (same OID marker, same SAN entries, same key parameters) using Node's built-in `crypto` plus `@peculiar/x509` and `pkijs` for X.509 / PKCS#12 — supporting RSA, ECDSA, and Ed25519 keys. On first use, it generates a cert and trusts it in the host OS certificate store. It then serves the certificate material to the remote side via VS Code's cross-host command routing.

3. **Remote Extension** (`extensionKind: ["workspace"]`) runs inside the container. On activation, it requests certificate material from the host extension, decodes it, and places it in two locations:
   - The .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) where Kestrel discovers it automatically via its `GetDevelopmentCertificateFromStore()` fallback
   - An OpenSSL trust directory (`~/.aspnet/dev-certs/trust/`) with hash symlinks (c_rehash, implemented in pure TypeScript) so `curl`, `wget`, and other OpenSSL-based tools trust it

The two extensions communicate using VS Code's cross-host `executeCommand()` routing. The remote extension detects whether the host extension is installed and prompts to install it if missing. This architecture is transport-agnostic — it works for devcontainers today and can support SSH remoting, WSL, or any future VS Code remote backend.

## Repository Layout

```
src/
  vscode-ui-extension/             VS Code host extension (extensionKind: ui)
    src/
      cert/                        Certificate generation, export, and management
        generator.ts               X.509 certificate generation (matches ASP.NET CertificateManager)
        properties.ts              OID constants, SAN entries, key parameters
        exporter.ts                PFX and PEM export
        manager.ts                 Orchestrates generate/trust/export/check
      platform/                    OS-specific cert store implementations
        windowsStore.ts            Windows cert store via PowerShell
        macStore.ts                macOS keychain via security CLI
        linuxStore.ts              Linux X509Store + OpenSSL trust directory
      certProvider.ts              Serves cert material to the workspace extension

  vscode-workspace-extension/      VS Code remote extension (extensionKind: workspace)
    src/
      certInstaller.ts             Writes cert files to correct paths
      util/rehash.ts               Pure TypeScript c_rehash (OpenSSL subject hash computation)
      util/sslCertDir.ts           SSL_CERT_DIR management for non-devcontainer remotes
      util/paths.ts                .NET store and OpenSSL trust directory paths

  devcontainer-feature/            Devcontainer feature
    src/devcontainer-dev-certs/
      devcontainer-feature.json    Feature metadata, options, extension references
      install.sh                   Container build-time setup (creates directories)

test/
  sample-project/                  Test project template (hydrated into .out/ for testing)
  hydrate.mjs                      Assembles a runnable test project from the template + feature

.github/workflows/                 CI/CD (build, extension packaging, feature publishing)
```

## Feature Options

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {
            "trustNss": true
        }
    }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `trustNss` | `false` | Install NSS tools for Chromium/Firefox trust inside the container |
| `sslCertDirs` | Standard distro paths | System CA directories for `SSL_CERT_DIR`. Override for non-standard base images. |
| `generateDotNetCert` | `true` | Auto-generate the ASP.NET / Aspire compatible HTTPS dev cert. Set to `false` to skip generation (useful when you only want to sync user-managed certs). |
| `syncUserCertificates` | `true` | Per-container opt-out for syncing certs configured in the host `devcontainerDevCerts.userCertificates` VS Code setting. |
| `extraCertDestinations` | `""` | Comma-separated list of additional directories to write cert artifacts to. Each entry is `<abs-dir>[=<format>]` where `format` is `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). Every synced cert is written under the directory as `{name}.{pem,key,pfx}` (and/or `{name}-bundle.pem`). Example: `/etc/nginx/certs=pem,/var/myapp`. |

## User-managed certificates

The host extension can sync arbitrary host-side certificates into your dev containers alongside (or instead of) the auto-generated dev cert. Configure them in your user or workspace VS Code settings:

```json
{
    "devcontainerDevCerts.userCertificates": [
        {
            "name": "corp-ca",
            "pemCertPath": "/Users/me/certs/corp-ca.pem"
        },
        {
            "name": "staging",
            "pfxPath": "/Users/me/certs/staging.pfx",
            "pfxPassword": "hunter2",
            "trustInContainer": true
        }
    ]
}
```

Each entry supplies exactly one of `pfxPath` (+ optional `pfxPassword`) or `pemCertPath` (+ optional `pemKeyPath`). Omitting the key produces a CA-only entry — the cert is still planted in the container trust store, but no private key is synced and no PFX is written to the .NET store. Expired certificates are synced anyway but produce a one-time warning notification so you know why TLS clients are rejecting them.

`name` is used verbatim as a filename stem both on the host (temp export directory) and inside the container (trust PEM and extra-destination files), so it's constrained to `[A-Za-z0-9._-]` (1–64 chars, no leading dot, no `.` / `..`). Entries with an invalid name are rejected with an error notification and skipped.

User-managed certs are **never** added to the host OS trust store; the assumption is you already trust them on the host if you're syncing them.

### Password handling

The user's PFX password is preserved end-to-end. For `pfxPath` sources, the original file bytes are sent to the container verbatim — no decrypt-then-reencrypt round trip strips the password on the wire or on disk. For `pemCertPath` sources, the `pfxPassword` field doubles as the encryption password used to synthesize a `.pfx` for extra destinations; if unset, the synthesized `.pfx` is passwordless (matching the source PEM key file's on-disk posture — neither carries a password, so there's nothing to strip).

### .NET X509Store install (opt-in)

By default, user-managed certs are **not** copied into the container's .NET X509Store (`~/.dotnet/corefx/cryptography/x509stores/my/`). `StoreName.My` enumeration on Linux constructs `X509Certificate2(path, /* password */ null)` and has no per-file password channel, so the on-disk file there has to be passwordless — copying your passworded PFX into that location would silently strip its password and leave the private key plain-text-equivalent on disk.

If you specifically need `X509Store(StoreName.My, StoreLocation.CurrentUser)` enumeration to find your user certs (for example, because some code reads `StoreName.My` directly), set:

```json
{
    "devcontainerDevCerts.installUserCertsToDotNetStore": true
}
```

Setting this acknowledges that the in-container PFX copy is passwordless. The original source file on the host is untouched, and the password-preserving copies still flow to extra destinations.

To exempt an individual entry from the global setting (e.g., keep most of your user certs in the store but carve out one sensitive cert), add `"excludeFromDotNetStore": true` to that `userCertificates` entry. Has no effect when the global setting is `false` (no user certs go to the store anyway).

The auto-generated dotnet-dev cert is always installed to the store regardless of these settings — it's intrinsically passwordless and the store IS its canonical location.

### Default Kestrel certificate (opt-in)

By default, Kestrel discovers the auto-generated dev cert through its X509Store fallback — no environment variables are set, and `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` remain untouched. If you'd like to pin a *custom* user certificate as Kestrel's default instead, set:

```json
{
    "devcontainerDevCerts.defaultKestrelCertificate": "corp-wildcard"
}
```

The value names a `devcontainerDevCerts.userCertificates` entry by `name`. When set, the workspace extension writes that cert's PFX to `~/.aspnet/dev-certs/https/kestrel-default.pfx` inside the container and sets these environment variables via VS Code's `EnvironmentVariableCollection`:

| Variable | Value |
|----------|-------|
| `ASPNETCORE_Kestrel__Certificates__Default__Path` | `~/.aspnet/dev-certs/https/kestrel-default.pfx` |
| `ASPNETCORE_Kestrel__Certificates__Default__Password` | The entry's `pfxPassword`, when set |

Only one certificate is selected at a time. Changing the setting (or clearing it) on the next sync rewrites or removes the file and the env vars. The pointer must reference a user-managed entry that carries a private key — CA-only entries are rejected with a warning notification.

**Scope.** The env vars only apply to processes launched from VS Code: integrated terminals, debug sessions, `tasks.json` invocations, the Aspire dashboard launcher, etc. Processes started outside VS Code (a stray `docker exec`, an SSH session into the container without VS Code attached) won't see them — that's intentional, since the selection lives in your VS Code settings, not in the container's environment. For those cases keep using the X509Store fallback (or set the env vars yourself in `devcontainer.json` `containerEnv`).

## Extra destinations

`extraCertDestinations` writes cert artifacts into additional directories inside the container — useful for non-.NET workloads (nginx, Java keystores, Python requests bundles, etc.). Each entry is a directory; every synced cert gets a set of files under it named after the cert. Formats:

| Format | Writes per cert |
|--------|-----------------|
| `pem` | `{name}.pem` (cert only) |
| `key` | `{name}.key` (private key; skipped when no key is available) |
| `pem-bundle` | `{name}-bundle.pem` (cert + key concatenated) |
| `pfx` | `{name}.pfx` (skipped when no private key is available) |
| `all` *(default)* | all of the above |

For PFX-sourced user certs the destination `.pfx` is the original file bytes verbatim — openable with the same `pfxPassword` you configured. For PEM-sourced user certs the `.pfx` is synthesized from the PEM key material; `pfxPassword` (if set) becomes its encryption password, otherwise it's passwordless.

After every cert has been written, OpenSSL's `c_rehash` runs once per unique destination directory (not once per cert and not once per write), so adding more synced certs doesn't multiply the rehash cost.

### Filename contract

Every cert written to an extra destination uses a stable, documented `{name}` that downstream configuration (nginx `ssl_certificate`, Java `keystore` scripts, etc.) can rely on:

| Cert | Filename stem |
|------|---------------|
| Auto-generated .NET dev cert | `aspnetcore-dev` |
| User-managed cert | the `name` field of the matching `userCertificates` entry |

So with `extraCertDestinations = /etc/nginx/certs` and a user cert named `corp-ca`, the directory ends up containing `aspnetcore-dev.pem`, `aspnetcore-dev.key`, `aspnetcore-dev.pfx`, `aspnetcore-dev-bundle.pem`, `corp-ca.pem`, `corp-ca.key`, `corp-ca.pfx`, and `corp-ca-bundle.pem` (subject to the format filter). The thumbprint-keyed filenames (`{thumbprint}.pfx`, `aspnetcore-localhost-{thumbprint}.pem`) remain only in the canonical .NET directories where Kestrel requires them — they do not appear in extra destinations.

## Development

### Prerequisites

- Node.js 22+
- Docker (for devcontainer testing)
- VS Code with the Dev Containers extension

### Building

Open the repo in VS Code and press F5. The `build-extensions` task will:

1. Build both TypeScript extensions with esbuild
2. Hydrate a test project from the template into `.out/test-project/`
3. Package the workspace extension VSIX into the test project's `.devcontainer/`

The Extension Development Host opens with the UI extension loaded on the host side. To test the full devcontainer flow, reopen `.out/test-project/` in a container.

## Known issues

### podman: subsequent feature's `apt-get update` fails with `Couldn't create temporary file /tmp/apt.conf.XXX`

This is [containers/buildah#6747](https://github.com/containers/buildah/issues/6747): when a devcontainer feature is installed via the `RUN --mount=type=bind,target=/tmp/build-features-src/<feat>_0 ...` pattern the devcontainer CLI generates, buildah/podman can commit the resulting layer with `/tmp` reset from `1777 root:root` to `0755 root:root`. A later feature that calls `apt-get update` then fails because `_apt` (uid 42) can no longer write to `/tmp`. Docker is not affected.

This feature applies the workaround at the end of its own install script, so combinations like `devcontainer-dev-certs` + `azure-functions-core-tools` on podman work out of the box. If you hit the same class of failure with a *different* feature, copy the standalone [`examples/buildah-tmp-fix/`](examples/buildah-tmp-fix/) local feature into your `.devcontainer/` and place it in `devcontainer.json` between the offending feature and the consumer.

## Limitations

- **Auto-generated dev cert matches .NET's format only.** The `generateDotNetCert` flow produces a cert identical to `dotnet dev-certs https` (specific OID marker, subject, SAN entries). To sync differently-shaped certs (corporate CAs, custom wildcard certs, etc.), add them via the `devcontainerDevCerts.userCertificates` VS Code setting — they're copied as-is.
- **VS Code only.** The companion extension pattern relies on VS Code's cross-host command routing. Other editors (JetBrains, Vim, etc.) are not supported, though the devcontainer feature includes a `setup-cert.sh` fallback script (with a `--bundle-json` form for multi-cert bundles) for manual use.
- **Host trust requires user interaction.** On Windows, trusting the auto-generated dev cert triggers a system dialog. On macOS, the keychain may prompt for a password. This only happens once and only for the .NET dev cert — user-managed certs are never added to the host OS trust store.

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Windows | x64, ARM64 |
| macOS | x64, ARM64 |
| Linux (glibc) | x64, ARM64 |
| Linux (musl/Alpine) | x64 |
