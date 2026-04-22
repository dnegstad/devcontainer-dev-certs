# Devcontainer Dev Certificates

Automatic HTTPS development certificate management for .NET or Aspire projects in devcontainers and VS Code remote environments.

## What This Does

When developing .NET applications or Aspire orchestration projects inside devcontainers, you need HTTPS certificates that are trusted on both sides: the host (so browsers accept forwarded ports) and the container (so servers can terminate HTTPS and allow inter-service calls work). This project automates the entire process.

Add the devcontainer feature to your `devcontainer.json` and everything works automatically:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:latest": {}
    }
}
```

No `dotnet dev-certs` commands, no manual PFX exports, no environment variable configuration.

## Getting Started

### Prerequisites

- VS Code 1.100 or later
- The [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
- Docker or a compatible container runtime

### Install the Host Extension

The dev container feature requests installation of the host extension automatically, but you can also install it ahead of time:

- **VS Code Marketplace:** [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host)
- **Extensions view:** search for `dnegstad.devcontainer-dev-certs-host`
- **CLI:** `code --install-extension dnegstad.devcontainer-dev-certs-host`

The remote extension (`dnegstad.devcontainer-dev-certs-remote`) is installed inside the container automatically by the feature and does not need manual installation.

### Add the Feature

Add the dev container feature to your project's `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:latest": {}
    }
}
```

Then rebuild or reopen your project in the dev container. On first use:

1. The host extension shows a consent prompt, then generates a development certificate and trusts it in your OS certificate store. On Windows this triggers a system dialog; on macOS the keychain may prompt for a password. This only happens once.
2. The remote extension receives the certificate and installs it in the container's .NET X509 store and OpenSSL trust directory.
3. ASP.NET, Aspire, and CLI tools like `curl` and `wget` trust the certificate automatically — no environment variables or manual configuration needed.
4. Your host browser trusts the certificate on forwarded ports.

## How It Works

The solution has three components that work together:

1. **Devcontainer Feature** sets up the container's trust infrastructure: creates the .NET X509 store and OpenSSL trust directories, configures `SSL_CERT_DIR`, and requests installation of the two companion VS Code extensions.

2. **Host Extension** (`extensionKind: ["ui"]`) runs on your local machine. It generates certificates identical to `dotnet dev-certs https` (same OID marker, same SAN entries, same key parameters) using `node-forge` for X.509 certificate creation. On first use, it generates a cert and trusts it in the host OS certificate store. It then serves the certificate material to the remote side via VS Code's cross-host command routing.

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
      devcontainer-feature.json    Feature metadata, containerEnv, extension references
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
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs": {
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
| `extraCertDestinations` | `""` | Comma-separated list of additional paths to write cert artifacts to. Each entry is `<abs-path>[=<format>]` where `format` is `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). Trailing `/` means a directory target; `${name}` may be used in the filename. Example: `/etc/nginx/certs/=pem,/var/myapp/`. |

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

User-managed certs are **never** added to the host OS trust store; the assumption is you already trust them on the host if you're syncing them.

## Extra destinations

`extraCertDestinations` writes cert artifacts to additional paths inside the container — useful for non-.NET workloads (nginx, Java keystores, Python requests bundles, etc.). Formats:

| Format | Writes |
|--------|--------|
| `pem` | `{name}.pem` (cert only) |
| `key` | `{name}.key` (private key; skipped when no key is available) |
| `pem-bundle` | `{name}-bundle.pem` (cert + key concatenated) |
| `pfx` | `{name}.pfx` (skipped when no key is available) |
| `all` *(default)* | all of the above |

Directory targets (trailing `/`) rehash the directory once per write so OpenSSL can discover the PEMs.

### Filename contract

Every cert written to an extra destination uses a stable, documented `{name}` that downstream configuration (nginx `ssl_certificate`, Java `keystore` scripts, etc.) can rely on:

| Cert | Filename stem |
|------|---------------|
| Auto-generated .NET dev cert | `aspnetcore-dev` |
| User-managed cert | the `name` field of the matching `userCertificates` entry |

So with `extraCertDestinations = /etc/nginx/certs/` and a user cert named `corp-ca`, the directory ends up containing `aspnetcore-dev.pem`, `aspnetcore-dev.key`, `aspnetcore-dev.pfx`, `aspnetcore-dev-bundle.pem`, `corp-ca.pem`, `corp-ca.key`, `corp-ca.pfx`, and `corp-ca-bundle.pem` (subject to the format filter). The thumbprint-keyed filenames (`{thumbprint}.pfx`, `aspnetcore-localhost-{thumbprint}.pem`) remain only in the canonical .NET directories where Kestrel requires them — they do not appear in extra destinations.

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
