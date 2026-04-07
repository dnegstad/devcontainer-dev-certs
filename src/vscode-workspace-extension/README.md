# Devcontainer Dev Certificates (Remote)

Automatically receive and install .NET HTTPS development certificates inside devcontainers and remote environments — no manual certificate management required.

This is the **remote companion** extension. It runs inside the remote environment (devcontainer, SSH, WSL) and works together with [Devcontainer Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) to enable trusted HTTPS across the host/remote boundary.

## The Problem

When developing .NET applications (Kestrel, Aspire) inside devcontainers, HTTPS certificates are a persistent pain point:

- The dev cert needs to be **trusted on the host** so browsers don't show security warnings on forwarded ports
- The same cert needs to be **recognized by .NET inside the container** so Kestrel can serve HTTPS and inter-service calls (common in Aspire) succeed
- Manually running `dotnet dev-certs`, exporting PFX/PEM files, copying them into the container, and configuring trust is tedious and error-prone

## The Solution

A devcontainer feature + two companion VS Code extensions that handle everything automatically:

**Host side** (companion extension):
- Bundles a platform-specific AOT-compiled .NET tool
- Generates a certificate identical to `dotnet dev-certs https`
- Trusts it in the host OS certificate store (so browsers trust forwarded ports)
- Serves the certificate material (PFX + PEM, base64-encoded) to the remote side via VS Code's cross-host command routing

**Remote side** (this extension):
- Receives the certificate material from the host extension
- Places the PFX in the .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) so Kestrel discovers it automatically
- Places the PEM in an OpenSSL trust directory with hash symlinks so `curl`, `wget`, and other tools trust it
- Configures `SSL_CERT_DIR` to include the trust directory alongside system CA paths

## Quick Start

Add the devcontainer feature to your `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/dotnet-dev-certs": {}
    }
}
```

That's it. The feature installs both extensions and configures the container's trust infrastructure. When you open the devcontainer in VS Code:

1. The host extension generates a .NET-compatible dev cert and trusts it in the host OS certificate store
2. This extension requests the cert material via VS Code's cross-host command routing
3. The cert is installed in the container's .NET X509 store and OpenSSL trust directory
4. Kestrel discovers the cert automatically — no environment variables or manual configuration needed
5. Your host browser trusts the cert on forwarded ports

## What This Extension Does

On activation in a remote context, this extension:

1. **Requests certificate material** from the host companion extension via `vscode.commands.executeCommand()` (routed transparently across VS Code extension hosts)
2. **Writes the PFX** to `~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx` — this is the .NET X509Store path that Kestrel's `GetDevelopmentCertificateFromStore()` reads from automatically
3. **Writes the PEM** to `~/.aspnet/dev-certs/trust/` with OpenSSL hash symlinks (c_rehash implemented in pure TypeScript — no `openssl` binary required)
4. **Ensures `SSL_CERT_DIR`** includes the trust directory alongside standard system CA paths, so OpenSSL-based tools (`curl`, `wget`, etc.) trust the cert

If the host companion extension is not installed, this extension prompts you to install it with a single click.

### .NET Certificate Discovery

No `ASPNETCORE_Kestrel__Certificates__Default__Path` or other environment variables are needed. Kestrel's startup chain falls back to reading the .NET X509Store, where it finds the PFX by its ASP.NET dev cert OID marker. This works for standalone Kestrel, Aspire orchestrated services, and any other .NET HTTPS workload.

### OpenSSL Trust

The PEM certificate is placed with hash symlinks matching the format that OpenSSL's directory-based lookup expects. The `SSL_CERT_DIR` environment variable (set by the devcontainer feature or by this extension for non-devcontainer scenarios) tells OpenSSL to check this directory alongside the system CA bundle.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `dotnet-dev-certs.autoInject` | `true` | Automatically inject the cert when a remote session starts |
| `dotnet-dev-certs.sslCertDirs` | `/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl` | System CA directories to include in `SSL_CERT_DIR`. Override for non-standard base images. |
| `dotnet-dev-certs.ensureSslCertDir` | `true` | Configure `SSL_CERT_DIR` when the devcontainer feature hasn't set it (for SSH/WSL scenarios) |

## Feature Options

When using the devcontainer feature, these options are available:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/dotnet-dev-certs": {
            "trustNss": false,
            "sslCertDirs": "/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl"
        }
    }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `trustNss` | `false` | Install NSS tools for Chromium/Firefox trust inside the container |
| `sslCertDirs` | Standard distro paths | System CA directories for `SSL_CERT_DIR`. Override if your base image uses non-standard paths. |

## Environment Variables

This extension honors the following environment variables, matching the behavior of the official .NET `CertificateManager`:

| Variable | Description |
|----------|-------------|
| `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY` | Override the default OpenSSL trust directory (`~/.aspnet/dev-certs/trust/`) |

## Requirements

- VS Code 1.85 or later
- [Devcontainer Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) installed on the local machine
