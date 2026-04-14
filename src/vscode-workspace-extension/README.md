# Dev Container Dev Certificates (Remote)

Automatically receive and install HTTPS development certificates inside Dev Containers and remote environments — no manual certificate management required.

This is the **remote companion** extension. It runs inside the remote environment (Dev Container, SSH, WSL) and works together with [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) to enable trusted HTTPS across the host/remote boundary.

## The Problem

When developing inside Dev Containers, HTTPS certificates are a persistent pain point:

- The dev cert needs to be **trusted on the host** so browsers don't show security warnings on forwarded ports
- The same cert needs to be **trusted inside the container** so services can communicate over HTTPS and tools like `curl` and `wget` work without `--insecure` flags
- Manually generating certificates, exporting PFX/PEM files, copying them into the container, and configuring trust is tedious and error-prone

This is especially common when working with [ASP.NET](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs) and [Aspire](https://aspire.dev/app-host/certificate-configuration/) projects, where HTTPS is the default for local development and inter-service communication.

## The Solution

A Dev Container feature + two companion VS Code extensions that handle everything automatically:

**Host side** (companion extension):
- Generates an HTTPS development certificate compatible with ASP.NET and Aspire (using node-forge — no .NET installation required on your host)
- Trusts it in the host OS certificate store (so browsers trust forwarded ports)
- Serves the certificate material (PFX + PEM, base64-encoded) to the remote side via VS Code's cross-host command routing

**Remote side** (this extension):
- Receives the certificate material from the host extension
- Places the PFX in the .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) so ASP.NET and Aspire discover it automatically
- Places the PEM in an OpenSSL trust directory with hash symlinks so `curl`, `wget`, and other tools trust it
- Configures `SSL_CERT_DIR` to include the trust directory alongside system CA paths

## Quick Start

Add the Dev Container feature to your `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs": {}
    }
}
```

That's it. The feature installs both extensions and configures the container's trust infrastructure. When you open the Dev Container in VS Code:

1. The host extension generates a dev cert and trusts it in the host OS certificate store
2. This extension requests the cert material via VS Code's cross-host command routing
3. The cert is installed in the container's .NET X509 store and OpenSSL trust directory
4. ASP.NET, Aspire, and other services discover the cert automatically — no environment variables or manual configuration needed
5. Your host browser trusts the cert on forwarded ports

## What This Extension Does

On activation in a remote context, this extension:

1. **Requests certificate material** from the host companion extension via `vscode.commands.executeCommand()` (routed transparently across VS Code extension hosts)
2. **Writes the PFX** to `~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx` — this is the .NET X509Store path that ASP.NET's `GetDevelopmentCertificateFromStore()` reads from automatically
3. **Writes the PEM** to `~/.aspnet/dev-certs/trust/` with OpenSSL hash symlinks (c_rehash implemented in pure TypeScript — no `openssl` binary required)
4. **Ensures `SSL_CERT_DIR`** includes the trust directory alongside standard system CA paths, so OpenSSL-based tools (`curl`, `wget`, etc.) trust the cert

If the host companion extension is not installed, this extension prompts you to install it with a single click.

### ASP.NET and Aspire Certificate Discovery

No `ASPNETCORE_Kestrel__Certificates__Default__Path` or other environment variables are needed. ASP.NET's startup chain falls back to reading the .NET X509Store, where it finds the PFX by its [ASP.NET dev cert OID marker](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs). This works for standalone ASP.NET services, [Aspire-orchestrated applications](https://aspire.dev/app-host/certificate-configuration/) (including non-.NET services), and any other workload that uses the ASP.NET dev cert format.

### OpenSSL Trust

The PEM certificate is placed with hash symlinks matching the format that OpenSSL's directory-based lookup expects. The `SSL_CERT_DIR` environment variable (set by the Dev Container feature or by this extension for non-Dev Container scenarios) tells OpenSSL to check this directory alongside the system CA bundle.

This means any tool or service that uses OpenSSL for TLS verification — regardless of language or framework — will trust the certificate.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoInject` | `true` | Automatically inject the cert when a remote session starts |
| `devcontainer-dev-certs.sslCertDirs` | `/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl` | System CA directories to include in `SSL_CERT_DIR`. Override for non-standard base images. |
| `devcontainer-dev-certs.ensureSslCertDir` | `true` | Configure `SSL_CERT_DIR` when the Dev Container feature hasn't set it (for SSH/WSL scenarios) |

## Feature Options

When using the Dev Container feature, these options are available:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs": {
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

- VS Code 1.100 or later
- [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) installed on the local machine

This extension is self-contained and does not require on any additional dependencies on your host or in the container.
