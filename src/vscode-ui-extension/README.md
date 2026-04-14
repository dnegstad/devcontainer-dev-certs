# Dev Container Dev Certificates (Host)

Automatically generate, trust, and share HTTPS development certificates with Dev Containers and remote environments — no manual certificate management or additional tools required on your host.

This is the **host companion** extension. It runs on your local machine and works together with [Dev Container Dev Certificates (Remote)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-remote) to enable trusted HTTPS across the host/remote boundary.

## The Problem

When developing inside Dev Containers, HTTPS certificates are a persistent pain point:

- The dev cert needs to be **trusted on the host** so browsers don't show security warnings on forwarded ports
- The same cert needs to be **trusted inside the container** so services can communicate over HTTPS and tools like `curl` and `wget` work without `--insecure` flags
- Manually generating certificates, exporting PFX/PEM files, copying them into the container, and configuring trust is tedious and error-prone

This is especially common when working with [ASP.NET](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs) and [Aspire](https://aspire.dev/app-host/certificate-configuration/) projects, where HTTPS is the default for local development and inter-service communication.

## The Solution

A Dev Container feature + two companion VS Code extensions that handle everything automatically:

**Host side** (this extension):
- Generates an HTTPS development certificate compatible with ASP.NET and Aspire (using node-forge — no .NET installation required on your host)
- Trusts it in the host OS certificate store (so browsers trust forwarded ports)
- Serves the certificate material (PFX + PEM, base64-encoded) to the remote side via VS Code's cross-host command routing

**Remote side** (companion extension):
- Receives the certificate material from this extension
- Places the PFX in the .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) so ASP.NET and Aspire discover it automatically
- Places the PEM in an OpenSSL trust directory with hash symlinks so `curl`, `wget`, and other tools trust it
- Configures `SSL_CERT_DIR` to include the trust directory alongside system CA paths

## Quick Start

Add the Dev Container feature to your `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/dotnet-dev-certs": {}
    }
}
```

That's it. The feature installs both extensions and configures the container's trust infrastructure. When you open the Dev Container in VS Code:

1. This extension generates a dev cert on your host (if one doesn't exist) and trusts it in your OS certificate store
2. The remote companion extension requests the cert material via VS Code's cross-host command routing
3. The cert is installed in the container's .NET X509 store and OpenSSL trust directory
4. ASP.NET, Aspire, and other services discover the cert automatically — no environment variables or manual configuration needed
5. Your host browser trusts the cert on forwarded ports

## How It Works

### Certificate Generation

The extension generates certificates using node-forge (pure JavaScript — no .NET installation required on your host). The certificate is compatible with the [ASP.NET dev cert format](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs) and includes:

- Subject: `CN=localhost`
- SAN: `localhost`, `*.dev.localhost`, `*.dev.internal`, `host.docker.internal`, `host.containers.internal`, `127.0.0.1`, `::1`
- The ASP.NET Core HTTPS development certificate OID marker (`1.3.6.1.4.1.311.84.1.1`, version 6)
- RSA 2048-bit key, SHA-256 signature, 365-day validity

This means `dotnet dev-certs https --check` recognizes it as a valid dev cert, and [Aspire](https://aspire.dev/app-host/certificate-configuration/) uses it for orchestrated service-to-service HTTPS — including non-.NET services.

### Host Trust

The cert is trusted in your OS certificate store:

| Platform | Trust Mechanism |
|----------|----------------|
| Windows | Added to `CurrentUser\Root` (triggers system dialog on first use) |
| macOS | Added to login keychain via `security add-trusted-cert` |
| Linux | Added to .NET Root store + OpenSSL trust directory |

### Cross-Host Transfer

Certificate material (PFX + PEM) is serialized as base64 and transferred via `vscode.commands.executeCommand()`, which VS Code routes transparently between extension hosts. No Docker commands, no file mounts — this works for any VS Code remote scenario.

### Container Trust

Inside the container, the remote extension places the cert in two locations:

- **`~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx`** — ASP.NET's X509Store fallback discovers it automatically
- **`~/.aspnet/dev-certs/trust/`** — PEM + OpenSSL hash symlinks, included in `SSL_CERT_DIR` so `curl`, `wget`, and other OpenSSL-based tools trust it

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `dotnet-dev-certs.autoProvision` | `true` | Automatically generate and trust a cert when the remote extension requests one |

## Requirements

- VS Code 1.85 or later
- [Dev Container Dev Certificates (Remote)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-remote) installed in the remote environment

No .NET installation is required on your host machine.

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Windows | x64, ARM64 |
| macOS | x64, ARM64 |
| Linux (glibc) | x64, ARM64 |
| Linux (musl/Alpine) | x64 |
