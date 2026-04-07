# Devcontainer Dev Certificates

> **Proof of concept** — this project is functional enough to validate the experience locally but has not been published to the VS Code Marketplace or any container registry. The devcontainer feature reference, marketplace links, and CI/CD workflows in this repo reflect an intended published state, but additional work is necessary before this can be made live.

Automatic HTTPS development certificate management for .NET or Aspire projects in devcontainers and VS Code remote environments.

## What This Does

When developing .NET applications or Aspire orchestration projects inside devcontainers, you need HTTPS certificates that are trusted on both sides: the host (so browsers accept forwarded ports) and the container (so servers can terminate HTTPS and allow inter-service calls work). This project automates the entire process.

Add the devcontainer feature to your `devcontainer.json` and everything works automatically:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/dotnet-dev-certs": {}
    }
}
```

No `dotnet dev-certs` commands, no manual PFX exports, no environment variable configuration.

## How It Works

The solution has three components that work together:

1. **Devcontainer Feature** sets up the container's trust infrastructure: creates the .NET X509 store and OpenSSL trust directories, configures `SSL_CERT_DIR`, and requests installation of the two companion VS Code extensions.

2. **Host Extension** (`extensionKind: ["ui"]`) runs on your local machine. It bundles a platform-specific AOT-compiled .NET tool that generates certificates identical to `dotnet dev-certs https` (same OID marker, same SAN entries, same key parameters). On first use, it generates a cert and trusts it in the host OS certificate store. It then serves the certificate material to the remote side via VS Code's cross-host command routing.

3. **Remote Extension** (`extensionKind: ["workspace"]`) runs inside the container. On activation, it requests certificate material from the host extension, decodes it, and places it in two locations:
   - The .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) where Kestrel discovers it automatically via its `GetDevelopmentCertificateFromStore()` fallback
   - An OpenSSL trust directory (`~/.aspnet/dev-certs/trust/`) with hash symlinks (c_rehash, implemented in pure TypeScript) so `curl`, `wget`, and other OpenSSL-based tools trust it

The two extensions communicate using VS Code's cross-host `executeCommand()` routing with `"api": "none"` and `extensionDependencies` for guaranteed activation ordering. This architecture is transport-agnostic — it works for devcontainers today and can support SSH remoting, WSL, or any future VS Code remote backend.

## Repository Layout

```
src/
  aot-tool/                        .NET 10 AOT-compiled certificate management CLI
    src/DevCerts.Tool/
      Certificate/                 Certificate generation (matches ASP.NET CertificateManager)
      Platform/                    OS-specific cert stores (Windows, macOS, Linux)
      Export/                      PFX and PEM export
      Commands/                    CLI command handlers (generate, trust, export, check, clean)
    tests/DevCerts.Tool.Tests/     Unit tests (xUnit)

  vscode-ui-extension/             VS Code host extension (extensionKind: ui)
    src/
      aotTool/                     Spawns the AOT binary
      certProvider.ts              Orchestrates generate/trust/export, serves cert material

  vscode-workspace-extension/      VS Code remote extension (extensionKind: workspace)
    src/
      certInstaller.ts             Writes cert files to correct paths
      util/rehash.ts               Pure TypeScript c_rehash (OpenSSL subject hash computation)
      util/sslCertDir.ts           SSL_CERT_DIR management for non-devcontainer remotes
      util/paths.ts                .NET store and OpenSSL trust directory paths

  devcontainer-feature/            Devcontainer feature
    src/dotnet-dev-certs/
      devcontainer-feature.json    Feature metadata, containerEnv, extension references
      install.sh                   Container build-time setup (creates directories)

test/
  sample-project/                  Test project template (hydrated into .out/ for testing)
  hydrate.mjs                      Assembles a runnable test project from the template + feature

.github/workflows/                 CI/CD (build, AOT publish, extension packaging, feature publishing)
```

## Feature Options

| Option | Default | Description |
|--------|---------|-------------|
| `trustNss` | `false` | Install NSS tools for Chromium/Firefox trust inside the container |
| `sslCertDirs` | Standard distro paths | System CA directories for `SSL_CERT_DIR`. Override for non-standard base images. |

## Development

### Prerequisites

- .NET 10 SDK
- Node.js 20+
- Docker (for devcontainer testing)
- VS Code with the Dev Containers extension

### Building

Open the repo in VS Code and press F5. The `build-extensions` task will:

1. AOT publish the `devcerts` binary for your platform into the UI extension's `bin/` directory
2. Build both TypeScript extensions with esbuild
3. Hydrate a test project from the template into `.out/test-project/`
4. Package the workspace extension VSIX into the test project's `.devcontainer/`

The Extension Development Host opens with the UI extension loaded on the host side. To test the full devcontainer flow, reopen `.out/test-project/` in a container.

### Testing the AOT Tool Directly

```bash
cd src/aot-tool
dotnet test                           # Run unit tests
dotnet run --project src/DevCerts.Tool -- check --json   # Check cert status
dotnet run --project src/DevCerts.Tool -- trust          # Generate + trust
dotnet run --project src/DevCerts.Tool -- clean          # Remove certs
```

## Limitations

- **Only .NET development certificates.** This project generates certificates that match the format produced by `dotnet dev-certs https` (specific OID marker, subject, SAN entries). It does not support injecting arbitrary CA certificates or custom certificates into devcontainers.
- **VS Code only.** The companion extension pattern relies on VS Code's cross-host command routing. Other editors (JetBrains, Vim, etc.) are not supported, though the devcontainer feature includes a `setup-cert.sh` fallback script for manual use.
- **Single certificate.** The tool manages one dev cert at a time. Running `trust` when a valid cert already exists reuses it; `clean` removes it entirely.
- **Host trust requires user interaction.** On Windows, trusting the certificate triggers a system dialog. On macOS, the keychain may prompt for a password. This only happens once.
- **macOS code signing not yet implemented.** The AOT binary needs to be signed and notarized with an Apple Developer ID certificate to access the macOS keychain and avoid Gatekeeper quarantine.

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Windows | x64, ARM64 |
| macOS | x64, ARM64 |
| Linux (glibc) | x64, ARM64 |
| Linux (musl/Alpine) | x64 |
