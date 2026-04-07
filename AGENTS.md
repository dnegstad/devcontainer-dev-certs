# Agent Instructions

This is a monorepo containing four components that together provide automatic HTTPS certificate management for .NET workloads in VS Code devcontainers and remote environments.

## Architecture

The system uses the VS Code **companion extension pattern**: two extensions communicate via cross-host `executeCommand()` routing.

- **UI extension** (`src/vscode-ui-extension/`) — `extensionKind: ["ui"]`, runs on the host machine. Bundles a platform-specific AOT-compiled .NET binary. Registers a single internal command `dotnet-dev-certs.getCertMaterial` that generates, trusts, and exports the certificate, returning PFX + PEM as base64.

- **Workspace extension** (`src/vscode-workspace-extension/`) — `extensionKind: ["workspace"]`, runs in the remote (container/SSH/WSL). Declares `extensionDependencies` on the UI extension with `"api": "none"` for guaranteed cross-host activation ordering. Calls `getCertMaterial`, writes PFX to the .NET X509 store path and PEM + hash symlinks to the OpenSSL trust directory.

- **AOT tool** (`src/aot-tool/`) — .NET 10 console app with `PublishAot=true`. Implements certificate generation matching ASP.NET's `CertificateManager` (OID `1.3.6.1.4.1.311.84.1.1`, version 6). Platform-specific stores for Windows (`CurrentUser\My` + `Root`), macOS (keychain + disk), Linux (X509Store + OpenSSL dir). CLI commands: `generate`, `trust`, `export`, `check`, `clean`.

- **Devcontainer feature** (`src/devcontainer-feature/`) — sets `SSL_CERT_DIR` via `containerEnv`, creates `.dotnet/corefx/cryptography/x509stores/my/` and `.aspnet/dev-certs/trust/` directories, requests both extensions via `customizations.vscode.extensions`.

## Key Design Decisions

These decisions were made deliberately. Do not change them without discussion.

- **No Kestrel environment variables.** Do not set `ASPNETCORE_Kestrel__Certificates__Default__Path` or `__Password`. Kestrel discovers the cert via X509Store fallback.

- **No `update-ca-certificates`.** OpenSSL trust is handled via `SSL_CERT_DIR` pointing to a directory with c_rehash hash symlinks. No system CA bundle modification.

- **No openssl binary dependency in the container.** The workspace extension implements c_rehash in pure TypeScript (`src/vscode-workspace-extension/src/util/rehash.ts`) — ASN.1 DER parsing + SHA-1 subject hash computation.

- **No docker exec/cp.** Certificate material is transferred via VS Code's cross-host command routing, making the solution remote-transport-agnostic. Do not introduce Docker-specific commands.

- **Honor `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY`.** Both the AOT tool (`LinuxCertificateStore`) and the workspace extension (`util/paths.ts`) respect this override, matching the official .NET `CertificateManager` behavior.

- **`SSL_CERT_DIR` must include system CA paths.** Setting it overrides the system default entirely. The devcontainer feature includes all common distro paths (`/etc/ssl/certs`, `/usr/lib/ssl/certs`, `/etc/pki/tls/certs`, `/var/lib/ca-certificates/openssl`) and exposes `sslCertDirs` as an option for user override.

- **The UI extension has no user-facing commands.** It exposes only the internal `getCertMaterial` command. Certificate generation and trust happen automatically when the workspace extension requests material.

## Build System

- **AOT tool**: .NET 10, `System.CommandLine 2.0.5`, central package management via `Directory.Packages.props`. Tests use xUnit.
- **Extensions**: TypeScript, esbuild bundler, `@types/vscode ^1.100.0`. No runtime npm dependencies — everything is bundled.
- **CI**: GitHub Actions. AOT builds require native compilation on each target platform (no cross-compilation). The UI extension is packaged as 7 platform-specific VSIXes. The workspace extension is a single universal VSIX.

## Testing

- **Unit tests**: `cd src/aot-tool && dotnet test` — 21 tests covering certificate generation, OID markers, SAN entries, PFX/PEM export round-trips.
- **Local AOT tool testing**: The `devcerts` binary can be run directly for manual testing (`check`, `trust`, `clean`, `export`).
- **Extension testing**: F5 launches an Extension Development Host. The `build-extensions` task hydrates a test project at `.out/test-project/` from the template at `test/sample-project/`. The workspace extension VSIX is staged in `.out/test-project/.devcontainer/` and referenced via `${containerWorkspaceFolder}` in `customizations.vscode.extensions`.
- **The `trust` command generates the cert if it doesn't exist.** This is intentional — it's the single entry point for provisioning.

## File Paths That Matter

| Path (in container) | Purpose |
|---------------------|---------|
| `~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx` | .NET X509Store — Kestrel reads from here |
| `~/.aspnet/dev-certs/trust/aspnetcore-localhost-{thumbprint}.pem` | OpenSSL trust — PEM cert |
| `~/.aspnet/dev-certs/trust/{hash}.0` | OpenSSL trust — hash symlink (c_rehash) |

## Certificate Properties

Must match ASP.NET's `CertificateManager` exactly:
- Subject: `CN=localhost`
- RSA 2048-bit, SHA-256, PKCS1 padding
- 365-day validity
- Extensions: Basic Constraints (critical, not CA), Key Usage (critical, KeyEncipherment|DigitalSignature), EKU (critical, Server Auth), SAN (critical, 7 entries), custom OID `1.3.6.1.4.1.311.84.1.1` with version byte `0x06`, SKI, AKI
