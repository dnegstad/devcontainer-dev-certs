# Agent Instructions

This is a monorepo containing three components that together provide automatic HTTPS certificate management for .NET workloads in VS Code devcontainers and remote environments.

## Architecture

The system uses the VS Code **companion extension pattern**: two extensions communicate via cross-host `executeCommand()` routing.

- **UI extension** (`src/vscode-ui-extension/`) — `extensionKind: ["ui"]`, runs on the host machine. Uses `node-forge` for X.509 certificate generation, loading, and platform-specific mechanisms for OS trust store management. Registers two cross-host commands:
  - `devcontainer-dev-certs.getAllCertMaterial({ includeDotNetDev, includeUserCerts })` — v2 multi-cert entrypoint. Returns a `CertBundle` combining the optional auto-generated .NET dev cert with any user-managed certificates configured in `devcontainerDevCerts.userCertificates`.
  - `devcontainer-dev-certs.getCertMaterial(autoProvision)` — legacy single-cert entrypoint, kept for backward compatibility with older pinned workspace extensions. Returns `null` when the host has disabled dotnet cert generation.

  Platform trust for the auto-generated cert is handled via PowerShell (Windows), the `security` CLI (macOS), and file-based stores with OpenSSL rehash (Linux). User-managed certs are never added to the host OS trust store.

- **Workspace extension** (`src/vscode-workspace-extension/`) — `extensionKind: ["workspace"]`, runs in the remote (container/SSH/WSL). Calls `getAllCertMaterial` first, falling back to `getCertMaterial` if the UI extension is on an older version. Parses `DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS` into an `ExtraDestination[]` via `src/util/destinations.ts`, then for each cert in the bundle:
  1. Installs it to the canonical .NET + OpenSSL locations (`installDotNetDevCert` / `installUserCert` in `certInstaller.ts`).
  2. Writes each cert to every configured extra destination via `writeExtraDestination`.
  3. Runs a single rehash per directory destination after all writes.

- **Devcontainer feature** (`src/devcontainer-feature/`) — sets `SSL_CERT_DIR` via `containerEnv`, creates `.dotnet/corefx/cryptography/x509stores/my/` and `.aspnet/dev-certs/trust/` directories, requests both extensions via `customizations.vscode.extensions`. `install.sh` also pre-creates any directories named in `extraCertDestinations` with `vscode` ownership so the remote extension can write without privileged escalation. Option values (`generateDotNetCert`, `syncUserCertificates`, `extraCertDestinations`) are surfaced to the runtime container via `/etc/environment`.

## Key Design Decisions

These decisions were made deliberately. Do not change them without discussion.

- **No Kestrel environment variables.** Do not set `ASPNETCORE_Kestrel__Certificates__Default__Path` or `__Password`. Kestrel discovers the cert via X509Store fallback.

- **No `update-ca-certificates`.** OpenSSL trust is handled via `SSL_CERT_DIR` pointing to a directory with c_rehash hash symlinks. No system CA bundle modification.

- **No openssl binary dependency in the container.** The workspace extension implements c_rehash in pure TypeScript (`src/vscode-workspace-extension/src/util/rehash.ts`) — ASN.1 DER parsing + SHA-1 subject hash computation.

- **No docker exec/cp.** Certificate material is transferred via VS Code's cross-host command routing, making the solution remote-transport-agnostic. Do not introduce Docker-specific commands.

- **Honor `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY`.** Both the UI extension's Linux store (`src/vscode-ui-extension/src/platform/linuxStore.ts`) and the workspace extension (`util/paths.ts`) respect this override, matching the official .NET `CertificateManager` behavior.

- **`SSL_CERT_DIR` must include system CA paths.** Setting it overrides the system default entirely. The devcontainer feature includes all common distro paths (`/etc/ssl/certs`, `/usr/lib/ssl/certs`, `/etc/pki/tls/certs`, `/var/lib/ca-certificates/openssl`) and exposes `sslCertDirs` as an option for user override.

- **The UI extension has no user-facing commands.** It exposes only the internal `getCertMaterial` command. Certificate generation and trust happen automatically when the workspace extension requests material.

## Build System

- **Extensions**: TypeScript, esbuild bundler, `@types/vscode ^1.100.0`. The UI extension bundles `node-forge` as its only runtime dependency (bundled by esbuild into the output).
- **CI**: GitHub Actions. The UI extension is packaged as a single universal VSIX (no per-platform binaries). The workspace extension is also a single universal VSIX.

## Testing

- **Extension testing**: F5 launches an Extension Development Host. The `build-extensions` task hydrates a test project at `.out/test-project/` from the template at `test/sample-project/`. The workspace extension VSIX is staged in `.out/test-project/.devcontainer/` and referenced via `${containerWorkspaceFolder}` in `customizations.vscode.extensions`.
- **The `trust` operation generates the cert if it doesn't exist.** This is intentional — it's the single entry point for provisioning.

## File Paths That Matter

| Path (in container) | Purpose |
|---------------------|---------|
| `~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx` | .NET X509Store — Kestrel reads from here. One per cert (dotnet-dev or user) that has a private key. |
| `~/.dotnet/corefx/cryptography/x509stores/root/{thumbprint}.pfx` | .NET Root store — public-cert-only PFX for trust reporting. |
| `~/.aspnet/dev-certs/trust/aspnetcore-localhost-{thumbprint}.pem` | OpenSSL trust — PEM for the auto-generated dotnet dev cert. |
| `~/.aspnet/dev-certs/trust/{userCert.name}.pem` | OpenSSL trust — PEM for a user-managed cert, keyed by the user-supplied `name` (stable, predictable filename). |
| `~/.aspnet/dev-certs/trust/{hash}.0` | OpenSSL trust — hash symlink (c_rehash) pointing at either of the above. |
| `{extraCertDestinations entry}/{certName}.{pem,key,pfx}` or `{certName}-bundle.pem` | Additional per-destination files. `certName` is `aspnetcore-dev` for the dotnet dev cert, or the `userCertificates[].name` for user certs. This is a stable contract; downstream configs may rely on it. |

## Certificate Properties

Must match ASP.NET's `CertificateManager` exactly:
- Subject: `CN=localhost`
- RSA 2048-bit, SHA-256, PKCS1 padding
- 365-day validity
- Extensions: Basic Constraints (critical, not CA), Key Usage (critical, KeyEncipherment|DigitalSignature), EKU (critical, Server Auth), SAN (critical, 7 entries), custom OID `1.3.6.1.4.1.311.84.1.1` with version byte `0x06`, SKI, AKI
