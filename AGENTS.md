# Agent Instructions

This is a monorepo containing three components that together provide automatic HTTPS certificate management for .NET workloads in VS Code devcontainers and remote environments.

## Architecture

The system uses the VS Code **companion extension pattern**: two extensions communicate via cross-host `executeCommand()` routing.

- **UI extension** (`src/vscode-ui-extension/`) — `extensionKind: ["ui"]`, runs on the host machine. Uses Node's built-in `crypto` plus `@peculiar/x509` (X.509) and `pkijs` (PKCS#12) for certificate generation, loading, and PFX I/O — supporting RSA, ECDSA, and Ed25519 keys for user-managed certs. Trust store management is handled by platform-specific mechanisms. Registers four cross-host commands:
  - `devcontainer-dev-certs.getAllCertMaterialV3({ includeDotNetDev, includeUserCerts })` — current multi-cert pull entry point with password-preserving `pfxBase64` and per-cert `installToDotNetStore` flag.
  - `devcontainer-dev-certs.getAllCertMaterial({ includeDotNetDev, includeUserCerts })` — v2 multi-cert pull entry point. Kept for workspace extensions pinned to the V2 wire contract.
  - `devcontainer-dev-certs.getCertMaterial(autoProvision)` — legacy single-cert pull entry point. Returns `null` when the host has disabled dotnet cert generation.
  - `devcontainer-dev-certs.acceptContainerDevCert({ thumbprint, pfxBase64, ... })` — **reverse-sync push entry point** (issue #63). Takes a PFX pushed from a Dev Container that opted into `syncContainerCert`, independently re-validates (`isValidDevCert` + `validateLocalSans`), prompts for one-time consent (`containerCertProvisionConsented` global state — distinct from the host-generation consent because the user is approving trust of a cert that came from a container they may or may not control), and saves + trusts the cert in the host platform store via the same path the auto-generation flow uses. Gated on the SAME host settings as the generation flow: `devcontainerDevCerts.generateDotNetCert` and `devcontainer-dev-certs.autoProvision`. SAN-local restriction has an opt-out via `devcontainerDevCerts.allowNonLocalContainerCertSans`.

  Platform trust for the auto-generated cert is handled via PowerShell (Windows), the `security` CLI (macOS), and file-based stores with OpenSSL rehash (Linux). User-managed certs are never added to the host OS trust store. Container-pushed dev certs (when both opt-ins are on) ARE added to the host OS trust store via the same platform path as the auto-generated cert.

- **Workspace extension** (`src/vscode-workspace-extension/`) — `extensionKind: ["workspace"]`, runs in the remote (container/SSH/WSL). Calls `getAllCertMaterialV3` first, falling back to `getAllCertMaterial` then `getCertMaterial` if the UI extension is older. Parses `DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS` into an `ExtraDestination[]` via `src/util/destinations.ts`, then for each cert in the bundle:
  1. Installs it to the canonical .NET + OpenSSL locations (`installDotNetDevCert` / `installUserCert` in `certInstaller.ts`).
  2. Writes each cert to every configured extra destination via `writeExtraDestination`.
  3. Runs a single rehash per directory destination after all writes.

  Additionally, when `DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER=true` (set by the `syncContainerCert` feature option), the workspace extension runs `pushContainerCertToHost()` **before** the standard pull. That scans `~/.dotnet/corefx/cryptography/x509stores/my/*.pfx` using the same shared `classifyCandidate` + `selectBestDevCert` rules the host uses on its own platform stores, pre-validates the winning candidate, and pushes it to the host via `acceptContainerDevCert`. The standard pull still runs afterwards (V3 pulls naturally return whatever cert the host now has trusted, so the container side ends up with the same cert it pushed).

- **Shared package** (`src/shared/`) — TypeScript-only, no vscode dependency. Houses the cert primitives both extensions need: `cert/types.ts` (DevCert/DevKey wrappers around `@peculiar/x509`), `cert/properties.ts` (OIDs, version constants, default SANs), `cert/pfx.ts` (PKCS#12 build/parse), `cert/loader.ts` (PFX + PEM file loading), `cert/validation.ts` (`isValidDevCert`, `getCertificateVersion`, `validateLocalSans`), and `cert/classify.ts` (`classifyCandidate`, `selectBestDevCert`, `extractThumbprintHintFromFilename`). The classifier is side-effect-free — callers in vscode contexts opt into a localized log line by passing `onSkipped` / `onMultipleCandidates` callbacks. Both extensions independently localize via their own `vscode.l10n.t` bundles.

- **Devcontainer feature** (`src/devcontainer-feature/`) — sets `SSL_CERT_DIR` from `install.sh` by writing `/etc/profile.d/devcontainer-dev-certs.sh` (login shells, `$HOME`-expanded) and `/etc/environment` (PAM, resolved `_REMOTE_USER_HOME`); the manifest can't carry it because `${containerEnv:HOME}` doesn't resolve inside `containerEnv` and `remoteEnv` isn't allowed in features under strict-schema validation. Creates `.dotnet/corefx/cryptography/x509stores/my/` and `.aspnet/dev-certs/trust/` directories, requests both extensions via `customizations.vscode.extensions`. `install.sh` also pre-creates any directories named in `extraCertDestinations` with `vscode` ownership so the remote extension can write without privileged escalation. Option values (`generateDotNetCert`, `syncUserCertificates`, `syncContainerCert`, `extraCertDestinations`) are surfaced to the runtime container via `/etc/environment`.

## Key Design Decisions

These decisions were made deliberately. Do not change them without discussion.

- **Kestrel environment variables are opt-in only.** Kestrel discovers the auto-generated dev cert via X509Store fallback — the workspace extension does NOT set `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` for it. The single exception is `devcontainerDevCerts.defaultKestrelCertificate`: when the host resolves it to a qualifying user cert, it attaches a bundle-level `defaultKestrelCert: {name, password?}` pointer on `CertBundleV3`, and the workspace extension looks up the matching cert by name, writes its PFX to `~/.aspnet/dev-certs/https/kestrel-default.pfx`, and sets the env vars via `context.environmentVariableCollection`. The pointer lives on the bundle rather than on a per-cert flag so the workspace's only validation is "does this name match one of the certs"; it never has to enforce "exactly one cert is marked". The `password` field mirrors `userCertificates[].pfxPassword` (single source of truth); the new VS Code option itself carries only the cert name. The env vars apply only to processes launched from VS Code (terminals, debug, tasks), not to `/etc/environment` or `/etc/profile.d` — deliberate, because non-VS-Code processes shouldn't pick up an extension-scoped selection. Only one cert can be the default; the setting must reference a user-managed entry with a private key.

- **No `update-ca-certificates`.** OpenSSL trust is handled via `SSL_CERT_DIR` pointing to a directory with c_rehash hash symlinks. No system CA bundle modification.

- **No openssl binary dependency in the container.** The workspace extension implements c_rehash in pure TypeScript (`src/vscode-workspace-extension/src/util/rehash.ts`) — ASN.1 DER parsing + SHA-1 subject hash computation.

- **No docker exec/cp.** Certificate material is transferred via VS Code's cross-host command routing, making the solution remote-transport-agnostic. Do not introduce Docker-specific commands.

- **Honor `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY`.** Both the UI extension's Linux store (`src/vscode-ui-extension/src/platform/linuxStore.ts`) and the workspace extension (`util/paths.ts`) respect this override, matching the official .NET `CertificateManager` behavior.

- **`SSL_CERT_DIR` must include system CA paths.** Setting it overrides the system default entirely. The devcontainer feature includes all common distro paths (`/etc/ssl/certs`, `/usr/lib/ssl/certs`, `/etc/pki/tls/certs`, `/var/lib/ca-certificates/openssl`) and exposes `sslCertDirs` as an option for user override.

- **The UI extension has no user-facing commands.** It exposes only the internal `getCertMaterial` command. Certificate generation and trust happen automatically when the workspace extension requests material.

- **Container-to-host reverse-sync is off by default per-container.** The `syncContainerCert` feature option defaults to `false` and is the only opt-in toggle. Host-side gating reuses the existing `devcontainerDevCerts.generateDotNetCert` + `devcontainer-dev-certs.autoProvision` settings — there is no separate "accept container certs" host setting (a user disabling managed dev certs via those existing settings implicitly disables container-pushed acceptance too). The host independently re-validates anything pushed via `acceptContainerDevCert`; do not skip the `isValidDevCert` + `validateLocalSans` checks even if the workspace asserts the cert is valid.

- **SAN-local restriction is the default on container-pushed certs.** When accepting a container-pushed cert, `validateLocalSans` rejects SAN entries outside well-known local scopes (loopback, RFC1918 private IP, localhost / docker host names, `*.dev.localhost`, `*.dev.internal`). `devcontainerDevCerts.allowNonLocalContainerCertSans` is the explicit opt-out, surfaced in the consent modal so the user can see exactly which non-local entries they're agreeing to trust.

## Build System

- **Extensions**: TypeScript, esbuild bundler, `@types/vscode ^1.100.0`. The UI extension bundles `@peculiar/x509`, `pkijs`, and `asn1js` as runtime dependencies (all bundled by esbuild into the output).
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

Must match ASP.NET's `CertificateManager` exactly for the auto-generated dev cert:
- Subject: `CN=localhost`
- RSA 2048-bit, SHA-256, PKCS1 padding (default; `generateCertificate` also accepts ECDSA / Ed25519 algorithm overrides for non-dotnet flows)
- 365-day validity
- Extensions: Basic Constraints (critical, not CA), Key Usage (critical, KeyEncipherment|DigitalSignature), EKU (critical, Server Auth), SAN (critical, 7 entries), custom OID `1.3.6.1.4.1.311.84.1.1` with version byte `0x06`, SKI, AKI

User-managed certificates (`devcontainerDevCerts.userCertificates`) are loaded as-is from PEM or PKCS#12 inputs and may use any algorithm Node's `crypto.createPrivateKey` understands (RSA, EC P-256/P-384/P-521, Ed25519, Ed448).
