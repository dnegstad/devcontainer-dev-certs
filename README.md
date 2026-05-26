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

### Suppressing dotnet's first-run certificate auto-generation

When the host is the dev cert source (the default flow — `generateDotNetCert: true` and `syncContainerCert: false`), the devcontainer feature also exports `DOTNET_GENERATE_ASPNET_CERTIFICATE=false` inside the container. Without it, the first `dotnet run` / `dotnet new webapi` / `dotnet build` of an HTTPS-enabled project triggers dotnet's implicit `CertificateManager` flow, which writes a self-signed cert into `~/.dotnet/corefx/cryptography/x509stores/my/` at roughly the same time the remote extension is trying to install OUR cert there. Whichever write lands last wins on disk, but the OS trust + .NET Root-store state may have been driven by the other side — yielding a "partially valid certificate on first run" combo where TLS works for some clients and fails for others.

The override is **gated** on the host being the source: it's only set when `generateDotNetCert: true` AND `syncContainerCert: false`. When `syncContainerCert: true` (the container is the source), dotnet's implicit auto-generation might literally BE the source — typically a `dotnet run` somewhere bootstrapping the cert this feature then pushes to the host — so suppressing it would break the source. When both options are disabled and you've opted out of every managed flow, the override stays off so dotnet behaves normally for users still relying on its own cert provisioning.

The override only affects the IMPLICIT path. Explicit `dotnet dev-certs https` commands always work regardless of the env var; the `syncContainerCert` flow that relies on a container-build step running `dotnet dev-certs https --trust` is unaffected.

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

## Configuration reference

All configurable surfaces in one place. Three categories: the devcontainer feature options (set in `devcontainer.json`), the host VS Code settings (set on your local machine), and the workspace VS Code settings (set inside the Dev Container — and inherited by SSH/WSL remotes). The detailed prose sections that follow this reference cover the workflows these knobs participate in.

A historical-naming note: two prefixes are in use. `devcontainerDevCerts.*` (camelCase) is the newer convention for settings that describe cert *content* the extensions share across the host/container boundary; `devcontainer-dev-certs.*` (hyphenated) is the older convention for extension behavior knobs. Both stay supported; we don't rename them to avoid churning user settings.

### Devcontainer feature options

Set under the feature entry in `devcontainer.json`:

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
| `trustNss` | `false` | Install NSS tools for Chromium/Firefox trust inside the container. |
| `sslCertDirs` | Standard distro paths | System CA directories for `SSL_CERT_DIR`. Override for non-standard base images. |
| `generateDotNetCert` | `true` | Auto-generate the ASP.NET / Aspire compatible HTTPS dev cert. Set to `false` to skip generation (useful when you only want to sync user-managed certs). |
| `syncUserCertificates` | `true` | Per-container opt-out for syncing certs configured in the host `devcontainerDevCerts.userCertificates` VS Code setting. |
| `syncContainerCert` | `false` | **Reverse sync (opt-in).** When the container itself already has a valid ASP.NET dev certificate (e.g. baked into the image with `dotnet dev-certs https`), push it to the host so the host trusts it instead of generating its own. Enabling this also implicitly overrides `generateDotNetCert` for this container — you don't need to set both. See "[Syncing a certificate from the container to the host](#syncing-a-certificate-from-the-container-to-the-host)". |
| `extraCertDestinations` | `""` | Comma-separated list of additional directories to write cert artifacts to. Each entry is `<abs-dir>[=<format>]` where `format` is `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). Every synced cert is written under the directory as `{name}.{pem,key,pfx}` (and/or `{name}-bundle.pem`). Example: `/etc/nginx/certs=pem,/var/myapp`. |
| `installFallbackTools` | `false` | Install the runtime prerequisites (`openssl`, `jq`) the fallback `devcontainer-dev-certs-install` script needs. The script itself is always delivered to `/usr/local/bin/` regardless of this option — set this to `true` only when you intend to invoke it manually (JetBrains / Vim / CLI users) and your base image does not already provide `openssl` and `jq`. See "[Manual / non-VS Code use](#manual--non-vs-code-use)". |

### Host VS Code settings

Set in your host VS Code's user or workspace settings. Provided by the **Dev Container Dev Certificates (Host)** extension (`dnegstad.devcontainer-dev-certs-host`).

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoProvision` | `true` | Allow certificate provisioning when the workspace extension requests one. On first use, a consent prompt explains what will happen before any certificates are generated. Set to `false` to disable provisioning entirely (host-generation AND acceptance of container-pushed certs). |
| `devcontainerDevCerts.generateDotNetCert` | `true` | Auto-generate the ASP.NET / Aspire compatible HTTPS dev cert and trust it in the host OS store. When `false`, user-managed certificates (if any) are still synced, but no managed dev cert lives on the host — this also implicitly disables acceptance of container-pushed certs (a container push would land one in the same trust store the user opted out of). |
| `devcontainerDevCerts.userCertificates` | `[]` | Host-managed certificates to sync from the host into dev containers. See "[User-managed certificates](#user-managed-certificates)" for the per-entry schema (`name`, `pfxPath`/`pemCertPath`, etc.). User-managed certs are never added to the host OS trust store. |
| `devcontainerDevCerts.installUserCertsToDotNetStore` | `false` | When `true`, also copies every entry from `userCertificates` into the container's .NET X509Store. **Security note:** the on-disk PFX there is passwordless (Linux's `StoreName.My` enumeration can't accept per-file passwords), so opting in strips your user cert's password on the in-container copy. Per-entry exemption via `excludeFromDotNetStore: true`. The auto-generated dotnet-dev cert is always installed to the store regardless. |
| `devcontainerDevCerts.defaultKestrelCertificate` | `""` | Name of a `userCertificates` entry to use as the default Kestrel certificate inside dev containers. When set, the remote extension writes that cert's PFX to `~/.aspnet/dev-certs/https/kestrel-default.pfx` and exports `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` to processes launched from VS Code (terminals, debug, tasks). Leave empty to opt out — Kestrel will still discover the auto-generated dev cert via X509Store. See "[Default Kestrel certificate (opt-in)](#default-kestrel-certificate-opt-in)" for scope and caveats. |
| `devcontainerDevCerts.allowNonLocalContainerCertSans` | `false` | When accepting a Dev Container-managed dev certificate (via `syncContainerCert`), override the default SAN restriction that limits trusted certificates to localhost / loopback / private IPs / docker host names. Only enable when you fully understand the SAN entries the container will push. Has no effect when `generateDotNetCert` or `autoProvision` is `false`. |

### Workspace (Remote) VS Code settings

Set in your workspace settings or user settings inside the Dev Container / remote. Provided by the **Dev Container Dev Certificates (Remote)** extension (`dnegstad.devcontainer-dev-certs-remote`).

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoInject` | `true` | Automatically inject and configure the dev cert when a remote session starts. Set to `false` to require manual invocation via the "Dev Certs: Inject Certificate into Remote" command. |
| `devcontainer-dev-certs.sslCertDirs` | Standard distro paths | Colon-separated system CA certificate directories to include in `SSL_CERT_DIR` alongside the dev-certs trust directory. Used when the Dev Container feature isn't present (e.g. SSH remoting, WSL); the feature's own `sslCertDirs` option takes precedence inside containers built with the feature. |
| `devcontainer-dev-certs.ensureSslCertDir` | `true` | Ensure `SSL_CERT_DIR` is configured in the remote environment when the Dev Container feature hasn't set it. |
| `devcontainer-dev-certs.warnOnStaleDevCerts` | `true` | Show a warning when multiple dev certificates are detected in this Dev Container's .NET certificate stores after install — alongside the extension-managed certificate. Pairs with the "Dev Certs: Clean Up Other Dev Certificates in Dev Container" command. |

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

By default, Kestrel discovers the auto-generated dev cert through its X509Store fallback — no environment variables are set, and `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` remain untouched. If you'd like to pin a *custom* user certificate as Kestrel's default instead, add the following to your VS Code user `settings.json`:

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

**Scope.** Because the selection lives in a VS Code setting, the env vars only apply to processes launched from VS Code. The remote extension wires them up two ways: `EnvironmentVariableCollection` covers integrated terminals (and the `tasks.json` invocations that run in them), and a `coreclr` `DebugConfigurationProvider` injects the same two vars into resolved debug configurations so F5 launches via the C# Dev Kit (and Aspire AppHost, which currently routes through `coreclr`) pick them up too. When both a launch config and the selection set the Path/Password keys, the selection wins — `defaultKestrelCertificate` is the higher-level abstraction and a stale `launchSettings.json` entry shouldn't silently override it. Processes started outside VS Code (a stray `docker exec`, an SSH session into the container without VS Code attached) won't see the vars — that's intentional. For those cases keep using the X509Store fallback (or set the env vars yourself in `devcontainer.json` `containerEnv`).

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

## Syncing a certificate from the container to the host

By default the host is the source of truth: the host extension generates the ASP.NET dev cert, trusts it locally, then pushes it into every dev container that asks for it. That keeps the OS-level trust prompt count low — you confirm trust once on the host and every container reuses the same cert.

Some projects flip that around: the container's own build step (or a `dotnet dev-certs https` invocation baked into the image) is the canonical generator of the cert. In that case you can opt the container in to pushing its dev cert *to* the host, so the host trusts the container's cert instead of generating its own.

To enable, set the feature option on the container:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {
            "syncContainerCert": true
        }
    }
}
```

The host side is gated by the same VS Code settings that gate the normal host-generation flow: `devcontainerDevCerts.generateDotNetCert` (default `true`) and `devcontainer-dev-certs.autoProvision` (default `true`). If you've disabled either — because you don't want any extension-managed dev cert on your host — a container's push is rejected with the same intent. No separate "accept container certs" toggle: the user-level question "is this host willing to trust a managed ASP.NET dev cert?" has one answer, regardless of where the cert came from.

With `syncContainerCert` enabled:

- The workspace extension scans `~/.dotnet/corefx/cryptography/x509stores/my/*.pfx` inside the container, classifies each candidate the same way the host classifies its own platform stores (CN=localhost, OID v4+, key + cert match, valid notBefore/notAfter), and picks the best (highest dev-cert version, then latest `notAfter`). If multiple valid candidates are present, a log line in the **Dev Container Dev Certs (Remote)** output channel lists every thumbprint that was considered.
- If a usable cert is found, the workspace extension pushes **just the public certificate** (PEM-encoded) to the host via a new IPC command. The private key never leaves the container — Kestrel keeps using its own copy of the key inside the container, and the host's job in this flow is to act purely as a trust anchor (so forwarded HTTPS ports and browser-side validation work on the host) rather than as a cert distribution point. If no usable cert is found, the push is a no-op — there's no fallback to host generation.
- **`syncContainerCert: true` overrides the `generateDotNetCert` feature option for this container.** You don't need to also set `generateDotNetCert: false` to opt out of host generation — when the container is pushing its own cert to the host, the workspace extension drops the dotnet dev cert from its pull-from-host request automatically. (Otherwise the container would end up with both its own cert AND a different host-generated cert in its .NET store.) User-managed certificates configured via `userCertificates` are unaffected — those still flow normally.
- The host extension independently re-validates the cert (same `isValidDevCert` rules; matches dev-cert OID, version, validity window). It then restricts SAN entries to local-only scopes by default — `localhost`, `*.localhost`, `*.dev.localhost`, `*.dev.internal`, `host.docker.internal`, `host.containers.internal`, IPv4 loopback / RFC1918 / link-local, IPv6 loopback / unique-local / link-local. A cert with SAN entries outside that set is rejected.
- If validation passes, the host shows a one-time modal consent prompt before adding the cert to the platform trust store. The OS-level trust prompt (macOS keychain dialog, Windows MMC dialog) fires for each unique cert as usual. The cert lands in the OS trust surfaces only — the .NET Root store on Linux, the login keychain's policy settings on macOS, CurrentUser/Root on Windows — never in `CurrentUser/My`, the keychain's identity slot, or the .NET store's `my/` directory. The host has nothing keyed by this thumbprint that contains a private key.

To allow SAN entries that aren't local (rare; security-sensitive — the cert will be trusted by your host browser for the listed names), opt in explicitly:

```json
{
    "devcontainerDevCerts.allowNonLocalContainerCertSans": true
}
```

When this is on, non-local SAN entries are shown in the consent modal so you can see exactly what you're agreeing to trust.

Pushes from a Dev Container without the matching feature option are ignored — the host setting on its own doesn't do anything until a container actively pushes. Host trust prompts fire per unique thumbprint, so opening multiple containers with different container-generated certs will accumulate trust prompts; this is intentional and is why the option isn't on by default.

## Manual / non-VS Code use

The companion-extension pattern is VS Code-specific, but the underlying container-side machinery isn't. JetBrains, Vim, raw CLI, and CI users can drive the same trust state through a small shell tool the feature installs into the container.

For an end-to-end walkthrough — generating the cert on the host, mounting it in, wiring `postStartCommand` — see [`examples/manual-setup/`](examples/manual-setup/). The summary here is the reference.

### `ddc` — the host-side CLI

[`ddc`](src/cli/README.md) is the host-side CLI that produces the cert files and `bundle.json` the in-container installer below consumes. One command does generation, host trust, and bundle emission:

```bash
mkdir -p ~/.dev-certs
ddc generate --out-dir ~/.dev-certs
```

It also exposes `ddc inspect` (cert details), `ddc bundle` (wrap an existing cert into a bundle.json), `ddc trust` (host-trust an existing cert), and `ddc doctor` (read-only diagnostics). See [`src/cli/README.md`](src/cli/README.md) for the full reference. Doing the steps by hand is documented in [`examples/manual-setup/`](examples/manual-setup/) for situations where the CLI isn't available.

### The fallback installer

The feature delivers `devcontainer-dev-certs-install` to `/usr/local/bin/` during install. It writes to the same canonical paths the VS Code workspace extension uses — `~/.dotnet/corefx/cryptography/x509stores/{my,root}` and `~/.aspnet/dev-certs/trust/` (with c_rehash symlinks) — so Kestrel's `X509Store` fallback and OpenSSL clients discover certs installed this way exactly as they would extension-installed ones.

Three invocation forms:

```bash
# Single cert (legacy positional form)
devcontainer-dev-certs-install /path/to/cert.pfx /path/to/cert.pem <sha1-fingerprint>

# Multi-cert + extra destinations (preferred)
devcontainer-dev-certs-install --bundle-json /path/to/bundle.json

# Read-only diagnostics
devcontainer-dev-certs-install --doctor
```

The bundle form requires `openssl` and `jq`; the positional form needs only `openssl`. Set the feature option `installFallbackTools: true` to have the feature install them when they're missing from the base image.

### Bundle JSON

A bundle describes one or more certs and (optionally) extra destinations. The full schema lives at [`schema/bundle.schema.json`](schema/bundle.schema.json); reference it from your bundle file to get autocomplete and validation in any editor that honors JSON Schema:

```jsonc
{
    "$schema": "https://raw.githubusercontent.com/dnegstad/devcontainer-dev-certs/main/schema/bundle.schema.json",
    "certs": [
        {
            "name": "aspnetcore-dev",
            "kind": "dotnet-dev",
            "thumbprint": "ABCDEF...",
            "pfxPath": "/host-dev-certs/aspnetcore-dev.pfx",
            "pemPath": "/host-dev-certs/aspnetcore-dev.pem",
            "pemKeyPath": "/host-dev-certs/aspnetcore-dev.key",
            "trustInContainer": true
        }
    ],
    "extraDestinations": [
        { "path": "/etc/nginx/certs", "format": "pem" }
    ]
}
```

Key fields:

| Field | Notes |
|-------|-------|
| `certs[].name` | Filename stem in extra destinations and (for user certs) in the OpenSSL trust dir. `[A-Za-z0-9._-]`, 1-64 chars. |
| `certs[].thumbprint` | SHA-1 fingerprint, hex, no separators. Used as the `.pfx` filename in the .NET store where Kestrel discovers it. |
| `certs[].pemPath` | Required. PEM-encoded cert. |
| `certs[].pfxPath` | PFX with private key. Required if you want Kestrel to serve TLS with this cert. |
| `certs[].pemKeyPath` | Private key in PEM form. Optional; needed only for `key` / `pem-bundle` extra destination formats. |
| `certs[].rootPfxPath` | Public-cert-only PFX for the .NET Root store. Synthesized via `openssl pkcs12 -nokeys` when omitted. |
| `certs[].trustInContainer` | Default `true`. Install into the Root store + OpenSSL trust dir, not just My. |
| `certs[].kind` | `dotnet-dev` uses the historic `aspnetcore-localhost-{thumbprint}.pem` filename; `user` (default) uses `{name}.pem`. |
| `extraDestinations[].path` | Absolute directory to write artifacts under. |
| `extraDestinations[].format` | `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). |

### Lifecycle: invoking the installer from `devcontainer.json`

Use `postStartCommand` (not `postCreateCommand`) so the install re-runs on every container start. That way regenerating the cert on the host takes effect on the next container start without a rebuild:

```jsonc
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {
            "installFallbackTools": true
        }
    },
    "mounts": [
        "source=${localEnv:HOME}/.dev-certs,target=/host-dev-certs,type=bind,readonly"
    ],
    "postStartCommand": "devcontainer-dev-certs-install --bundle-json /host-dev-certs/bundle.json || true"
}
```

The `|| true` keeps a missing or malformed bundle from blocking container startup.

### Path hints for integrations

The feature exports a handful of `DEVCONTAINER_DEV_CERTS_*` env vars so integration scripts don't have to hardcode the canonical paths. They're available in login shells (via `/etc/profile.d/`) and PAM-based sessions (via `/etc/environment`):

| Variable | Value |
|----------|-------|
| `DEVCONTAINER_DEV_CERTS_INSTALL_BIN` | `/usr/local/bin/devcontainer-dev-certs-install` |
| `DEVCONTAINER_DEV_CERTS_DOTNET_STORE_DIR` | `~/.dotnet/corefx/cryptography/x509stores/my` |
| `DEVCONTAINER_DEV_CERTS_DOTNET_ROOT_STORE_DIR` | `~/.dotnet/corefx/cryptography/x509stores/root` |
| `DEVCONTAINER_DEV_CERTS_TRUST_DIR` | `~/.aspnet/dev-certs/trust` |
| `DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET` | Mirror of the `generateDotNetCert` feature option. |
| `DEVCONTAINER_DEV_CERTS_SYNC_USER` | Mirror of the `syncUserCertificates` feature option. |
| `DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER` | Mirror of the `syncContainerCert` feature option. |
| `DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS` | Mirror of the `extraCertDestinations` feature option. |

### Verifying with `--doctor`

`devcontainer-dev-certs-install --doctor` runs read-only checks across the trust infrastructure: prerequisite presence, trust-directory existence and writability, `SSL_CERT_DIR` state, the gating of `DOTNET_GENERATE_ASPNET_CERTIFICATE`, per-store cert listings (subject / `notAfter` / SHA-1), c_rehash symlink integrity, and expired-cert / multiple-dev-cert detection. Exits non-zero only when something is demonstrably broken, so it's safe to chain into CI:

```bash
devcontainer-dev-certs-install --bundle-json /host-dev-certs/bundle.json \
    && devcontainer-dev-certs-install --doctor
```

### What's still VS Code-only

- **Host-side cert generation and trust.** Use `dotnet dev-certs https --trust` (or your platform's equivalent) and export the PFX / PEM into your mounted host directory. The host extension's editor-agnostic generator is on the roadmap.
- **`defaultKestrelCertificate`.** Lives in a VS Code setting and is delivered via `EnvironmentVariableCollection`. Set `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` yourself in `devcontainer.json` `containerEnv` if you need this outside VS Code.
- **Reverse sync (`syncContainerCert`).** Needs a privileged host-side process with a consent UI; the script can't perform host trust.

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
- **Full automation is VS Code-only.** The host extension's certificate generation, OS trust, and cross-host routing rely on VS Code APIs. JetBrains, Vim, and CLI users can drive the same container-side trust state through the `devcontainer-dev-certs-install` fallback installer the feature ships at `/usr/local/bin/` — see "[Manual / non-VS Code use](#manual--non-vs-code-use)" — but cert generation and host trust are still on the user.
- **Host trust requires user interaction.** On Windows, trusting the auto-generated dev cert triggers a system dialog. On macOS, the keychain may prompt for a password. This only happens once and only for the .NET dev cert — user-managed certs are never added to the host OS trust store.

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Windows | x64, ARM64 |
| macOS | x64, ARM64 |
| Linux (glibc) | x64, ARM64 |
| Linux (musl/Alpine) | x64 |
