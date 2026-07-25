# Dev Container Dev Certificates

Automatic HTTPS development certificate management for .NET or Aspire projects in Dev Containers and VS Code remote environments.

## What This Does

When developing .NET applications or Aspire orchestration projects inside Dev Containers, you need HTTPS certificates that are trusted on both sides: the host (so browsers accept forwarded ports) and the container (so servers can terminate HTTPS and inter-service calls succeed). This project automates the entire process.

Add the Dev Container feature to your `devcontainer.json` and everything works automatically:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {}
    }
}
```

No `dotnet dev-certs` commands, no manual PFX exports, no environment variable configuration.

## Contents

- [Getting Started](#getting-started) — install it and confirm it worked
- [How It Works](#how-it-works) — the three components
- [Configuration reference](#configuration-reference) — every option, setting, command, and environment variable
- [User-managed certificates](#user-managed-certificates) — sync your own certs (corporate CAs, wildcards)
- [Extra destinations](#extra-destinations) — write certs for nginx, Java, and other non-.NET workloads
- [Syncing a certificate from the container to the host](#syncing-a-certificate-from-the-container-to-the-host) — reverse sync (opt-in)
- [Troubleshooting](#troubleshooting) — logs and the common failure modes
- [Known issues](#known-issues)
- [Non-VS Code editors](#non-vs-code-editors) — the manual fallback script
- [Limitations](#limitations) · [Supported Platforms](#supported-platforms)
- [Development](#development) · [Verifying Release Provenance](#verifying-release-provenance)

## Getting Started

### Prerequisites

- VS Code 1.100 or later
- The [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
- Docker or a compatible container runtime
- A host OS on the [supported platform list](#supported-platforms)

### Add the Feature

Add the Dev Container feature to your project's `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {}
    }
}
```

Then rebuild or reopen your project in the Dev Container. The feature declares both companion extensions, so VS Code installs the remote extension inside the container automatically. The host extension is installed on your local VS Code automatically as well; if it isn't, the remote extension prompts you with an **Install Host Extension** button on first use.

On first use:

1. The host extension shows a one-time consent prompt, then generates a development certificate and trusts it in your OS certificate store. On Windows this triggers a system dialog; on macOS the keychain may prompt for a password.
2. The remote extension receives the certificate and installs it in the container's .NET X509 store and OpenSSL trust directory.
3. ASP.NET, Aspire, and CLI tools like `curl` and `wget` trust the certificate automatically — no environment variables or manual configuration needed.
4. Your host browser trusts the certificate on forwarded ports.

### Verify it worked

Inside the container, three checks confirm the certificate landed where it needs to be:

```bash
# 1. The .NET X509 store — Kestrel reads the cert from here
ls ~/.dotnet/corefx/cryptography/x509stores/my/
#    expect: {thumbprint}.pfx

# 2. The OpenSSL trust directory — curl/wget read from here
ls ~/.aspnet/dev-certs/trust/
#    expect: aspnetcore-localhost-{thumbprint}.pem plus a {hash}.0 symlink

# 3. If the .NET SDK is installed in the container
dotnet dev-certs https --check
#    expect: "A valid HTTPS certificate is already present."
```

Then start your app and call it over HTTPS from inside the container **without** `-k` / `--insecure`:

```bash
curl https://localhost:<port>
```

On the host, open the forwarded port in your browser — it should show a padlock with no warning. (On Linux hosts, browsers need one extra step; see [Linux hosts: browser trust](#linux-hosts-browser-trust).)

If any of these fail, see [Troubleshooting](#troubleshooting).

### Installing the Host Extension Manually (Optional)

You normally don't need to do this — the feature handles it. If you'd rather install the host extension (`dnegstad.devcontainer-dev-certs-host`) ahead of time:

- **VS Code Marketplace:** [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host)
- **Extensions view:** search for `dnegstad.devcontainer-dev-certs-host`
- **CLI:** `code --install-extension dnegstad.devcontainer-dev-certs-host`

The remote extension (`dnegstad.devcontainer-dev-certs-remote`) runs inside the container and is installed by the feature. Don't install it on your local VS Code — it has no effect there.

### Linux hosts: browser trust

On Windows and macOS, trusting the certificate in the OS store is enough for browsers — you can skip this section.

On Linux, Firefox and Chromium use [NSS](https://firefox-source-docs.mozilla.org/security/nss/) for certificate trust and do **not** read OpenSSL trust directories or the .NET root store. Without this step, forwarded ports still show a certificate warning in the browser even though `curl` works fine.

Run **Dev Certs: Trust Certificate in Browsers** from the Command Palette on the host. It:

- Checks for `certutil` (from `libnss3-tools`) on the `PATH`
- If available, trusts the cert in Chromium (`~/.pki/nssdb/`) and in your Firefox profile NSS databases
- If `certutil` is missing or no browser databases are found, shows the certificate path so you can import it manually

To install `certutil`:

| Distro | Command |
|--------|---------|
| Debian / Ubuntu | `sudo apt install libnss3-tools` |
| Fedora / RHEL | `sudo dnf install nss-tools` |
| Arch | `sudo pacman -S nss` |

To import manually in Firefox: **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**, then select the PEM file from `~/.aspnet/dev-certs/trust/`.

Restart the browser after trusting so it picks up the updated NSS database.

For browser trust *inside* the container (rarely needed — usually only when running a headless browser there), set the [`trustNss`](#dev-container-feature-options) feature option.

## How It Works

The solution has three components that work together:

1. **Dev Container Feature** sets up the container's trust infrastructure: creates the .NET X509 store and OpenSSL trust directories, configures `SSL_CERT_DIR`, and requests installation of the two companion VS Code extensions.

2. **Host Extension** (`extensionKind: ["ui"]`) runs on your local machine. It generates certificates identical to `dotnet dev-certs https` (same OID marker, same SAN entries, same key parameters) using Node's built-in `crypto` plus `@peculiar/x509` and `pkijs` for X.509 / PKCS#12 — supporting RSA, ECDSA, and Ed25519 keys. On first use, it generates a cert and trusts it in the host OS certificate store. It then serves the certificate material to the remote side via VS Code's cross-host command routing.

3. **Remote Extension** (`extensionKind: ["workspace"]`) runs inside the container. On activation, it requests certificate material from the host extension, decodes it, and places it in two locations:
   - The .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) where Kestrel discovers it automatically via its `GetDevelopmentCertificateFromStore()` fallback
   - An OpenSSL trust directory (`~/.aspnet/dev-certs/trust/`) with hash symlinks (c_rehash, implemented in pure TypeScript) so `curl`, `wget`, and other OpenSSL-based tools trust it

The two extensions communicate using VS Code's cross-host `executeCommand()` routing. The remote extension detects whether the host extension is installed and prompts to install it if missing. This architecture is transport-agnostic — it works for Dev Containers today and can support SSH remoting, WSL, or any future VS Code remote backend.

## Configuration reference

All configurable surfaces in one place. Four categories: the Dev Container feature options (set in `devcontainer.json`), the host VS Code settings (set on your local machine), the workspace VS Code settings (set inside the Dev Container — and inherited by SSH/WSL remotes), and the commands both extensions contribute. The prose sections that follow this reference cover the workflows these knobs participate in.

**Two settings prefixes are in use.** `devcontainerDevCerts.*` (camelCase) is the newer convention for settings that describe cert *content* the extensions share across the host/container boundary; `devcontainer-dev-certs.*` (hyphenated) is the older convention for extension behavior knobs. Both stay supported; we don't rename them to avoid churning user settings.

**One name, two scopes.** `generateDotNetCert` exists both as a *feature option* (container-side: "pull the host's dev cert into this container") and as a *host VS Code setting* `devcontainerDevCerts.generateDotNetCert` (host-side: "generate and trust a managed dev cert on this machine at all"). They are separate knobs at different layers — turning off the host setting means no managed dev cert exists anywhere; turning off the feature option means this one container doesn't receive it. Check which table you're reading.

### Dev Container feature options

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
| `trustNss` | `false` | Install NSS tools for Chromium/Firefox trust inside the container. For browser trust on a Linux *host*, see "[Linux hosts: browser trust](#linux-hosts-browser-trust)" instead. |
| `sslCertDirs` | Standard distro paths | System CA directories for `SSL_CERT_DIR`. Override for non-standard base images. |
| `pruneMissingCertDirs` | `true` | Filter out non-existent directories from `sslCertDirs` before writing `SSL_CERT_DIR` (some TLS stacks error on a missing entry). Set to `false` to use `sslCertDirs` verbatim — e.g. for a directory created after install but before it's needed. |
| `generateDotNetCert` | `true` | Pull the host-generated ASP.NET / Aspire compatible HTTPS dev cert into this container. Set to `false` to skip it (useful when this container only needs user-managed certs). Distinct from the host setting of the same name — see the note above. |
| `syncUserCertificates` | `true` | Per-container opt-out for syncing certs configured in the host `devcontainerDevCerts.userCertificates` VS Code setting. |
| `syncContainerCert` | `false` | **Reverse sync (opt-in).** When the container itself already has a valid ASP.NET dev certificate (e.g. baked into the image with `dotnet dev-certs https`), push it to the host so the host trusts it instead of generating its own. Enabling this also implicitly overrides `generateDotNetCert` for this container — you don't need to set both. See "[Syncing a certificate from the container to the host](#syncing-a-certificate-from-the-container-to-the-host)". |
| `extraCertDestinations` | `""` | Comma-separated list of additional directories to write cert artifacts to. Each entry is `<abs-dir>[=<format>]` where `format` is `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). Every synced cert is written under the directory as `{name}.{pem,key,pfx}` (and/or `{name}-bundle.pem`). Example: `/etc/nginx/certs=pem,/var/myapp`. See "[Extra destinations](#extra-destinations)". |

### Host VS Code settings

Set in your host VS Code's user or workspace settings. Provided by the **Dev Container Dev Certificates (Host)** extension (`dnegstad.devcontainer-dev-certs-host`).

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoProvision` | `true` | Allow certificate provisioning when the workspace extension requests one. On first use, a consent prompt explains what will happen before any certificates are generated. Set to `false` to disable provisioning entirely (host-generation AND acceptance of container-pushed certs). |
| `devcontainerDevCerts.generateDotNetCert` | `true` | Auto-generate the ASP.NET / Aspire compatible HTTPS dev cert and trust it in the host OS store. When `false`, user-managed certificates (if any) are still synced, but no managed dev cert lives on the host — this also implicitly disables acceptance of container-pushed certs (a container push would land one in the same trust store the user opted out of). |
| `devcontainerDevCerts.userCertificates` | `[]` | Host-managed certificates to sync from the host into Dev Containers. See "[User-managed certificates](#user-managed-certificates)" for the per-entry field table. User-managed certs are never added to the host OS trust store. |
| `devcontainerDevCerts.installUserCertsToDotNetStore` | `false` | When `true`, also copies every entry from `userCertificates` into the container's .NET X509Store. **Security note:** the on-disk PFX there is passwordless (Linux's `StoreName.My` enumeration can't accept per-file passwords), so opting in strips your user cert's password on the in-container copy. Per-entry exemption via `excludeFromDotNetStore: true`. The auto-generated dotnet-dev cert is always installed to the store regardless. |
| `devcontainerDevCerts.defaultKestrelCertificate` | `""` | Name of a `userCertificates` entry to use as the default Kestrel certificate inside Dev Containers. When set, the remote extension writes that cert's PFX to `~/.aspnet/dev-certs/https/kestrel-default.pfx` and exports `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` to processes launched from VS Code (terminals, debug, tasks). Leave empty to opt out — Kestrel will still discover the auto-generated dev cert via X509Store. See "[Default Kestrel certificate (opt-in)](#default-kestrel-certificate-opt-in)" for scope and caveats. |
| `devcontainerDevCerts.allowNonLocalContainerCertSans` | `false` | When accepting a Dev Container-managed dev certificate (via `syncContainerCert`), override the default SAN restriction that limits trusted certificates to localhost / loopback / private IPs / docker host names. Only enable when you fully understand the SAN entries the container will push. Has no effect when `generateDotNetCert` or `autoProvision` is `false`. |

### Workspace (Remote) VS Code settings

Set in your workspace settings or user settings inside the Dev Container / remote. Provided by the **Dev Container Dev Certificates (Remote)** extension (`dnegstad.devcontainer-dev-certs-remote`).

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoInject` | `true` | Automatically inject and configure the dev cert when a remote session starts. Set to `false` to require manual invocation via the "Dev Certs: Inject Certificate into Remote" command. |
| `devcontainer-dev-certs.warnOnStaleDevCerts` | `true` | Show a warning when multiple dev certificates are detected in this Dev Container's .NET certificate stores after install — alongside the extension-managed certificate. Pairs with the "Dev Certs: Clean Up Other Dev Certificates in Dev Container" command. |

### Commands

All three are available from the Command Palette (`F1`). The host command runs on your local machine; the remote commands run inside the Dev Container.

| Command | Runs on | Command ID | Description |
|---------|---------|------------|-------------|
| **Dev Certs: Trust Certificate in Browsers** | Host | `devcontainer-dev-certs.trustInBrowsers` | Trust the dev cert in Firefox / Chromium NSS databases. Linux hosts only — on Windows and macOS browser trust follows the OS store automatically. See "[Linux hosts: browser trust](#linux-hosts-browser-trust)". |
| **Dev Certs: Inject Certificate into Remote** | Remote | `devcontainer-dev-certs.injectCert` | Re-run the certificate injection flow manually. Normally automatic on activation; needed when `autoInject` is `false`, or to retry after a failure. |
| **Dev Certs: Clean Up Other Dev Certificates in Dev Container** | Remote | `devcontainer-dev-certs.cleanupStaleDevCerts` | Remove dev cert artifacts in the container's .NET stores that aren't the extension-managed one, then rehash the OpenSSL trust directory. Refuses to run when no managed dev cert is known, so it can't delete every dev cert on disk. |

### Environment variables

The feature writes these into the container at build time (via `/etc/profile.d` and the container environment), so they apply to VS Code terminals, tasks, debug sessions, and `docker exec` alike:

| Variable | Value | Set when |
|----------|-------|----------|
| `SSL_CERT_DIR` | `$HOME/.aspnet/dev-certs/trust:` + the resolved `sslCertDirs` | Always |
| `DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET` | The `generateDotNetCert` option | Always |
| `DEVCONTAINER_DEV_CERTS_SYNC_USER` | The `syncUserCertificates` option | Always |
| `DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER` | The `syncContainerCert` option | Always |
| `DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS` | The `extraCertDestinations` option | Always |
| `DOTNET_GENERATE_ASPNET_CERTIFICATE` | `false` | Only when `generateDotNetCert: true` AND `syncContainerCert: false` — see below |

The remote extension sets two more at runtime, and honors one:

| Variable | Notes |
|----------|-------|
| `ASPNETCORE_Kestrel__Certificates__Default__Path` / `__Password` | Set only when `devcontainerDevCerts.defaultKestrelCertificate` names a user cert, and only for processes launched from VS Code. See "[Default Kestrel certificate (opt-in)](#default-kestrel-certificate-opt-in)". |
| `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY` | *Honored, not set.* Overrides the default OpenSSL trust directory (`~/.aspnet/dev-certs/trust/`), matching the official .NET `CertificateManager` behavior. |

#### Why `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`

When the host is the dev cert source (the default flow), the first `dotnet run` / `dotnet new webapi` / `dotnet build` of an HTTPS-enabled project would otherwise trigger dotnet's implicit `CertificateManager` flow, writing a self-signed cert into `~/.dotnet/corefx/cryptography/x509stores/my/` at roughly the same time the remote extension is installing ours there. Whichever write lands last wins on disk, but the OS trust and .NET root-store state may have been driven by the other side — yielding a "partially valid certificate on first run" state where TLS works for some clients and fails for others.

The override is **gated** on the host being the source. When `syncContainerCert: true`, dotnet's implicit auto-generation might literally *be* the source — typically a `dotnet run` bootstrapping the cert this feature then pushes to the host — so suppressing it would break the source. When both options are disabled and you've opted out of every managed flow, the override stays off so dotnet behaves normally.

The override only affects the *implicit* path. Explicit `dotnet dev-certs https` commands always work regardless of the environment variable, so a `syncContainerCert` flow that relies on a container-build step running `dotnet dev-certs https --trust` is unaffected.

## User-managed certificates

The host extension can sync arbitrary host-side certificates into your Dev Containers alongside (or instead of) the auto-generated dev cert. Configure them in your host user or workspace VS Code settings:

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

### Per-entry fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Filename stem used inside the container (`{name}.pem`, etc.) and on the host's temp export directory. 1–64 chars from `[A-Za-z0-9._-]`, no leading dot, not `.` or `..`. Entries with an invalid name are rejected with an error notification and skipped. |
| `pfxPath` | one of | Absolute path on the host to a PFX/PKCS#12 file. |
| `pfxPassword` | optional | Password for the PFX (or, for `pemCertPath` sources, the password used when synthesizing the `.pfx` for extra destinations). |
| `pemCertPath` | one of | Absolute path on the host to a PEM-encoded certificate. |
| `pemKeyPath` | optional | Absolute path on the host to a PEM-encoded private key. Omit for CA-only entries. |
| `trustInContainer` | optional, default `true` | Plant the cert in the container's OpenSSL trust directory and .NET root store, so tools inside the container trust it. Set to `false` to sync the cert files without making the container trust the issuer. |
| `excludeFromDotNetStore` | optional, default `false` | When `installUserCertsToDotNetStore` is on globally, exempt this single cert from the `my/` write (avoids the password-stripping copy for sensitive entries). No effect when the global setting is `false`. |

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

To exempt an individual entry from the global setting (e.g., keep most of your user certs in the store but carve out one sensitive cert), add `"excludeFromDotNetStore": true` to that `userCertificates` entry.

The auto-generated dotnet-dev cert is always installed to the store regardless of these settings — it's intrinsically passwordless and the store IS its canonical location.

### Default Kestrel certificate (opt-in)

By default, Kestrel discovers the auto-generated dev cert through its X509Store fallback — no environment variables are set, and `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` remain untouched. If you'd like to pin a *custom* user certificate as Kestrel's default instead, add the following to your host VS Code user `settings.json`:

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

By default the host is the source of truth: the host extension generates the ASP.NET dev cert, trusts it locally, then pushes it into every Dev Container that asks for it. That keeps the OS-level trust prompt count low — you confirm trust once on the host and every container reuses the same cert.

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
- If validation passes, the host shows a one-time modal consent prompt before adding the cert to the platform trust store. The OS-level trust prompt (macOS keychain dialog, Windows MMC dialog) fires for each unique cert as usual. The cert lands in the OS trust surfaces only — the .NET root store on Linux, the login keychain's policy settings on macOS, CurrentUser/Root on Windows — never in `CurrentUser/My`, the keychain's identity slot, or the .NET store's `my/` directory. The host has nothing keyed by this thumbprint that contains a private key.

To allow SAN entries that aren't local (rare; security-sensitive — the cert will be trusted by your host browser for the listed names), opt in explicitly:

```json
{
    "devcontainerDevCerts.allowNonLocalContainerCertSans": true
}
```

When this is on, non-local SAN entries are shown in the consent modal so you can see exactly what you're agreeing to trust.

Pushes from a Dev Container without the matching feature option are ignored — the host setting on its own doesn't do anything until a container actively pushes. Host trust prompts fire per unique thumbprint, so opening multiple containers with different container-generated certs will accumulate trust prompts; this is intentional and is why the option isn't on by default.

## Troubleshooting

### Start with the logs

Both extensions log to output channels (**View → Output**, then pick the channel from the dropdown):

| Channel | Where to look for it |
|---------|----------------------|
| **Dev Container Dev Certs** | Your local VS Code window — generation, host trust, and what was served to the container |
| **Dev Container Dev Certs (Remote)** | The Dev Container window — what was received, where each file was written, thumbprints considered |

Failure notifications from the remote extension usually name which side to check. A failure to *obtain* certificates points at the host channel; a failure to *install* them points at the remote channel.

### Nothing happened at all

Work through these in order:

1. **Is the host extension installed?** The remote extension shows an **Install Host Extension** prompt when it can't reach the host side. If you dismissed it, install `dnegstad.devcontainer-dev-certs-host` on your local VS Code and reload.
2. **Is auto-injection on?** If `devcontainer-dev-certs.autoInject` is `false`, run **Dev Certs: Inject Certificate into Remote** from the Command Palette.
3. **Is provisioning on?** If `devcontainer-dev-certs.autoProvision` or `devcontainerDevCerts.generateDotNetCert` is `false` on the host, no managed dev cert is generated or served.
4. **Did the feature actually install?** Check `echo $SSL_CERT_DIR` in a container terminal — it should start with `~/.aspnet/dev-certs/trust`. If it's empty, the feature didn't run; rebuild the container.

Running **Dev Certs: Inject Certificate into Remote** is the standard way to retry any of this without rebuilding.

### The browser still warns on a forwarded port

- **Linux host:** browsers use NSS, not the OS/OpenSSL trust stores. Run **Dev Certs: Trust Certificate in Browsers** and restart the browser — see "[Linux hosts: browser trust](#linux-hosts-browser-trust)".
- **Windows / macOS:** confirm you accepted the OS trust dialog on first use. If you dismissed it, the cert exists but isn't trusted — reload the window to re-trigger the flow.
- **Any host:** if the certificate was regenerated (expiry, a new container-pushed cert), browsers may hold the old one until restarted.

### `curl` / `wget` fails inside the container

Check that the trust directory has both the PEM and its hash symlink:

```bash
ls -l ~/.aspnet/dev-certs/trust/
echo $SSL_CERT_DIR
```

You should see `aspnetcore-localhost-{thumbprint}.pem` and a `{hash}.0` symlink pointing at it, and `SSL_CERT_DIR` should include that directory. If the directory is populated but `SSL_CERT_DIR` doesn't reference it, the shell probably didn't source `/etc/profile.d` — open a fresh VS Code terminal.

If a *specific* tool still fails while `curl` works, it may read a bundle file rather than a directory; use [`extraCertDestinations`](#extra-destinations) to write a PEM where that tool expects one.

### Kestrel doesn't pick up the certificate

- Confirm the PFX is in `~/.dotnet/corefx/cryptography/x509stores/my/`.
- If more than one dev cert is present, Kestrel may select a different one. Run **Dev Certs: Clean Up Other Dev Certificates in Dev Container** — this is exactly what the stale-cert warning is for.
- If you disabled `DOTNET_GENERATE_ASPNET_CERTIFICATE=false` handling or run in a `syncContainerCert` flow, a `dotnet run` may have written its own cert alongside ours; see "[Why `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`](#why-dotnet_generate_aspnet_certificatefalse)".

### A container-pushed certificate was rejected

With `syncContainerCert: true`, the host rejects certs whose SAN entries fall outside local scopes, and rejects everything when `autoProvision` or `devcontainerDevCerts.generateDotNetCert` is `false`. The host output channel names the reason. If the SAN entries are legitimately non-local, see [`allowNonLocalContainerCertSans`](#syncing-a-certificate-from-the-container-to-the-host).

## Known issues

### podman: subsequent feature's `apt-get update` fails with `Couldn't create temporary file /tmp/apt.conf.XXX`

This is [containers/buildah#6747](https://github.com/containers/buildah/issues/6747): when a Dev Container feature is installed via the `RUN --mount=type=bind,target=/tmp/build-features-src/<feat>_0 ...` pattern the devcontainer CLI generates, buildah/podman can commit the resulting layer with `/tmp` reset from `1777 root:root` to `0755 root:root`. A later feature that calls `apt-get update` then fails because `_apt` (uid 42) can no longer write to `/tmp`. Docker is not affected.

This feature applies the workaround at the end of its own install script, so combinations like `devcontainer-dev-certs` + `azure-functions-core-tools` on podman work out of the box. If you hit the same class of failure with a *different* feature, copy the standalone [`examples/buildah-tmp-fix/`](examples/buildah-tmp-fix/) local feature into your `.devcontainer/` and place it in `devcontainer.json` between the offending feature and the consumer.

## Non-VS Code editors

The companion extension pattern relies on VS Code's cross-host command routing, so JetBrains, Vim, and other editors can't use the automatic flow. For those, the repository ships a standalone helper script that performs the container-side install the remote extension would normally do:

[`src/devcontainer-feature/src/devcontainer-dev-certs/scripts/setup-cert.sh`](src/devcontainer-feature/src/devcontainer-dev-certs/scripts/setup-cert.sh)

**The feature does not copy this script into the container** — it's a manual fallback. Copy it into your image or bind-mount it, then invoke it yourself:

```bash
# Single cert
setup-cert.sh <pfx-path> <pem-path> <thumbprint>

# Multiple certs and/or extra destinations
setup-cert.sh --bundle-json <path-to-bundle.json>
```

The bundle JSON form takes one or more certs plus optional extra destinations:

```json
{
    "certs": [
        {
            "name": "aspnetcore-dev",
            "thumbprint": "ABC123...",
            "pfxPath": "/abs/cert.pfx",
            "pemPath": "/abs/cert.pem",
            "pemKeyPath": "/abs/cert.key",
            "rootPfxPath": "/abs/root.pfx",
            "trustInContainer": true
        }
    ],
    "extraDestinations": [
        { "path": "/etc/nginx/certs", "format": "pem" },
        { "path": "/var/app", "format": "pem-bundle" }
    ]
}
```

`pemKeyPath` and `rootPfxPath` are optional — the root PFX is generated with `openssl` when omitted. The script honors `_REMOTE_USER` / `_REMOTE_USER_HOME` (defaulting to `vscode` / `/home/vscode`) to decide whose home directory receives the certs.

**Requirements:** `openssl` must be installed for hash computation and PFX conversion; the `--bundle-json` form additionally requires `jq`.

You still need to produce the certificate material yourself on the host (for example with `dotnet dev-certs https --export-path`) and get it into the container — the script handles placement and trust, not transfer.

## Limitations

- **Auto-generated dev cert matches .NET's format only.** The `generateDotNetCert` flow produces a cert identical to `dotnet dev-certs https` (specific OID marker, subject, SAN entries). To sync differently-shaped certs (corporate CAs, custom wildcard certs, etc.), add them via the `devcontainerDevCerts.userCertificates` VS Code setting — they're copied as-is.
- **VS Code only.** The companion extension pattern relies on VS Code's cross-host command routing. Other editors (JetBrains, Vim, etc.) are not supported automatically; see "[Non-VS Code editors](#non-vs-code-editors)" for the manual fallback.
- **Host trust requires user interaction.** On Windows, trusting the auto-generated dev cert triggers a system dialog. On macOS, the keychain may prompt for a password. This only happens once and only for the .NET dev cert — user-managed certs are never added to the host OS trust store.
- **Linux browser trust is a separate step.** Firefox and Chromium on Linux don't read the OS/OpenSSL trust stores; see "[Linux hosts: browser trust](#linux-hosts-browser-trust)".

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Windows | x64, ARM64 |
| macOS | x64, ARM64 |
| Linux (glibc) | x64, ARM64 |
| Linux (musl/Alpine) | x64 |

## Development

### Prerequisites

- Node.js 22+
- Docker (for Dev Container testing)
- VS Code with the Dev Containers extension

### Building

Open the repo in VS Code and press F5. The `build-extensions` task will:

1. Build both TypeScript extensions with esbuild
2. Hydrate a test project from the template into `.out/test-project/`
3. Package the workspace extension VSIX into the test project's `.devcontainer/`

The Extension Development Host opens with the UI extension loaded on the host side. To test the full Dev Container flow, reopen `.out/test-project/` in a container.

### Repository Layout

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
      util/paths.ts                .NET store and OpenSSL trust directory paths

  devcontainer-feature/            Dev Container feature
    src/devcontainer-dev-certs/
      devcontainer-feature.json    Feature metadata, options, extension references
      install.sh                   Container build-time setup (creates directories)
      scripts/setup-cert.sh        Manual fallback installer for non-VS Code editors

test/
  sample-project/                  Test project template (hydrated into .out/ for testing)
  hydrate.mjs                      Assembles a runnable test project from the template + feature

.github/workflows/                 CI/CD (build, extension packaging, feature publishing)
```

## Verifying Release Provenance

Starting with **v1.0.0**, each release publishes [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestations that bind the artifact back to the GitHub Actions workflow run that produced it. Attestations are minted from short-lived OpenID Connect tokens — no long-lived publishing credentials are stored in the repository — and the publishing workflow runs in a protected `release` environment scoped to release tags. Earlier (`0.x`) releases predate this pipeline and are not attested.

You can verify any release artifact with the [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify) command:

- **Dev Container feature.** The provenance attestation is pushed to GHCR alongside the OCI artifact:
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
