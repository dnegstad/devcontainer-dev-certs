# Dev Container Dev Certificates (Remote)

Automatically receive and install HTTPS development certificates inside Dev Containers and remote environments — no manual certificate management required.

This is the **remote companion** extension. It runs inside the remote environment (Dev Container, SSH, WSL) and works together with [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) to enable trusted HTTPS across the host/remote boundary.

📖 **Full documentation:** [github.com/dnegstad/devcontainer-dev-certs](https://github.com/dnegstad/devcontainer-dev-certs)

## The Problem

When developing inside Dev Containers, HTTPS certificates are a persistent pain point:

- The dev cert needs to be **trusted on the host** so browsers don't show security warnings on forwarded ports
- The same cert needs to be **trusted inside the container** so services can communicate over HTTPS and tools like `curl` and `wget` work without `--insecure` flags
- Manually generating certificates, exporting PFX/PEM files, copying them into the container, and configuring trust is tedious and error-prone

This is especially common when working with [ASP.NET](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs) and [Aspire](https://aspire.dev/app-host/certificate-configuration/) projects, where HTTPS is the default for local development and inter-service communication.

## The Solution

A Dev Container feature + two companion VS Code extensions that handle everything automatically:

**Host side** (companion extension):
- Generates an HTTPS development certificate compatible with ASP.NET and Aspire (using Node's built-in `crypto` plus `@peculiar/x509`/`pkijs` — no .NET installation required on your host)
- Trusts it in the host OS certificate store (so browsers trust forwarded ports)
- Serves the certificate material (PFX + PEM, base64-encoded) to the remote side via VS Code's cross-host command routing

**Remote side** (this extension):
- Receives certificate material from the host extension (the auto-generated dev cert + any user-managed certs configured on the host)
- Places each PFX in the .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) so ASP.NET and Aspire discover it automatically
- Places each PEM in an OpenSSL trust directory with hash symlinks so `curl`, `wget`, and other tools trust it
- Optionally writes each cert into additional destinations (nginx config dirs, Java keystores, etc.) when `extraCertDestinations` is configured
- Optionally pushes the container's OWN dev cert to the host when `syncContainerCert` is enabled (reverse-sync)
- Surfaces a one-time cleanup prompt when leftover dev certs from previous installs are detected

## Quick Start

> **Don't install this extension manually on your local VS Code — it has no effect there.** This extension runs inside a Dev Container (or other remote) and is installed automatically by the Dev Container feature described below. The only thing you need to do on your local machine is install the [host companion extension](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host), and even that is usually handled for you by the feature.

Add the Dev Container feature to your project's `devcontainer.json` (not to any extension settings):

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {}
    }
}
```

The feature declares both companion extensions and configures the container's trust infrastructure. When you open the Dev Container in VS Code:

1. The host companion extension generates a dev cert and trusts it in the host OS certificate store
2. This extension requests the cert material via VS Code's cross-host command routing
3. The cert is installed in the container's .NET X509 store and OpenSSL trust directory
4. ASP.NET, Aspire, and other services discover the cert automatically — no environment variables or manual configuration needed
5. Your host browser trusts the cert on forwarded ports

If the host companion extension is missing when this extension activates, you'll see an **Install Host Extension** prompt that installs it with one click.

### Verify it worked

```bash
ls ~/.dotnet/corefx/cryptography/x509stores/my/    # expect {thumbprint}.pfx
ls ~/.dotnet/corefx/cryptography/x509stores/root/  # expect the same {thumbprint}.pfx
ls ~/.aspnet/dev-certs/trust/                      # expect the PEM plus a {hash}.0 symlink
dotnet dev-certs https --check --trust             # if the .NET SDK is present
```

`--check` on its own only confirms a valid cert exists in `my/`; adding `--trust` makes it report the trusted state as well (both are read-only in this combination).

Then call your app over HTTPS from inside the container without `-k` — `curl https://localhost:5001`, substituting your app's HTTPS port.

## What This Extension Does

On activation in a remote context, this extension:

1. **Requests certificate material** from the host companion extension via `vscode.commands.executeCommand()` (routed transparently across VS Code extension hosts). Calls `getAllCertMaterialV3` for the modern multi-cert bundle and falls back to older single-cert endpoints if the host extension is on an older version.
2. **Installs each certificate in the bundle** — the auto-generated dotnet dev cert plus any user-managed certs the host is configured to sync. Where the files land depends on which kind it is:
   - **The dotnet dev cert** always gets all three canonical writes: the PFX to `~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx` so ASP.NET's `GetDevelopmentCertificateFromStore()` discovers it, the PEM to `~/.aspnet/dev-certs/trust/` with OpenSSL hash symlinks (c_rehash implemented in pure TypeScript — no `openssl` binary required), and a public-cert-only PFX to the .NET root store so dotnet reports it as trusted.
   - **User-managed certs** get those writes conditionally. The `my/` PFX only when `installUserCertsToDotNetStore` is on, the entry isn't carrying `excludeFromDotNetStore`, and it has a private key; the trust PEM and root-store PFX only while that entry's `trustInContainer` stays on. An entry with trust off and no `my/` opt-in produces no canonical files at all — just whatever `extraCertDestinations` writes.

   Opting out is not retroactive for the trust writes. The `my/` PFX is swept when an entry loses its opt-in, but turning `trustInContainer` off only stops *future* root-store and trust-PEM writes — files from a previous sync stay, and the cert stays trusted in the container, until you delete `~/.dotnet/corefx/cryptography/x509stores/root/{thumbprint}.pfx` and `~/.aspnet/dev-certs/trust/{name}.pem` (plus its hash symlink) yourself. The stale-cert cleanup command doesn't cover these — it only identifies ASP.NET dev cert PFXes in the `my/` store.
3. **Writes user-managed certs to extra destinations** when configured — each entry in `extraCertDestinations` becomes a directory inside the container the extension writes per-cert `{name}.pem` / `.key` / `.pfx` / `-bundle.pem` files to (useful for nginx, Java keystores, requests bundles, etc.).
4. **Pushes the container's own dev cert to the host** when `syncContainerCert` is enabled — the optional reverse-sync flow (see below).
5. **Surfaces a one-time cleanup prompt** when it detects other ASP.NET dev cert artifacts in the container's .NET store alongside the managed one, so leftover certs from previous installs don't confuse Kestrel's selection logic.

OpenSSL-based tools (`curl`, `wget`, etc.) trust the cert because the Dev Container feature points `SSL_CERT_DIR` at the trust directory (see [OpenSSL Trust](#openssl-trust)).

### ASP.NET and Aspire Certificate Discovery

No `ASPNETCORE_Kestrel__Certificates__Default__Path` or other environment variables are needed by default. ASP.NET's startup chain falls back to reading the .NET X509Store, where it finds the PFX by its [ASP.NET dev cert OID marker](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs). This works for standalone ASP.NET services, [Aspire-orchestrated applications](https://aspire.dev/app-host/certificate-configuration/) (including non-.NET services), and any other workload that uses the ASP.NET dev cert format.

The one exception is `devcontainerDevCerts.defaultKestrelCertificate` (a host VS Code setting): when set, it names a `userCertificates` entry to make the default for Kestrel inside Dev Containers. This extension writes the matching cert's PFX to `~/.aspnet/dev-certs/https/kestrel-default.pfx` and exports `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` to processes launched from VS Code (integrated terminals, debug configurations via a `coreclr` provider, and tasks). Processes spawned outside VS Code (a stray `docker exec`, an SSH session without VS Code attached) don't see these vars.

### OpenSSL Trust

The PEM certificate is placed with hash symlinks matching the format that OpenSSL's directory-based lookup expects. The `SSL_CERT_DIR` environment variable (set by the Dev Container feature's `install.sh`) tells OpenSSL to check this directory alongside the system CA bundle.

This means any tool or service that uses OpenSSL for TLS verification — regardless of language or framework — will trust the certificate.

### Container-to-host reverse sync (opt-in)

When `syncContainerCert: true` is set on the Dev Container feature, this extension runs an additional step **before** the standard pull: it scans `~/.dotnet/corefx/cryptography/x509stores/my/*.pfx` inside the container for a valid ASP.NET dev cert (same classify-and-select-best rules the host uses on its own stores), and if it finds one, pushes the **public** cert (PEM-encoded — no PFX, no private key) to the host extension to trust. Useful when the container itself produces the dev cert (e.g. baked into the image with `dotnet dev-certs https`, or generated on first run by Aspire AppHost).

Enabling `syncContainerCert` implicitly overrides `generateDotNetCert` for that container — this extension will skip pulling a host-generated dotnet dev cert, since the container is the source. User-managed certificates configured via `userCertificates` are still pulled normally.

The host independently re-validates the pushed cert and rejects any SAN entry outside well-known local scopes (loopback / RFC1918 private IPs / docker host names / `.localhost` / `.dev.localhost` / `.dev.internal` / IPv6 ULA + link-local). An explicit `devcontainerDevCerts.allowNonLocalContainerCertSans` host setting is available for cases that legitimately need non-local SANs.

### Stale dev cert cleanup

If after install this extension finds dev cert PFXes in the container's .NET store that don't match any of the certs it just synced, it surfaces a one-time "Clean Up" prompt. Accepting runs **Dev Certs: Clean Up Other Dev Certificates in Dev Container** (also available from the Command Palette at any time), which preserves the extension-managed certs and removes the rest, then rehashes the OpenSSL trust directory. The cleanup command refuses to operate when no managed dev cert is known — preventing accidental deletion of every dev cert on disk.

## Commands

Available from the Command Palette (`F1`) in a Dev Container window:

| Command | Command ID | Description |
|---------|------------|-------------|
| **Dev Certs: Inject Certificate into Remote** | `devcontainer-dev-certs.injectCert` | Manually re-run the certificate injection flow (normally automatic on activation). Use it when `autoInject` is off, or to retry after a failure without rebuilding. |
| **Dev Certs: Clean Up Other Dev Certificates in Dev Container** | `devcontainer-dev-certs.cleanupStaleDevCerts` | Sweep dev cert artifacts in the container's .NET stores that aren't the extension-managed one, preserving the managed cert. |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoInject` | `true` | Automatically inject the cert when a remote session starts. Set to `false` to require manually invoking "Dev Certs: Inject Certificate into Remote". |
| `devcontainer-dev-certs.warnOnStaleDevCerts` | `true` | Show the post-install warning when other dev certs are detected alongside the managed one. Set to `false` to silence the prompt; the cleanup command stays available from the Command Palette either way. |

Certificate *content* — which certs exist and get synced — is configured on the host side (`devcontainerDevCerts.userCertificates`, `defaultKestrelCertificate`, and friends). See the [host extension](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) or the [configuration reference](https://github.com/dnegstad/devcontainer-dev-certs#configuration-reference).

## Dev Container feature options

Container-side behavior is configured on the feature in your project's `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {
            "syncContainerCert": true
        }
    }
}
```

These are the options that change what this extension does:

| Option | Default | Description |
|--------|---------|-------------|
| `generateDotNetCert` | `true` | Pull the host-generated ASP.NET dev cert into this container. Set to `false` if you're only using user-managed certs in this container. |
| `syncUserCertificates` | `true` | Per-container opt-out for syncing certs configured in the host `devcontainerDevCerts.userCertificates` setting. |
| `syncContainerCert` | `false` | Opt in to pushing the container's own dev cert to the host (reverse-sync). When true, also implicitly overrides `generateDotNetCert` — you don't need to set both. |
| `extraCertDestinations` | `""` | Comma-separated list of additional directories to write cert artifacts to. Each entry is `<abs-dir>[=<format>]` where format is `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). Useful for non-.NET workloads (nginx, Java keystores, etc.). |

The feature also accepts `sslCertDirs` and `pruneMissingCertDirs`, which configure the container's trust infrastructure at build time. See the [full option reference](https://github.com/dnegstad/devcontainer-dev-certs#dev-container-feature-options).

## Environment Variables

The Dev Container feature sets `SSL_CERT_DIR` (plus `DEVCONTAINER_DEV_CERTS_*` vars describing the selected options) at build time. When the host is the dev cert source — `generateDotNetCert: true` and `syncContainerCert: false`, the default — it also sets `DOTNET_GENERATE_ASPNET_CERTIFICATE=false` so the first `dotnet run` of an HTTPS-enabled project doesn't race this extension's install with a cert of its own. Explicit `dotnet dev-certs https` commands always work regardless. [Details](https://github.com/dnegstad/devcontainer-dev-certs#why-dotnet_generate_aspnet_certificatefalse).

This extension additionally honors, matching the behavior of the official .NET `CertificateManager`:

| Variable | Description |
|----------|-------------|
| `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY` | Override the default OpenSSL trust directory (`~/.aspnet/dev-certs/trust/`) |

## Troubleshooting

This extension logs to the **Dev Container Dev Certs (Remote)** output channel (**View → Output**, then pick it from the dropdown) — what was received from the host, where each file was written, and which thumbprints were considered. The host companion logs separately to **Dev Container Dev Certs** in your local VS Code window; a failure to *obtain* certificates is usually explained there.

If nothing happened at all, check that the host extension is installed, that `autoInject` is on (or run **Dev Certs: Inject Certificate into Remote**), and that `echo $SSL_CERT_DIR` in a container terminal leads with the expanded trust directory (e.g. `/home/vscode/.aspnet/dev-certs/trust`). See the [troubleshooting guide](https://github.com/dnegstad/devcontainer-dev-certs#troubleshooting) for the full list.

## Requirements

- VS Code 1.100 or later
- [Dev Container Dev Certificates (Host)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-host) installed on the local machine

This extension is self-contained and does not require any additional dependencies on your host or in the container.
