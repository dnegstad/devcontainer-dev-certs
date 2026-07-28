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
- Generates an HTTPS development certificate compatible with ASP.NET and Aspire (using Node's built-in `crypto` plus `@peculiar/x509`/`pkijs` — no .NET installation required on your host)
- Trusts it in the host OS certificate store (so browsers trust forwarded ports)
- Serves the certificate material (PFX + PEM, base64-encoded) to the remote side via VS Code's cross-host command routing
- Syncs additional user-managed certificates (corporate CAs, wildcard certs, etc.) into containers when configured
- Accepts container-pushed dev certificates and trusts them on the host (opt-in reverse-sync, useful when the container is the cert source)

**Remote side** (companion extension):
- Receives certificate material from this extension (the auto-generated dev cert + any user-managed certs)
- Places each PFX in the .NET X509 store (`~/.dotnet/corefx/cryptography/x509stores/my/`) so ASP.NET and Aspire discover it automatically
- Places each PEM in an OpenSSL trust directory with hash symlinks so `curl`, `wget`, and other tools trust it
- Optionally writes each cert into additional destinations (nginx config dirs, Java keystores, etc.) when `extraCertDestinations` is configured
- Optionally pushes its OWN dev cert back to this extension when `syncContainerCert` is enabled

## Quick Start

Add the Dev Container feature to your project's `devcontainer.json` (not to any extension settings):

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {}
    }
}
```

The feature declares both companion extensions and configures the container's trust infrastructure. When you open the Dev Container in VS Code:

1. This extension shows a one-time consent prompt, generates a dev cert on your host (if one doesn't exist), and trusts it in your OS certificate store
2. The remote companion extension requests the cert material via VS Code's cross-host command routing
3. The cert is installed in the container's .NET X509 store and OpenSSL trust directory
4. ASP.NET, Aspire, and other services discover the cert automatically — no environment variables or manual configuration needed
5. Your host browser trusts the cert on forwarded ports

## How It Works

### Certificate Generation

The extension generates certificates using Node's built-in `crypto` plus `@peculiar/x509` (X.509) and `pkijs` (PKCS#12) — no .NET installation required on your host. The auto-generated certificate is compatible with the [ASP.NET dev cert format](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs) and includes:

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
| Linux | Added to .NET Root store + OpenSSL trust directory + `SSL_CERT_DIR` in VS Code terminals |

### Linux Trust Details

On Linux, host trust involves three layers:

1. **`.NET Root store`** (`~/.dotnet/corefx/cryptography/x509stores/root/`) — trusted automatically by the .NET runtime
2. **`OpenSSL trust directory`** (`~/.aspnet/dev-certs/trust/`) — PEM certificate with hash symlinks for OpenSSL-based tools
3. **`SSL_CERT_DIR` in VS Code terminals** — the extension prepends the trust directory to `SSL_CERT_DIR` in VS Code's integrated terminal environment, so `curl`, `wget`, and other CLI tools trust the cert automatically

For tools running **outside** VS Code integrated terminals (e.g., a system terminal), set `SSL_CERT_DIR` manually:

```bash
export SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust${SSL_CERT_DIR:+:$SSL_CERT_DIR}"
```

#### Browser Trust (Firefox / Chromium)

Firefox and Chromium on Linux use [NSS](https://firefox-source-docs.mozilla.org/security/nss/) for certificate trust — they do **not** read from OpenSSL trust directories. This extension provides a **"Dev Certs: Trust Certificate in Browsers"** command (available from the Command Palette) that:

- Checks for `certutil` (from `libnss3-tools`) on the PATH
- If available, automatically trusts the cert in Chromium (`~/.pki/nssdb/`) and Firefox profile NSS databases
- If `certutil` is not installed or no browser databases are found, displays the certificate path so you can import it manually

To install `certutil`:

| Distro | Command |
|--------|---------|
| Debian / Ubuntu | `sudo apt install libnss3-tools` |
| Fedora / RHEL | `sudo dnf install nss-tools` |
| Arch | `sudo pacman -S nss` |

To import manually in Firefox: **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**, then select the PEM file from `~/.aspnet/dev-certs/trust/`.

> **Note:** The default trust directory is `~/.aspnet/dev-certs/trust/`. This can be overridden with the `DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY` environment variable.

### Cross-Host Transfer

Certificate material (PFX + PEM) is serialized as base64 and transferred via `vscode.commands.executeCommand()`, which VS Code routes transparently between extension hosts. No Docker commands, no file mounts — this works for any VS Code remote scenario.

### Container Trust

Inside the container, the remote extension places the cert in two locations:

- **`~/.dotnet/corefx/cryptography/x509stores/my/{thumbprint}.pfx`** — ASP.NET's X509Store fallback discovers it automatically
- **`~/.aspnet/dev-certs/trust/`** — PEM + OpenSSL hash symlinks, included in `SSL_CERT_DIR` so `curl`, `wget`, and other OpenSSL-based tools trust it

## User-managed certificates

In addition to the auto-generated dev cert, you can sync arbitrary host-side certificates (corporate CAs, custom wildcard certs, staging certs, etc.) into your Dev Containers. Configure them in your host VS Code settings:

```json
{
    "devcontainerDevCerts.userCertificates": [
        { "name": "corp-ca", "pemCertPath": "/Users/me/certs/corp-ca.pem" },
        { "name": "staging", "pfxPath": "/Users/me/certs/staging.pfx", "pfxPassword": "hunter2", "trustInContainer": true }
    ]
}
```

Each entry supplies exactly one of `pfxPath` (+ optional `pfxPassword`) or `pemCertPath` (+ optional `pemKeyPath`). Omitting the key produces a CA-only entry. User-managed certificates are **never** added to the host OS trust store — the assumption is you already trust them on the host if you're syncing them in. PFX passwords are preserved end-to-end (no decrypt/re-encrypt round-trip strips them on the wire).

Per-entry options:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Filename stem used inside the container (`{name}.pem`, etc.). 1-64 chars from `[A-Za-z0-9._-]`, no leading dot. |
| `pfxPath` | one of | Absolute path on the host to a PFX/PKCS#12 file. |
| `pfxPassword` | optional | Password for the PFX (or, for `pemCertPath` sources, the password used when synthesizing the `.pfx` for extra destinations). |
| `pemCertPath` | one of | Absolute path on the host to a PEM-encoded certificate. |
| `pemKeyPath` | optional | Absolute path on the host to a PEM-encoded private key. Omit for CA-only entries. |
| `trustInContainer` | optional, default `true` | Plant the cert in the container's OpenSSL trust dir + .NET Root store. |
| `excludeFromDotNetStore` | optional, default `false` | When `installUserCertsToDotNetStore` is on globally, exempt this single cert from the `my/` write (avoids the password-stripping copy for sensitive entries). |

## Container-to-host sync (opt-in)

The default flow is host-as-source. If you have a Dev Container that already produces its own ASP.NET dev cert (for example via `dotnet dev-certs https` baked into the image, or generated by an Aspire AppHost on first run), you can flip the direction and let the container push its cert to the host for trust:

1. On the container, set the `syncContainerCert` feature option:

    ```json
    { "features": { "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": { "syncContainerCert": true } } }
    ```

2. No new host setting is needed — the same `devcontainerDevCerts.generateDotNetCert` + `devcontainer-dev-certs.autoProvision` settings that gate host-generation also gate accepting a container-pushed cert. The host independently re-validates the incoming certificate (ASP.NET dev-cert format + local-only SAN entries by default) and prompts you once before trusting it.

The host only ever trusts the **public** certificate — the private key never leaves the container. The trust step goes through the same OS-level path host-generated certs use: on Linux that includes the .NET Root store, the OpenSSL trust directory, and NSS browser databases; on macOS the login keychain trust policy; on Windows `CurrentUser/Root` via `certutil`. The cert is NOT written to `CurrentUser/My`, the macOS keychain identity slot, or the .NET `my/` directory.

By default the host rejects any cert whose SAN entries reach outside well-known local scopes:

- **DNS** — `localhost`, `host.docker.internal`, `host.containers.internal`, `gateway.docker.internal`; suffix match on `.localhost`, `.dev.localhost`, `.dev.internal` (wildcards like `*.dev.localhost` handled by stripping the leading `*.` and re-checking).
- **IPv4** — 127.0.0.0/8 (loopback), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC1918 private), 169.254.0.0/16 (link-local).
- **IPv6** — `::1` (loopback), `fc00::/7` (unique local), `fe80::/10` (link-local).

This matches the SAN set baked into the default ASP.NET dev cert. To allow a cert with SAN entries outside this set (rare; security-sensitive), set `devcontainerDevCerts.allowNonLocalContainerCertSans: true`. The consent prompt surfaces every non-local SAN entry when the override is enabled so you can see exactly what you're agreeing to trust.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `devcontainer-dev-certs.autoProvision` | `true` | Allow certificate provisioning when the workspace extension requests one. On first use, a consent prompt explains what will happen before any certificates are generated. Set to `false` to disable provisioning entirely (host-generation AND acceptance of container-pushed certs). |
| `devcontainerDevCerts.generateDotNetCert` | `true` | Auto-generate the ASP.NET / Aspire compatible HTTPS dev cert and trust it in the host OS store. When `false`, user-managed certificates (if any) are still synced, but no managed dev cert lives on the host — also implicitly disables acceptance of container-pushed dev certs. |
| `devcontainerDevCerts.userCertificates` | `[]` | Host-managed certificates to sync from the host into Dev Containers (see "User-managed certificates" above). |
| `devcontainerDevCerts.installUserCertsToDotNetStore` | `false` | When `true`, also copies every entry from `userCertificates` into the container's .NET X509Store. **Security note:** the on-disk PFX there is passwordless (Linux's `StoreName.My` enumeration can't accept per-file passwords), so opting in strips your user cert's password on the in-container copy. Per-entry exemption via `excludeFromDotNetStore: true`. The auto-generated dotnet-dev cert is always installed to the store regardless. |
| `devcontainerDevCerts.defaultKestrelCertificate` | `""` | Name of a `userCertificates` entry to use as the default Kestrel certificate inside Dev Containers. When set, the remote extension writes that cert's PFX to `~/.aspnet/dev-certs/https/kestrel-default.pfx` and exports `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` to processes launched from VS Code (terminals, debug, tasks). Leave empty to opt out — Kestrel will still discover the auto-generated dev cert via X509Store. |
| `devcontainerDevCerts.allowNonLocalContainerCertSans` | `false` | When accepting a Dev Container-managed dev certificate (via `syncContainerCert`), override the default SAN restriction that limits trusted certificates to localhost / loopback / private IPs / docker host names. Only enable when you fully understand the SAN entries the container will push. Has no effect when `generateDotNetCert` or `autoProvision` is `false`. |

## Dev Container Feature Options

These options are set on the feature in your project's `devcontainer.json` (not in VS Code settings) and configure the container side. The feature declares and installs both companion extensions, so you don't list them yourself.

```json
{
    "features": {
        "ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs:1": {
            "syncContainerCert": true
        }
    }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `sslCertDirs` | Standard distro paths | System CA directories for `SSL_CERT_DIR`. Override if your base image uses non-standard paths. |
| `pruneMissingCertDirs` | `true` | Filter out directories that don't exist on this image from `sslCertDirs` before writing `SSL_CERT_DIR` (some TLS stacks error on a missing entry). Set to `false` to use `sslCertDirs` verbatim — e.g. when a directory is created after install but before it's needed. |
| `generateDotNetCert` | `true` | Pull the host-generated ASP.NET dev cert into this container. Set to `false` if you're only using user-managed certs in this container. |
| `syncUserCertificates` | `true` | Per-container opt-out for syncing certs configured in the host `devcontainerDevCerts.userCertificates` setting. |
| `syncContainerCert` | `false` | Opt in to pushing the container's own dev cert to the host (reverse-sync). When true, also implicitly overrides `generateDotNetCert` — you don't need to set both. |
| `extraCertDestinations` | `""` | Comma-separated list of additional directories to write cert artifacts to. Each entry is `<abs-dir>[=<format>]` where format is `pem`, `key`, `pem-bundle`, `pfx`, or `all` (default). Useful for non-.NET workloads (nginx, Java keystores, etc.). |

## Avoiding dotnet's first-run cert auto-generation race

When the host is the dev cert source (default), the devcontainer feature also sets `DOTNET_GENERATE_ASPNET_CERTIFICATE=false` inside the container so dotnet's implicit first-run cert provisioning doesn't race the workspace extension's install of OUR cert. The override is gated — it's only applied when `generateDotNetCert: true` AND `syncContainerCert: false`, so it doesn't break the `syncContainerCert` flow when the container relies on dotnet's auto-gen as its source. Explicit `dotnet dev-certs https` commands are unaffected in either case.

## Requirements

- VS Code 1.100 or later
- [Dev Container Dev Certificates (Remote)](https://marketplace.visualstudio.com/items?itemName=dnegstad.devcontainer-dev-certs-remote) installed in the remote environment

No .NET installation is required on your host machine.

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Windows | x64, ARM64 |
| macOS | x64, ARM64 |
| Linux (glibc) | x64, ARM64 |
| Linux (musl/Alpine) | x64 |
