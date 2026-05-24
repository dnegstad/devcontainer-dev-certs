#!/usr/bin/env bash
set -e

# Options from devcontainer-feature.json (uppercased)
TRUST_NSS="${TRUSTNSS:-false}"
SSL_CERT_DIRS="${SSLCERTDIRS:-/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl}"
GENERATE_DOTNET_CERT="${GENERATEDOTNETCERT:-true}"
SYNC_USER_CERTIFICATES="${SYNCUSERCERTIFICATES:-true}"
SYNC_CONTAINER_CERT="${SYNCCONTAINERCERT:-false}"
EXTRA_CERT_DESTINATIONS="${EXTRACERTDESTINATIONS:-}"

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-/home/${REMOTE_USER}}"

echo "Setting up dev certificate infrastructure..."

# Validate sslCertDirs: colon-separated absolute paths only. The value lands
# inside an `export SSL_CERT_DIR=...` line that gets sourced at every login,
# so command-substitution metacharacters here would execute as the shell
# user. Reject anything that doesn't look like a plain path list.
if ! printf '%s' "${SSL_CERT_DIRS}" | grep -qE '^/[A-Za-z0-9._/+@%-]+(:/[A-Za-z0-9._/+@%-]+)*$'; then
    echo "Error: sslCertDirs contains unexpected characters; expected colon-separated absolute paths." >&2
    exit 1
fi

# Validate that no feature option contains a newline. We append these to
# /etc/environment, and an embedded newline would inject an extra env line
# (potentially with a name the operator didn't intend).
for varname in TRUST_NSS SSL_CERT_DIRS GENERATE_DOTNET_CERT SYNC_USER_CERTIFICATES SYNC_CONTAINER_CERT EXTRA_CERT_DESTINATIONS; do
    case "${!varname}" in
        *$'\n'*)
            echo "Error: feature option ${varname} must not contain newlines." >&2
            exit 1
            ;;
    esac
done

# Install NSS tools if requested (for Chromium/Firefox trust)
if [ "${TRUST_NSS}" = "true" ]; then
    if command -v apt-get &>/dev/null; then
        apt-get update -y
        apt-get install -y --no-install-recommends libnss3-tools
        rm -rf /var/lib/apt/lists/*
    elif command -v apk &>/dev/null; then
        apk add --no-cache nss-tools
    elif command -v dnf &>/dev/null; then
        dnf install -y nss-tools
        dnf clean all
    fi
fi

# Create .NET X509Store CurrentUser\My directory
# This is where Kestrel discovers dev certs via X509Store fallback
DOTNET_STORE_DIR="${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/my"
mkdir -p "${DOTNET_STORE_DIR}"

# Create .NET X509Store CurrentUser\Root directory
# The .NET runtime checks this store to determine whether a certificate is trusted
DOTNET_ROOT_STORE_DIR="${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/root"
mkdir -p "${DOTNET_ROOT_STORE_DIR}"

# Create OpenSSL trust directory
# PEM certs + hash symlinks go here; SSL_CERT_DIR includes this path
TRUST_DIR="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust"
mkdir -p "${TRUST_DIR}"

# Pre-create any extra cert destinations so the remote extension can write
# without needing elevated privileges at runtime. Directory targets get the
# path itself created; file targets get the parent directory created.
declare -a EXTRA_DIRS_TO_CHOWN=()
if [ -n "${EXTRA_CERT_DESTINATIONS}" ]; then
    IFS=',' read -ra ENTRIES <<< "${EXTRA_CERT_DESTINATIONS}"
    for entry in "${ENTRIES[@]}"; do
        # Strip whitespace
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [ -z "${entry}" ] && continue

        # Split on =
        path_part="${entry%%=*}"
        # Strip trailing whitespace on path_part
        path_part="${path_part%"${path_part##*[![:space:]]}"}"

        case "${path_part}" in
            /*) ;;
            *)
                echo "Warning: extraCertDestinations entry '${entry}' is not an absolute path; skipping."
                continue
                ;;
        esac

        # Every destination is a directory. Strip any trailing slashes.
        target_dir="${path_part%/}"
        [ -z "${target_dir}" ] && target_dir="/"

        if [ "${target_dir}" != "/" ]; then
            mkdir -p "${target_dir}"
            EXTRA_DIRS_TO_CHOWN+=("${target_dir}")
            echo "  extra destination dir: ${target_dir}"
        fi
    done
fi

# Append KEY="VALUE" to /etc/environment with proper escaping for the PAM
# parser (pam_env): backslashes and double quotes inside the value must be
# escaped. Always quote, even for values without special chars, so unquoted
# spaces don't silently truncate the variable. Reject embedded newlines —
# pam_env is line-oriented and an injected newline would smuggle an
# additional env assignment into the file.
append_env() {
    local key="$1"
    local value="$2"
    case "${value}" in
        *$'\n'*)
            echo "Error: refusing to write ${key} containing a newline to /etc/environment." >&2
            exit 1
            ;;
    esac
    local escaped="${value//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    echo "${key}=\"${escaped}\"" >> /etc/environment
}

# Surface configuration to processes in the container. Two sinks, neither
# alone enough on its own — write to BOTH:
#
#   /etc/profile.d/devcontainer-dev-certs.sh — sourced by login shells.
#     This is the path that reaches the VS Code extension host process:
#     `userEnvProbe` (default `loginInteractiveShell`) captures env from
#     `bash -lic env` and injects it into every spawned extension. Vars
#     written here also show up in integrated terminals.
#   /etc/environment — read by pam_env on PAM-based logins (sshd, console).
#     Not loaded by `docker exec`, which is how VS Code attaches in the
#     typical devcontainer flow, so this sink alone misses the extension
#     host. Kept as the fallback path for non-VS-Code consumers (e.g.
#     an SSH session into a long-running container).
#
# SSL_CERT_DIR needs `$HOME` expansion per user, so it goes into profile.d
# unexpanded and into /etc/environment with a resolved `_REMOTE_USER_HOME`
# (pam_env doesn't expand `$HOME`). The other feature-option vars are plain
# string values and go to both sinks with the same content.
PROFILE_SCRIPT="/etc/profile.d/devcontainer-dev-certs.sh"
: > "${PROFILE_SCRIPT}"
chmod 0644 "${PROFILE_SCRIPT}"

# Append `export KEY="VALUE"` to the profile.d script with shell escaping
# (backslash and double quote). Newlines in feature options were rejected
# upstream by the per-option validation loop, so we don't re-check here.
append_profile() {
    local key="$1"
    local value="$2"
    local escaped="${value//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    echo "export ${key}=\"${escaped}\"" >> "${PROFILE_SCRIPT}"
}

# $HOME is intentionally left unexpanded so each user picks up their own
# trust directory at login. SSL_CERT_DIRS has been validated against
# /^/[A-Za-z0-9._/+@%-]+(:/[A-Za-z0-9._/+@%-]+)*$/ above, so the only
# remaining shell-meaningful character that can reach this line is `$`
# (via $HOME). All other inputs are safe to embed verbatim.
echo "export SSL_CERT_DIR=\"\$HOME/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}\"" >> "${PROFILE_SCRIPT}"

append_profile "DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET" "${GENERATE_DOTNET_CERT}"
append_profile "DEVCONTAINER_DEV_CERTS_SYNC_USER" "${SYNC_USER_CERTIFICATES}"
append_profile "DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER" "${SYNC_CONTAINER_CERT}"
append_profile "DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS" "${EXTRA_CERT_DESTINATIONS}"

SSL_CERT_DIR_RESOLVED="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}"
append_env "SSL_CERT_DIR" "${SSL_CERT_DIR_RESOLVED}"

# Keep the same values in /etc/environment for non-VS-Code PAM-based
# consumers. extraCertDestinations can contain spaces (users routinely
# separate CSV entries with `, `), so unconditionally quote in both sinks.
append_env "DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET" "${GENERATE_DOTNET_CERT}"
append_env "DEVCONTAINER_DEV_CERTS_SYNC_USER" "${SYNC_USER_CERTIFICATES}"
append_env "DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER" "${SYNC_CONTAINER_CERT}"
append_env "DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS" "${EXTRA_CERT_DESTINATIONS}"

# Set ownership
if id "${REMOTE_USER}" &>/dev/null; then
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.dotnet"
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.aspnet"
    for d in "${EXTRA_DIRS_TO_CHOWN[@]}"; do
        chown -R "${REMOTE_USER}" "${d}" 2>/dev/null || true
    done
fi

# Workaround for containers/buildah#6747: a `RUN --mount=type=bind,target=X`
# committed by buildah/podman can reset the mode and ownership of every
# parent directory of the mount target. The devcontainer CLI generates such a
# RUN for every feature with target `/tmp/build-features-src/<feature>_0`,
# which leaves `/tmp` at mode 0755 root:root instead of 1777 in the committed
# layer — even when nothing in the RUN touched `/tmp` itself.
#
# The next feature that runs `apt-get update` then fails with:
#   Couldn't create temporary file /tmp/apt.conf.XXX for passing config to apt-key
# because `_apt` (uid 42) can no longer write to `/tmp`. azure-functions-core-tools
# is the canonical trigger; see issue #47.
#
# A bare `chmod 1777 /tmp` doesn't survive the layer commit: when the mode is
# already 1777 in the lower overlay layer the chmod is a no-op and buildah
# never serializes a corrected `/tmp` entry into the diff. The reliable
# workaround is to force overlayfs to copy `/tmp` up to the upper layer by
# creating and removing a marker file, then re-asserting the mode. No-op on
# Docker, where the commit preserves `/tmp` correctly.
if __tmpfix_marker="$(mktemp /tmp/.devcontainer-dev-certs-tmpfix.XXXXXX 2>/dev/null)"; then
    rm -f -- "${__tmpfix_marker}"
    chmod 1777 /tmp 2>/dev/null || true
fi

echo "Dev certificate infrastructure ready."
echo "  .NET cert store:      ${DOTNET_STORE_DIR}"
echo "  .NET root store:      ${DOTNET_ROOT_STORE_DIR}"
echo "  OpenSSL trust:        ${TRUST_DIR}"
echo "  SSL_CERT_DIR:         ${SSL_CERT_DIR_RESOLVED}"
echo "  generateDotNetCert:   ${GENERATE_DOTNET_CERT}"
echo "  syncUserCertificates: ${SYNC_USER_CERTIFICATES}"
echo "  syncContainerCert:    ${SYNC_CONTAINER_CERT}"
