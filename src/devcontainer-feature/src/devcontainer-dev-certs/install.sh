#!/usr/bin/env bash
set -e

# Options from devcontainer-feature.json (uppercased)
TRUST_NSS="${TRUSTNSS:-false}"
SSL_CERT_DIRS="${SSLCERTDIRS:-/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl}"
DEFAULT_SSL_CERT_DIRS="/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl"
GENERATE_DOTNET_CERT="${GENERATEDOTNETCERT:-true}"
SYNC_USER_CERTIFICATES="${SYNCUSERCERTIFICATES:-true}"
EXTRA_CERT_DESTINATIONS="${EXTRACERTDESTINATIONS:-}"

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-/home/${REMOTE_USER}}"

echo "Setting up dev certificate infrastructure..."

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
            /*)
                # absolute path, ok
                ;;
            *)
                echo "Warning: extraCertDestinations entry '${entry}' is not an absolute path; skipping."
                continue
                ;;
        esac

        if [[ "${path_part}" == */ ]]; then
            target_dir="${path_part%/}"
        else
            base="$(basename "${path_part}")"
            if [[ "${base}" == *"\${name}"* ]] || [[ "${base}" == *'${name}'* ]]; then
                target_dir="$(dirname "${path_part}")"
            else
                target_dir="$(dirname "${path_part}")"
            fi
        fi

        if [ -n "${target_dir}" ] && [ "${target_dir}" != "/" ]; then
            mkdir -p "${target_dir}"
            EXTRA_DIRS_TO_CHOWN+=("${target_dir}")
            echo "  extra destination dir: ${target_dir}"
        fi
    done
fi

# If the user overrode sslCertDirs, we need to override the containerEnv value
# that was baked into the image with the default paths. containerEnv handles the
# default case; this only fires on user override.
if [ "${SSL_CERT_DIRS}" != "${DEFAULT_SSL_CERT_DIRS}" ]; then
    SSL_CERT_DIR_VALUE="\$HOME/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}"
    echo "SSL_CERT_DIR=${SSL_CERT_DIR_VALUE}" >> /etc/environment
    echo "Overriding SSL_CERT_DIR: ${SSL_CERT_DIR_VALUE}"
fi

# Surface the feature options to the running container so the remote extension
# can read them via process.env.
{
    echo "DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET=${GENERATE_DOTNET_CERT}"
    echo "DEVCONTAINER_DEV_CERTS_SYNC_USER=${SYNC_USER_CERTIFICATES}"
    echo "DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS=${EXTRA_CERT_DESTINATIONS}"
} >> /etc/environment

# Set ownership
if id "${REMOTE_USER}" &>/dev/null; then
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.dotnet"
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.aspnet"
    for d in "${EXTRA_DIRS_TO_CHOWN[@]}"; do
        chown -R "${REMOTE_USER}" "${d}" 2>/dev/null || true
    done
fi

echo "Dev certificate infrastructure ready."
echo "  .NET cert store:      ${DOTNET_STORE_DIR}"
echo "  .NET root store:      ${DOTNET_ROOT_STORE_DIR}"
echo "  OpenSSL trust:        ${TRUST_DIR}"
echo "  generateDotNetCert:   ${GENERATE_DOTNET_CERT}"
echo "  syncUserCertificates: ${SYNC_USER_CERTIFICATES}"
