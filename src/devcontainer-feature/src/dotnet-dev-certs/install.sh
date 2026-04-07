#!/usr/bin/env bash
set -e

# Options from devcontainer-feature.json (uppercased)
TRUST_NSS="${TRUSTNSS:-false}"
SSL_CERT_DIRS="${SSLCERTDIRS:-/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl}"
DEFAULT_SSL_CERT_DIRS="/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl"

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-/home/${REMOTE_USER}}"

echo "Setting up ASP.NET dev certificate infrastructure..."

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

# Create OpenSSL trust directory
# PEM certs + hash symlinks go here; SSL_CERT_DIR includes this path
TRUST_DIR="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust"
mkdir -p "${TRUST_DIR}"

# If the user overrode sslCertDirs, we need to override the containerEnv value
# that was baked into the image with the default paths. containerEnv handles the
# default case; this only fires on user override.
if [ "${SSL_CERT_DIRS}" != "${DEFAULT_SSL_CERT_DIRS}" ]; then
    SSL_CERT_DIR_VALUE="\$HOME/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}"
    echo "SSL_CERT_DIR=${SSL_CERT_DIR_VALUE}" >> /etc/environment
    echo "Overriding SSL_CERT_DIR: ${SSL_CERT_DIR_VALUE}"
fi

# Set ownership
if id "${REMOTE_USER}" &>/dev/null; then
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.dotnet"
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.aspnet"
fi

echo "ASP.NET dev certificate infrastructure ready."
echo "  .NET cert store: ${DOTNET_STORE_DIR}"
echo "  OpenSSL trust:   ${TRUST_DIR}"
