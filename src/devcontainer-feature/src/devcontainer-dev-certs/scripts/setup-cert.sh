#!/usr/bin/env bash
# Fallback helper for non-VSCode scenarios (JetBrains, CLI, etc.)
# The VSCode workspace extension handles this natively via TypeScript.
#
# Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>
#
# This script requires openssl to be installed for hash computation.
set -e

PFX_PATH="${1:?Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>}"
PEM_PATH="${2:?Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>}"
THUMBPRINT="${3:?Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>}"

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-/home/${REMOTE_USER}}"

DOTNET_STORE_DIR="${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/my"
DOTNET_ROOT_STORE_DIR="${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/root"
TRUST_DIR="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust"

# Copy PFX to .NET store
mkdir -p "${DOTNET_STORE_DIR}"
cp "${PFX_PATH}" "${DOTNET_STORE_DIR}/${THUMBPRINT}.pfx"
chmod 600 "${DOTNET_STORE_DIR}/${THUMBPRINT}.pfx"

# Create public-cert-only PFX for .NET Root store (trust verification)
mkdir -p "${DOTNET_ROOT_STORE_DIR}"
if command -v openssl &>/dev/null; then
    openssl pkcs12 -export -in "${PEM_PATH}" -nokeys -passout pass: \
        -out "${DOTNET_ROOT_STORE_DIR}/${THUMBPRINT}.pfx"
    chmod 644 "${DOTNET_ROOT_STORE_DIR}/${THUMBPRINT}.pfx"
else
    echo "Warning: openssl not found. Root store PFX not created. Certificate may not be reported as trusted by dotnet."
fi

# Copy PEM to trust directory
mkdir -p "${TRUST_DIR}"
PEM_FILENAME="aspnetcore-localhost-${THUMBPRINT}.pem"
cp "${PEM_PATH}" "${TRUST_DIR}/${PEM_FILENAME}"
chmod 644 "${TRUST_DIR}/${PEM_FILENAME}"

# Create hash symlink (c_rehash equivalent) — requires openssl
if command -v openssl &>/dev/null; then
    HASH=$(openssl x509 -hash -noout -in "${TRUST_DIR}/${PEM_FILENAME}" 2>/dev/null || true)
    if [ -n "${HASH}" ]; then
        # Find available slot
        for i in $(seq 0 9); do
            LINK="${TRUST_DIR}/${HASH}.${i}"
            if [ ! -e "${LINK}" ]; then
                ln -sf "${PEM_FILENAME}" "${LINK}"
                break
            fi
        done
    fi
else
    echo "Warning: openssl not found. Hash symlinks not created. OpenSSL trust may not work."
    echo "Install openssl or use the VSCode extension which handles this natively."
fi

# Fix ownership
if id "${REMOTE_USER}" &>/dev/null; then
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.dotnet"
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.aspnet"
fi

echo "Certificate installed."
echo "  .NET store:      ${DOTNET_STORE_DIR}/${THUMBPRINT}.pfx"
echo "  .NET root store: ${DOTNET_ROOT_STORE_DIR}/${THUMBPRINT}.pfx"
echo "  OpenSSL trust:   ${TRUST_DIR}/${PEM_FILENAME}"
