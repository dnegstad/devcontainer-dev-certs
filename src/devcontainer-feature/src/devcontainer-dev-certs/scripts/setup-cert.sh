#!/usr/bin/env bash
# Fallback helper for non-VSCode scenarios (JetBrains, CLI, etc.)
# The VSCode workspace extension handles this natively via TypeScript.
#
# Usage:
#   setup-cert.sh <pfx-path> <pem-path> <thumbprint>
#   setup-cert.sh --bundle-json <path>
#
# Bundle JSON form (accepts one or more certs plus optional extra destinations):
#   {
#     "certs": [
#       {
#         "name": "aspnetcore-dev",
#         "thumbprint": "ABC123...",
#         "pfxPath": "/abs/cert.pfx",
#         "pemPath": "/abs/cert.pem",
#         "pemKeyPath": "/abs/cert.key",       // optional
#         "rootPfxPath": "/abs/root.pfx",      // optional; generated via openssl if omitted
#         "trustInContainer": true
#       }
#     ],
#     "extraDestinations": [
#       { "path": "/etc/nginx/certs", "format": "pem" },
#       { "path": "/var/app", "format": "pem-bundle" }
#     ]
#   }
#
# This script requires openssl to be installed for hash computation and (in
# the bundle form) PFX/root-PFX conversion. The bundle form additionally
# requires `jq` for JSON parsing.
set -e

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-/home/${REMOTE_USER}}"

DOTNET_STORE_DIR="${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/my"
DOTNET_ROOT_STORE_DIR="${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/root"
TRUST_DIR="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust"

ensure_openssl() {
    if ! command -v openssl &>/dev/null; then
        echo "Error: openssl is required but not installed." >&2
        exit 1
    fi
}

# Create a c_rehash-style hash symlink for the given PEM file in its directory.
create_hash_symlink() {
    local pem_dir="$1"
    local pem_filename="$2"
    local hash
    hash=$(openssl x509 -hash -noout -in "${pem_dir}/${pem_filename}" 2>/dev/null || true)
    if [ -z "${hash}" ]; then
        return
    fi
    for i in $(seq 0 9); do
        local link="${pem_dir}/${hash}.${i}"
        if [ ! -e "${link}" ]; then
            ln -sf "${pem_filename}" "${link}"
            break
        fi
    done
}

# Install one cert to the canonical .NET + OpenSSL locations.
# Args: name, thumbprint, pfx_path, pem_path, pem_key_path, root_pfx_path (optional), trust_in_container (true/false), is_user_cert (true/false)
install_cert_canonical() {
    local name="$1"
    local thumbprint="$2"
    local pfx_path="$3"
    local pem_path="$4"
    local pem_key_path="$5"
    local root_pfx_path="$6"
    local trust_in_container="$7"
    local is_user_cert="$8"

    mkdir -p "${DOTNET_STORE_DIR}" "${DOTNET_ROOT_STORE_DIR}" "${TRUST_DIR}"

    # .NET store (CurrentUser\My) — Kestrel reads from here. Keyed by thumbprint.
    if [ -f "${pfx_path}" ]; then
        cp "${pfx_path}" "${DOTNET_STORE_DIR}/${thumbprint}.pfx"
        chmod 600 "${DOTNET_STORE_DIR}/${thumbprint}.pfx"
    fi

    if [ "${trust_in_container}" = "true" ]; then
        # .NET root store — public-cert-only PFX
        if [ -n "${root_pfx_path}" ] && [ -f "${root_pfx_path}" ]; then
            cp "${root_pfx_path}" "${DOTNET_ROOT_STORE_DIR}/${thumbprint}.pfx"
        else
            ensure_openssl
            openssl pkcs12 -export -in "${pem_path}" -nokeys -passout pass: \
                -out "${DOTNET_ROOT_STORE_DIR}/${thumbprint}.pfx"
        fi
        chmod 644 "${DOTNET_ROOT_STORE_DIR}/${thumbprint}.pfx"

        # PEM in the OpenSSL trust dir. User certs use a stable {name}.pem;
        # the auto-generated dotnet dev cert uses the historic thumbprint name.
        local pem_filename
        if [ "${is_user_cert}" = "true" ]; then
            pem_filename="${name}.pem"
        else
            pem_filename="aspnetcore-localhost-${thumbprint}.pem"
        fi
        cp "${pem_path}" "${TRUST_DIR}/${pem_filename}"
        chmod 644 "${TRUST_DIR}/${pem_filename}"

        ensure_openssl
        create_hash_symlink "${TRUST_DIR}" "${pem_filename}"
    fi
}

# Write cert artifacts to an extra destination directory per the format grammar.
# Args: dest_path, dest_format, name, pem_path, pem_key_path, pfx_path
write_extra_destination() {
    local dest_path="$1"
    local dest_format="$2"
    local name="$3"
    local pem_path="$4"
    local pem_key_path="$5"
    local pfx_path="$6"

    # Every destination is a directory.
    local target_dir="${dest_path%/}"
    mkdir -p "${target_dir}"

    emit() {
        local ext="$1"
        local src="$2"
        [ -z "${src}" ] && return 0
        [ ! -f "${src}" ] && return 0
        cp "${src}" "${target_dir}/${name}.${ext}"
    }

    emit_bundle() {
        local out="${target_dir}/${name}-bundle.pem"
        cat "${pem_path}" > "${out}"
        if [ -n "${pem_key_path}" ] && [ -f "${pem_key_path}" ]; then
            cat "${pem_key_path}" >> "${out}"
        fi
    }

    case "${dest_format}" in
        pem)        emit "pem" "${pem_path}" ;;
        key)        emit "key" "${pem_key_path}" ;;
        pem-bundle) emit_bundle ;;
        pfx)        emit "pfx" "${pfx_path}" ;;
        all)
            emit "pem" "${pem_path}"
            emit "key" "${pem_key_path}"
            emit "pfx" "${pfx_path}"
            emit_bundle
            ;;
        *)
            echo "Warning: unknown destination format '${dest_format}'; skipping." >&2
            ;;
    esac
}

# --- Bundle JSON form ---
if [ "${1:-}" = "--bundle-json" ]; then
    BUNDLE="${2:?Usage: setup-cert.sh --bundle-json <path>}"
    if ! command -v jq &>/dev/null; then
        echo "Error: jq is required for --bundle-json mode." >&2
        exit 1
    fi
    ensure_openssl

    # Track directory destinations that need a rehash at the end.
    declare -a REHASH_DIRS=()

    cert_count=$(jq '.certs | length' "${BUNDLE}")
    if [ "${cert_count}" -gt 0 ]; then
        for i in $(seq 0 $((cert_count - 1))); do
            name=$(jq -r ".certs[${i}].name" "${BUNDLE}")
            thumbprint=$(jq -r ".certs[${i}].thumbprint" "${BUNDLE}")
            pfx_path=$(jq -r ".certs[${i}].pfxPath // \"\"" "${BUNDLE}")
            pem_path=$(jq -r ".certs[${i}].pemPath" "${BUNDLE}")
            pem_key_path=$(jq -r ".certs[${i}].pemKeyPath // \"\"" "${BUNDLE}")
            root_pfx_path=$(jq -r ".certs[${i}].rootPfxPath // \"\"" "${BUNDLE}")
            trust_in_container=$(jq -r ".certs[${i}].trustInContainer // true" "${BUNDLE}")
            kind=$(jq -r ".certs[${i}].kind // \"user\"" "${BUNDLE}")

            is_user_cert="true"
            if [ "${kind}" = "dotnet-dev" ]; then
                is_user_cert="false"
            fi

            install_cert_canonical "${name}" "${thumbprint}" "${pfx_path}" "${pem_path}" \
                "${pem_key_path}" "${root_pfx_path}" "${trust_in_container}" "${is_user_cert}"

            # Extra destinations. Guard both the outer cert loop and this
            # inner loop against seq-on-empty (some seq builds treat
            # `seq 0 -1` as an error under set -e).
            dest_count=$(jq '.extraDestinations | length // 0' "${BUNDLE}")
            if [ "${dest_count}" -gt 0 ]; then
                for j in $(seq 0 $((dest_count - 1))); do
                    dest_path=$(jq -r ".extraDestinations[${j}].path" "${BUNDLE}")
                    dest_format=$(jq -r ".extraDestinations[${j}].format // \"all\"" "${BUNDLE}")
                    write_extra_destination "${dest_path}" "${dest_format}" "${name}" \
                        "${pem_path}" "${pem_key_path}" "${pfx_path}"
                    if [ "${dest_format}" = "pem" ] || [ "${dest_format}" = "all" ]; then
                        REHASH_DIRS+=("${dest_path%/}")
                    fi
                done
            fi
        done
    fi

    # Rehash any directory pem destinations so OpenSSL can find the certs.
    for d in "${REHASH_DIRS[@]}"; do
        for f in "${d}"/*.pem; do
            [ -f "${f}" ] || continue
            create_hash_symlink "${d}" "$(basename "${f}")"
        done
    done

    # Fix ownership
    if id "${REMOTE_USER}" &>/dev/null; then
        chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.dotnet" 2>/dev/null || true
        chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.aspnet" 2>/dev/null || true
    fi

    echo "Certificate bundle installed."
    exit 0
fi

# --- Legacy positional form: <pfx-path> <pem-path> <thumbprint> ---
PFX_PATH="${1:?Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>}"
PEM_PATH="${2:?Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>}"
THUMBPRINT="${3:?Usage: setup-cert.sh <pfx-path> <pem-path> <thumbprint>}"

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
