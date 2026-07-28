#!/usr/bin/env bash
# Fallback helper for non-VSCode scenarios (JetBrains, CLI, etc.)
# The VSCode workspace extension handles this natively via TypeScript.
#
# Usage:
#   setup-cert.sh <pfx-path> <pem-path> <thumbprint>
#   setup-cert.sh --bundle-json <path>
#   setup-cert.sh --doctor
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
# Doctor mode runs read-only checks over the trust infrastructure (directories,
# env vars, cert presence, hash symlinks) and reports findings. Exits non-zero
# only when something is actually broken (missing prereqs, missing or
# unwritable trust dirs, expired managed certs).
#
# This script requires openssl to be installed for hash computation and (in
# the bundle form) PFX/root-PFX conversion. The bundle form additionally
# requires `jq` for JSON parsing.
set -e

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-${HOME:-/home/${REMOTE_USER}}}"

# Honor the DEVCONTAINER_DEV_CERTS_*_DIR vars exported by install.sh
# (via /etc/profile.d and /etc/environment) so non-VS-Code users —
# whose shell session doesn't set _REMOTE_USER — get the same paths
# install.sh chowned at feature-build time. Falling back to the
# REMOTE_USER_HOME computation keeps the legacy path working when
# the env vars aren't present (e.g. running this script directly
# without a login shell or PAM session).
DOTNET_STORE_DIR="${DEVCONTAINER_DEV_CERTS_DOTNET_STORE_DIR:-${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/my}"
DOTNET_ROOT_STORE_DIR="${DEVCONTAINER_DEV_CERTS_DOTNET_ROOT_STORE_DIR:-${REMOTE_USER_HOME}/.dotnet/corefx/cryptography/x509stores/root}"
TRUST_DIR="${DEVCONTAINER_DEV_CERTS_TRUST_DIR:-${REMOTE_USER_HOME}/.aspnet/dev-certs/trust}"

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

# --- Doctor mode: read-only diagnostics ---
if [ "${1:-}" = "--doctor" ]; then
    doctor_errors=0
    doctor_warnings=0

    # Output helpers. The tags double as a grep-able stable interface for
    # tooling that wants to parse this — keep them short and stable.
    ok()      { printf '  [ok]    %s\n' "$*"; }
    warn()    { printf '  [warn]  %s\n' "$*"; doctor_warnings=$((doctor_warnings + 1)); }
    fail()    { printf '  [fail]  %s\n' "$*"; doctor_errors=$((doctor_errors + 1)); }
    info()    { printf '  [info]  %s\n' "$*"; }
    section() { printf '\n%s\n' "$*"; }

    section "Prerequisites:"
    if command -v openssl &>/dev/null; then
        ok "openssl present ($(openssl version 2>/dev/null | head -1))"
    else
        fail "openssl missing — required for hash symlinks and root-PFX synthesis"
    fi
    if command -v jq &>/dev/null; then
        ok "jq present ($(jq --version 2>/dev/null))"
    else
        warn "jq missing — needed only for --bundle-json mode; install if you use bundle invocations"
    fi

    # Helper: check a directory exists and is writable by the current user.
    # Doctor runs as whoever invoked it (typically the remote user, not root),
    # which is the same identity that will later need to write certs here.
    check_dir() {
        local label="$1"
        local dir="$2"
        if [ ! -d "${dir}" ]; then
            fail "${label}: ${dir} does not exist"
            return
        fi
        if [ ! -w "${dir}" ]; then
            fail "${label}: ${dir} exists but is not writable by $(id -un)"
            return
        fi
        ok "${label}: ${dir}"
    }

    section "Trust directories:"
    check_dir ".NET CurrentUser/My  " "${DOTNET_STORE_DIR}"
    check_dir ".NET CurrentUser/Root" "${DOTNET_ROOT_STORE_DIR}"
    check_dir "OpenSSL trust        " "${TRUST_DIR}"

    section "Environment:"
    if [ -n "${SSL_CERT_DIR:-}" ]; then
        case ":${SSL_CERT_DIR}:" in
            *:"${TRUST_DIR}":*) ok "SSL_CERT_DIR includes ${TRUST_DIR}" ;;
            *) warn "SSL_CERT_DIR is set but does NOT include ${TRUST_DIR} — OpenSSL clients (curl, wget) won't trust the dev cert" ;;
        esac
        info "SSL_CERT_DIR=${SSL_CERT_DIR}"
    else
        warn "SSL_CERT_DIR is unset — log out / log back in to source /etc/profile.d, or export it manually"
    fi

    case "${DOTNET_GENERATE_ASPNET_CERTIFICATE:-}" in
        false) ok "DOTNET_GENERATE_ASPNET_CERTIFICATE=false (suppresses dotnet's first-run cert race)" ;;
        "")    info "DOTNET_GENERATE_ASPNET_CERTIFICATE unset — expected when syncContainerCert=true or generateDotNetCert=false; otherwise dotnet's first-run auto-gen may race the managed install" ;;
        *)     info "DOTNET_GENERATE_ASPNET_CERTIFICATE=${DOTNET_GENERATE_ASPNET_CERTIFICATE}" ;;
    esac

    # Helper: describe a .pfx — subject + notAfter + fingerprint. Empty
    # passphrase is assumed (matches the on-disk posture for the .NET
    # X509Store on Linux). Returns 1 if the file can't be parsed.
    describe_pfx() {
        local path="$1"
        local pem
        pem=$(openssl pkcs12 -in "${path}" -nokeys -passin pass: 2>/dev/null) || return 1
        local subject not_after fp
        subject=$(printf '%s' "${pem}" | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject= *//')
        not_after=$(printf '%s' "${pem}" | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
        # OpenSSL 1.x prints `SHA1 Fingerprint=...`, OpenSSL 3.x prints
        # `sha1 Fingerprint=...`. Strip up to and including the `=` to
        # cover both spellings.
        fp=$(printf '%s' "${pem}" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | sed 's/^[^=]*=//' | tr -d ':')
        printf '%s | notAfter=%s | sha1=%s' "${subject}" "${not_after}" "${fp}"
    }

    # Helper: 0 if the cert PEM's notAfter is in the past, 1 otherwise.
    pfx_is_expired() {
        local path="$1"
        local pem
        pem=$(openssl pkcs12 -in "${path}" -nokeys -passin pass: 2>/dev/null) || return 1
        # checkend exits 0 when cert is still valid for at least N seconds,
        # 1 when expired. Invert so this function returns 0 (true) when
        # the cert IS expired.
        ! printf '%s' "${pem}" | openssl x509 -noout -checkend 0 &>/dev/null
    }

    section ".NET CurrentUser/My contents:"
    if command -v openssl &>/dev/null && [ -d "${DOTNET_STORE_DIR}" ]; then
        my_count=0
        # Glob pattern may yield the literal pattern when no matches; guard.
        for pfx in "${DOTNET_STORE_DIR}"/*.pfx; do
            [ -f "${pfx}" ] || continue
            my_count=$((my_count + 1))
            # An unparseable PFX in My is a hard error: Kestrel constructs
            # X509Certificate2(path, null) over exactly these files, so a
            # file openssl can't open with an empty passphrase is one .NET
            # can't load either. The expiry probe is skipped for it —
            # pfx_is_expired returns "not expired" on parse failure, which
            # would misleadingly read as healthy.
            if desc=$(describe_pfx "${pfx}" 2>/dev/null); then
                info "$(basename "${pfx}"): ${desc}"
                if pfx_is_expired "${pfx}"; then
                    fail "$(basename "${pfx}") has expired — Kestrel will not serve HTTPS with this cert"
                fi
            else
                fail "$(basename "${pfx}"): unparseable PFX (openssl pkcs12 with empty passphrase failed) — Kestrel cannot load this identity"
            fi
        done
        if [ "${my_count}" -eq 0 ]; then
            warn "no .pfx files present — Kestrel's X509Store fallback will find nothing"
        elif [ "${my_count}" -gt 1 ]; then
            warn "${my_count} .pfx files present — multiple dev certs in this store cause nondeterministic Kestrel selection (run the host extension's 'clean up other dev certificates' command, or remove manually)"
        fi
    fi

    section ".NET CurrentUser/Root contents:"
    if command -v openssl &>/dev/null && [ -d "${DOTNET_ROOT_STORE_DIR}" ]; then
        root_count=0
        for pfx in "${DOTNET_ROOT_STORE_DIR}"/*.pfx; do
            [ -f "${pfx}" ] || continue
            root_count=$((root_count + 1))
            # Same standard as the My store above: .NET reads this store to
            # decide whether My's certs count as trusted, so an unparseable
            # trust anchor must fail the doctor rather than pass as info.
            if desc=$(describe_pfx "${pfx}" 2>/dev/null); then
                info "$(basename "${pfx}"): ${desc}"
            else
                fail "$(basename "${pfx}"): unparseable PFX (openssl pkcs12 with empty passphrase failed) — .NET cannot load this trust anchor"
            fi
        done
        if [ "${root_count}" -eq 0 ]; then
            info "no .pfx files present — .NET will not consider any of My's certs as locally trusted"
        fi
    fi

    section "OpenSSL trust directory contents:"
    if [ -d "${TRUST_DIR}" ]; then
        pem_count=0
        for pem in "${TRUST_DIR}"/*.pem; do
            [ -f "${pem}" ] || continue
            pem_count=$((pem_count + 1))
            pem_name=$(basename "${pem}")
            if command -v openssl &>/dev/null; then
                # `|| hash=""` keeps the script-wide `set -e` from
                # terminating the doctor on a malformed PEM — the empty
                # value routes to the fail branch below instead.
                hash=$(openssl x509 -hash -noout -in "${pem}" 2>/dev/null) || hash=""
                if [ -n "${hash}" ]; then
                    # Look for at least one symlink "${hash}.N" that resolves to this PEM.
                    found_link=""
                    for i in 0 1 2 3 4 5 6 7 8 9; do
                        link="${TRUST_DIR}/${hash}.${i}"
                        if [ -L "${link}" ] && [ "$(readlink "${link}")" = "${pem_name}" ]; then
                            found_link="${link}"
                            break
                        fi
                    done
                    if [ -n "${found_link}" ]; then
                        info "${pem_name} → $(basename "${found_link}") (hash ${hash})"
                    else
                        fail "${pem_name}: no c_rehash symlink (${hash}.N) pointing back — OpenSSL won't find this cert; re-run the installer or 'openssl rehash ${TRUST_DIR}'"
                    fi
                else
                    fail "${pem_name}: openssl could not compute a subject hash"
                fi
            else
                info "${pem_name}"
            fi
        done
        if [ "${pem_count}" -eq 0 ]; then
            warn "no .pem files in ${TRUST_DIR} — OpenSSL-based tools (curl, wget) won't trust any dev cert"
        fi
    fi

    section "Summary:"
    if [ "${doctor_errors}" -gt 0 ]; then
        printf '  %d error(s), %d warning(s).\n' "${doctor_errors}" "${doctor_warnings}"
        exit 1
    fi
    if [ "${doctor_warnings}" -gt 0 ]; then
        printf '  0 errors, %d warning(s) — review above before relying on this setup.\n' "${doctor_warnings}"
    else
        printf '  All checks passed.\n'
    fi
    exit 0
fi

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

# Both the root-store PFX conversion and the OpenSSL hash symlink need
# `openssl`. Falling back to a warning leaves the cert partially
# installed but the script exiting 0, which the caller has no way to
# detect. Refuse the install up front instead.
ensure_openssl

# Copy PFX to .NET store
mkdir -p "${DOTNET_STORE_DIR}"
cp "${PFX_PATH}" "${DOTNET_STORE_DIR}/${THUMBPRINT}.pfx"
chmod 600 "${DOTNET_STORE_DIR}/${THUMBPRINT}.pfx"

# Create public-cert-only PFX for .NET Root store (trust verification)
mkdir -p "${DOTNET_ROOT_STORE_DIR}"
openssl pkcs12 -export -in "${PEM_PATH}" -nokeys -passout pass: \
    -out "${DOTNET_ROOT_STORE_DIR}/${THUMBPRINT}.pfx"
chmod 644 "${DOTNET_ROOT_STORE_DIR}/${THUMBPRINT}.pfx"

# Copy PEM to trust directory
mkdir -p "${TRUST_DIR}"
PEM_FILENAME="aspnetcore-localhost-${THUMBPRINT}.pem"
cp "${PEM_PATH}" "${TRUST_DIR}/${PEM_FILENAME}"
chmod 644 "${TRUST_DIR}/${PEM_FILENAME}"

# Create hash symlink (c_rehash equivalent).
create_hash_symlink "${TRUST_DIR}" "${PEM_FILENAME}"

# Fix ownership
if id "${REMOTE_USER}" &>/dev/null; then
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.dotnet"
    chown -R "${REMOTE_USER}" "${REMOTE_USER_HOME}/.aspnet"
fi

echo "Certificate installed."
echo "  .NET store:      ${DOTNET_STORE_DIR}/${THUMBPRINT}.pfx"
echo "  .NET root store: ${DOTNET_ROOT_STORE_DIR}/${THUMBPRINT}.pfx"
echo "  OpenSSL trust:   ${TRUST_DIR}/${PEM_FILENAME}"
