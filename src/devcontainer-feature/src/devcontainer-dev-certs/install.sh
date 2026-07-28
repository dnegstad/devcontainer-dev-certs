#!/usr/bin/env bash
set -e

# Options from devcontainer-feature.json (uppercased)
# Keep this literal in sync with the `sslCertDirs` default in
# devcontainer-feature.json (asserted by test/validate-feature.mjs).
DEFAULT_SSL_CERT_DIRS="/etc/ssl/certs:/usr/lib/ssl/certs:/etc/pki/tls/certs:/var/lib/ca-certificates/openssl"
SSL_CERT_DIRS="${SSLCERTDIRS:-${DEFAULT_SSL_CERT_DIRS}}"
# Whether to drop non-existent directories from SSL_CERT_DIRS. A dedicated
# toggle rather than something inferred from "is this the default or an
# override?": the devcontainer CLI exports SSLCERTDIRS set to the declared
# default even when the user didn't specify the option, so install.sh genuinely
# cannot tell an omitted option from one explicitly set to the default value —
# any inference is guesswork. An explicit boolean sidesteps that entirely.
PRUNE_MISSING_CERT_DIRS="${PRUNEMISSINGCERTDIRS:-true}"
GENERATE_DOTNET_CERT="${GENERATEDOTNETCERT:-true}"
SYNC_USER_CERTIFICATES="${SYNCUSERCERTIFICATES:-true}"
SYNC_CONTAINER_CERT="${SYNCCONTAINERCERT:-false}"
EXTRA_CERT_DESTINATIONS="${EXTRACERTDESTINATIONS:-}"
INSTALL_FALLBACK_TOOLS="${INSTALLFALLBACKTOOLS:-false}"

# Resolve our own source directory so the fallback script copy works
# regardless of where the devcontainer CLI mounts us.
FEATURE_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FALLBACK_BIN_PATH="/usr/local/bin/devcontainer-dev-certs-install"

REMOTE_USER="${_REMOTE_USER:-vscode}"
REMOTE_USER_HOME="${_REMOTE_USER_HOME:-/home/${REMOTE_USER}}"

# System-config sink root. Empty in production — every system file
# (/etc/profile.d/*, /etc/environment, the interactive-shell bashrc) is written
# at its real absolute path. Set to a temp dir by test/install-sh.test.mjs so
# the script can be exercised hermetically without touching the host's /etc.
# Validated as an absolute path (or empty) for the same reason every other path
# input is: this value is prefixed onto files we then write to.
DEVCERTS_SYSROOT="${DEVCERTS_SYSROOT:-}"
if [ -n "${DEVCERTS_SYSROOT}" ]; then
    case "${DEVCERTS_SYSROOT}" in
        /*) ;;
        *)
            echo "Error: DEVCERTS_SYSROOT must be an absolute path." >&2
            exit 1
            ;;
    esac
fi
ETC_ENVIRONMENT="${DEVCERTS_SYSROOT}/etc/environment"
PROFILE_DIR="${DEVCERTS_SYSROOT}/etc/profile.d"
# Physical destination for the fallback installer. FALLBACK_BIN_PATH stays the
# unprefixed runtime path — it's what gets exported to /etc/environment and
# profile.d as DEVCONTAINER_DEV_CERTS_INSTALL_BIN — while the actual `install`
# write goes under the sysroot so the hermetic test never touches the host's
# /usr/local/bin.
FALLBACK_BIN_DEST="${DEVCERTS_SYSROOT}${FALLBACK_BIN_PATH}"

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
for varname in SSL_CERT_DIRS PRUNE_MISSING_CERT_DIRS GENERATE_DOTNET_CERT SYNC_USER_CERTIFICATES SYNC_CONTAINER_CERT EXTRA_CERT_DESTINATIONS INSTALL_FALLBACK_TOOLS; do
    case "${!varname}" in
        *$'\n'*)
            echo "Error: feature option ${varname} must not contain newlines." >&2
            exit 1
            ;;
    esac
done

# Prune non-existent dirs from SSL_CERT_DIRS when pruneMissingCertDirs is on
# (the default).
#
# The default sslCertDirs list enumerates CA paths across several distros
# (Debian/Ubuntu, Fedora/RHEL, SUSE); only a subset exists on any given base
# image. OpenSSL silently ignores a missing dir in SSL_CERT_DIR, but some
# consumers do not: Rust's openssl-probe / rustls-native-certs `read_dir` each
# entry and error on a path that isn't there. So by default we keep only the
# dirs that actually exist on this image.
#
# This is a single explicit toggle rather than something inferred from whether
# sslCertDirs was overridden: install.sh can't reliably tell "user omitted the
# option" from "user set it to the default value" (the CLI passes the declared
# default as the env var in both cases). pruneMissingCertDirs=false uses the
# list verbatim — e.g. when a directory is created after install but before it's
# needed and must not be dropped now.
if [ "${PRUNE_MISSING_CERT_DIRS}" = "true" ]; then
    PRUNED_SSL_CERT_DIRS=""
    IFS=':' read -ra _candidate_cert_dirs <<< "${SSL_CERT_DIRS}"
    for _cert_dir in "${_candidate_cert_dirs[@]}"; do
        if [ -d "${_cert_dir}" ]; then
            PRUNED_SSL_CERT_DIRS="${PRUNED_SSL_CERT_DIRS:+${PRUNED_SSL_CERT_DIRS}:}${_cert_dir}"
        else
            echo "  skipping absent CA dir: ${_cert_dir}"
        fi
    done
    SSL_CERT_DIRS="${PRUNED_SSL_CERT_DIRS}"
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
#
# This MUST run before any package-manager invocation below: when a PRIOR
# feature's layer already broke `/tmp`, our own `apt-get update` in the
# installFallbackTools block would otherwise hit the same failure (under
# `set -e`, fatally) before the end-of-script placement this repair used
# to have could ever execute. The copy-up survives the rest of the RUN, so
# running it early both unbreaks our own installs and still corrects the
# committed layer for subsequent features.
if __tmpfix_marker="$(mktemp /tmp/.devcontainer-dev-certs-tmpfix.XXXXXX 2>/dev/null)"; then
    rm -f -- "${__tmpfix_marker}"
    chmod 1777 /tmp 2>/dev/null || true
fi

# Install fallback-script prerequisites if requested. The script requires
# openssl unconditionally and jq for the --bundle-json form; install only
# what's missing so this is a no-op on images that already provide them.
if [ "${INSTALL_FALLBACK_TOOLS}" = "true" ]; then
    declare -a FALLBACK_PKGS=()
    command -v openssl &>/dev/null || FALLBACK_PKGS+=("openssl")
    command -v jq &>/dev/null || FALLBACK_PKGS+=("jq")
    if [ "${#FALLBACK_PKGS[@]}" -gt 0 ]; then
        if command -v apt-get &>/dev/null; then
            apt-get update -y
            apt-get install -y --no-install-recommends "${FALLBACK_PKGS[@]}"
            rm -rf /var/lib/apt/lists/*
        elif command -v apk &>/dev/null; then
            apk add --no-cache "${FALLBACK_PKGS[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y "${FALLBACK_PKGS[@]}"
            dnf clean all
        elif command -v microdnf &>/dev/null; then
            microdnf install -y "${FALLBACK_PKGS[@]}"
            microdnf clean all
        elif command -v yum &>/dev/null; then
            yum install -y "${FALLBACK_PKGS[@]}"
            yum clean all
        elif command -v zypper &>/dev/null; then
            zypper --non-interactive install "${FALLBACK_PKGS[@]}"
            zypper clean
        else
            echo "Warning: installFallbackTools=true but no supported package manager found; skipping." >&2
        fi
    fi
fi

# Deliver the fallback installer to a stable PATH location so non-VS Code
# consumers (JetBrains, Vim, raw CLI) have something to invoke. The script
# is small and inert at rest, so we always copy regardless of options —
# only its runtime prerequisites are gated by installFallbackTools above.
if [ -f "${FEATURE_SRC_DIR}/scripts/setup-cert.sh" ]; then
    mkdir -p "$(dirname "${FALLBACK_BIN_DEST}")"
    install -m 0755 "${FEATURE_SRC_DIR}/scripts/setup-cert.sh" "${FALLBACK_BIN_DEST}"
else
    echo "Warning: scripts/setup-cert.sh not found under ${FEATURE_SRC_DIR}; fallback installer will not be available." >&2
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

# Append KEY="VALUE" to /etc/environment with full shell-metachar escaping.
#
# Two consumers we need to be safe for:
#  - pam_env (the primary reader of /etc/environment on PAM-based logins):
#    line-oriented, parses KEY=VALUE with backslash escapes inside double
#    quotes. \$, \`, \", \\ all decode to the literal character. Newlines
#    are not allowed in values — they'd split the record.
#  - Shell sourcing (some distros' /etc/profile does `. /etc/environment`,
#    and individual users sometimes add it to their own dotfiles): bash
#    inside double quotes evaluates $..., $(...), and `...` — so a value
#    containing `$(rm -rf $HOME)` would execute when sourced if we only
#    escape \ and ". Escape $, backticks, \, and " here so the written
#    line is inert under either reader.
#
# Reject embedded newlines outright — there's no safe-via-escaping path
# for them in /etc/environment's line format.
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
    escaped="${escaped//\$/\\\$}"
    escaped="${escaped//\`/\\\`}"
    echo "${key}=\"${escaped}\"" >> "${ETC_ENVIRONMENT}"
}

# Quote a value for safe single-quoted embedding in a shell script. Single
# quotes prevent every form of bash expansion ($, $(...), `...`, $VAR), so
# wrapping the user-supplied bytes in single quotes in /etc/profile.d/* is
# the most reliable defense — the only character that has to be encoded is
# the single quote itself, via the standard `'\''` end-quote-escape-restart
# pattern.
shell_single_quote() {
    local value="$1"
    # Replace every ' with '\'' so the value can be wrapped in '…'.
    #
    # Bash-escaping note: `\'` inside the pattern half of
    # `${var//pat/repl}` matches a literal single quote, even though
    # the whole expansion is itself inside double quotes. Two layers
    # of parsing are at play and they're easy to conflate:
    #   - The outer string parser sees `"${value//\'/\'\\\'\'}"` as a
    #     double-quoted string. In a plain double-quoted string `\` is
    #     only special before $ ` " \ <newline>, so a stray `\'` would
    #     pass through as the two characters `\` and `'`.
    #   - But INSIDE `${...//pat/repl}` bash hands the pattern off to
    #     its glob/pattern parser, where `\X` means "literal X" for
    #     any X. So the pattern matches just `'` (one character), not
    #     `\'` (two characters). The same applies to the replacement.
    # Verified with `x="a'b"; echo "${x//\'/Y}"` printing `aYb`.
    # Tested round-trips through `source` for embedded / leading /
    # trailing / consecutive quotes and the empty string; tested that
    # `$(...)` and backticks embedded in a quoted value land inside
    # the single-quoted segment and do NOT execute when sourced.
    printf "'%s'" "${value//\'/\'\\\'\'}"
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
# Ensure the sink directories exist before writing. /etc and /etc/profile.d are
# present on every mainstream base image, but a few stripped-down images ship
# without /etc/profile.d — create it so the login-shell export still lands
# (and so the hermetic test can run under an empty DEVCERTS_SYSROOT).
mkdir -p "${PROFILE_DIR}"
mkdir -p "$(dirname "${ETC_ENVIRONMENT}")"

PROFILE_SCRIPT="${PROFILE_DIR}/devcontainer-dev-certs.sh"
: > "${PROFILE_SCRIPT}"
chmod 0644 "${PROFILE_SCRIPT}"

# Append `export KEY='VALUE'` to the profile.d script. Single quotes — not
# double — because every byte of `VALUE` comes from an untrusted feature
# option (anything the user puts in devcontainer.json) and this file is
# sourced by every login shell on the container. Double-quoted strings
# would happily evaluate `$(...)`, backticks, and `$VAR` substitutions at
# source time, turning any unvalidated character in a feature option into
# a code-execution vector. The single-quote wrapping via `shell_single_quote`
# keeps the value byte-literal regardless of what it contains. The
# per-option newline validation upstream still applies; we don't re-check
# here.
append_profile() {
    local key="$1"
    local value="$2"
    local quoted
    quoted="$(shell_single_quote "${value}")"
    echo "export ${key}=${quoted}" >> "${PROFILE_SCRIPT}"
}

# SSL_CERT_DIR is the one profile.d line that needs `$HOME` to remain
# unexpanded at install time so each user picks up their own trust
# directory at login. Emit two adjacent shell tokens — a double-quoted
# segment carrying just `$HOME` + the constant prefix, then a single-
# quoted segment carrying the user-supplied SSL_CERT_DIRS. Bash
# concatenates adjacent quoted strings, so the resulting value is
# `<expanded HOME>/.aspnet/dev-certs/trust:<literal user value>`. Even if
# the SSL_CERT_DIRS regex validation above is later loosened, the user
# portion stays inert because of the single quotes.
# SSL_CERT_DIRS can be empty here if pruning dropped every default CA dir
# (a minimal image with none of the standard paths). Emit the trust dir
# alone in that case — appending a `:` with nothing after it would leave a
# trailing empty path element, the same artifact that trips up Rust's
# dir-walking TLS stacks that the pruning above is meant to avoid.
if [ -n "${SSL_CERT_DIRS}" ]; then
    SSL_CERT_DIRS_SQ="$(shell_single_quote "${SSL_CERT_DIRS}")"
    echo "export SSL_CERT_DIR=\"\$HOME/.aspnet/dev-certs/trust:\"${SSL_CERT_DIRS_SQ}" >> "${PROFILE_SCRIPT}"
else
    echo "export SSL_CERT_DIR=\"\$HOME/.aspnet/dev-certs/trust\"" >> "${PROFILE_SCRIPT}"
fi

append_profile "DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET" "${GENERATE_DOTNET_CERT}"
append_profile "DEVCONTAINER_DEV_CERTS_SYNC_USER" "${SYNC_USER_CERTIFICATES}"
append_profile "DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER" "${SYNC_CONTAINER_CERT}"
append_profile "DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS" "${EXTRA_CERT_DESTINATIONS}"

# Path hints for non-VS Code consumers. These let a postStartCommand or an
# editor "external tool" config invoke the installer and locate the trust
# stores without hardcoding the canonical paths. We export the resolved
# per-user paths into /etc/environment (pam_env can't expand $HOME) and the
# $HOME-expanded form into profile.d so each user gets their own at login.
append_profile "DEVCONTAINER_DEV_CERTS_INSTALL_BIN" "${FALLBACK_BIN_PATH}"
# Profile.d entries that need per-user $HOME expansion at login time.
{
    echo "export DEVCONTAINER_DEV_CERTS_DOTNET_STORE_DIR=\"\$HOME/.dotnet/corefx/cryptography/x509stores/my\""
    echo "export DEVCONTAINER_DEV_CERTS_DOTNET_ROOT_STORE_DIR=\"\$HOME/.dotnet/corefx/cryptography/x509stores/root\""
    echo "export DEVCONTAINER_DEV_CERTS_TRUST_DIR=\"\$HOME/.aspnet/dev-certs/trust\""
} >> "${PROFILE_SCRIPT}"

# Suppress dotnet's first-run HTTPS dev cert provisioning ONLY when the
# host is the source.
#
# The race: on `dotnet run` / `dotnet new webapi` / `dotnet build` of an
# HTTPS-enabled project, dotnet's implicit CertificateManager flow
# writes a fresh self-signed cert into ~/.dotnet/corefx/cryptography/
# x509stores/my/. If the workspace extension is also trying to put OUR
# cert there at the same time, whichever write lands last wins on disk,
# but the OS trust + .NET Root-store state may have been driven by the
# other side — leaving a half-trusted, half-orphaned cert combo (the
# "partially valid certificate on first run" symptom).
#
# Gating rules:
#   - `syncContainerCert: true` → the container is the source, and the
#     container-side "generate" step might literally BE dotnet's
#     implicit auto-gen (some users rely on `dotnet run` to bootstrap
#     the cert that we then push to the host). Suppressing it here
#     would break that source. Leave dotnet's auto-gen ALONE.
#   - `generateDotNetCert: false` AND `syncContainerCert: false` → the
#     user opted out of every managed dotnet dev cert flow. There's
#     nothing to race with; let dotnet behave normally for users who
#     still want HTTPS via the dotnet-managed cert.
#   - `generateDotNetCert: true` AND `syncContainerCert: false` (the
#     default) → the host is generating and the workspace is installing
#     into `my/`. THIS is where the race lives, so set false.
#
# `DOTNET_GENERATE_ASPNET_CERTIFICATE=false` only gates dotnet's
# IMPLICIT path; explicit `dotnet dev-certs https` commands still
# work regardless, so the syncContainerCert case can still use them
# directly if it wants.
SUPPRESS_DOTNET_AUTOGEN="false"
if [ "${SYNC_CONTAINER_CERT}" != "true" ] && [ "${GENERATE_DOTNET_CERT}" = "true" ]; then
    SUPPRESS_DOTNET_AUTOGEN="true"
    append_profile "DOTNET_GENERATE_ASPNET_CERTIFICATE" "false"
fi

# Same empty-safety as the profile.d write above: only join with a `:` when
# there's actually a system CA dir to follow it.
if [ -n "${SSL_CERT_DIRS}" ]; then
    SSL_CERT_DIR_RESOLVED="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust:${SSL_CERT_DIRS}"
else
    SSL_CERT_DIR_RESOLVED="${REMOTE_USER_HOME}/.aspnet/dev-certs/trust"
fi
append_env "SSL_CERT_DIR" "${SSL_CERT_DIR_RESOLVED}"

# Keep the same values in /etc/environment for non-VS-Code PAM-based
# consumers. extraCertDestinations can contain spaces (users routinely
# separate CSV entries with `, `), so unconditionally quote in both sinks.
append_env "DEVCONTAINER_DEV_CERTS_GENERATE_DOTNET" "${GENERATE_DOTNET_CERT}"
append_env "DEVCONTAINER_DEV_CERTS_SYNC_USER" "${SYNC_USER_CERTIFICATES}"
append_env "DEVCONTAINER_DEV_CERTS_SYNC_FROM_CONTAINER" "${SYNC_CONTAINER_CERT}"
append_env "DEVCONTAINER_DEV_CERTS_EXTRA_DESTINATIONS" "${EXTRA_CERT_DESTINATIONS}"
append_env "DEVCONTAINER_DEV_CERTS_INSTALL_BIN" "${FALLBACK_BIN_PATH}"
append_env "DEVCONTAINER_DEV_CERTS_DOTNET_STORE_DIR" "${DOTNET_STORE_DIR}"
append_env "DEVCONTAINER_DEV_CERTS_DOTNET_ROOT_STORE_DIR" "${DOTNET_ROOT_STORE_DIR}"
append_env "DEVCONTAINER_DEV_CERTS_TRUST_DIR" "${TRUST_DIR}"
# Mirror the dotnet-autogen suppression into /etc/environment so PAM-based
# sessions (sshd, console) see the same gating logic as login shells. Same
# conditional as the profile.d write above — see the comment there.
if [ "${SUPPRESS_DOTNET_AUTOGEN}" = "true" ]; then
    append_env "DOTNET_GENERATE_ASPNET_CERTIFICATE" "false"
fi

# Bridge the env into interactive NON-login shells. Neither sink above reaches
# them: /etc/profile.d is sourced only by LOGIN shells, and /etc/environment is
# read only by pam_env (sshd, console getty). A plain
# `docker exec -it <container> bash` — the most common way to poke at a running
# container, as root or the remote user — starts an interactive non-login shell,
# which sources /etc/bash.bashrc (Debian/Ubuntu) or /etc/bashrc (Fedora/RHEL/
# SUSE) and then the user's ~/.bashrc. Without a hook there, that session gets
# no SSL_CERT_DIR (nor the DEVCONTAINER_DEV_CERTS_* vars) at all — the "exec into
# bash and nothing is set" symptom.
#
# Source the profile.d script from the system-wide interactive bashrc rather
# than duplicating the exports: it's the single source of truth, it stays in
# sync automatically, and `$HOME` is set per-user in that context so the
# `$HOME/.aspnet/dev-certs/trust` prefix resolves correctly for whichever user
# opened the shell (root vs. the remote user). Re-sourcing in a login shell —
# where /etc/profile sources /etc/bash.bashrc before profile.d/* — is harmless:
# the script is plain idempotent `export` assignments, not appends.
#
# `sh`/dash non-login interactive shells use $ENV instead and aren't covered
# here; bash is what `docker exec ... bash` and the documented base images use.
#
# Pick the system-wide rc that this image's interactive bash actually sources:
# Debian/Ubuntu read /etc/bash.bashrc automatically; the RPM/SUSE family read
# /etc/bashrc via the default ~/.bashrc skeleton. Append to whichever exists,
# else create the Debian/Ubuntu path (the documented base images).
INTERACTIVE_PROFILE_SCRIPT="/etc/profile.d/devcontainer-dev-certs.sh"
SYSTEM_BASHRC=""
for _candidate in /etc/bash.bashrc /etc/bashrc; do
    if [ -f "${DEVCERTS_SYSROOT}${_candidate}" ]; then
        SYSTEM_BASHRC="${DEVCERTS_SYSROOT}${_candidate}"
        break
    fi
done
if [ -z "${SYSTEM_BASHRC}" ]; then
    SYSTEM_BASHRC="${DEVCERTS_SYSROOT}/etc/bash.bashrc"
    mkdir -p "$(dirname "${SYSTEM_BASHRC}")"
fi
BASHRC_MARKER="# devcontainer-dev-certs: cert env for interactive non-login shells"
if ! { [ -f "${SYSTEM_BASHRC}" ] && grep -qF "${BASHRC_MARKER}" "${SYSTEM_BASHRC}"; }; then
    {
        echo ""
        echo "${BASHRC_MARKER}"
        echo "if [ -r ${INTERACTIVE_PROFILE_SCRIPT} ]; then . ${INTERACTIVE_PROFILE_SCRIPT}; fi"
    } >> "${SYSTEM_BASHRC}"
fi

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
echo "  SSL_CERT_DIR:         ${SSL_CERT_DIR_RESOLVED}"
echo "  fallback installer:   ${FALLBACK_BIN_PATH}"
echo "  generateDotNetCert:   ${GENERATE_DOTNET_CERT}"
echo "  syncUserCertificates: ${SYNC_USER_CERTIFICATES}"
echo "  syncContainerCert:    ${SYNC_CONTAINER_CERT}"
echo "  installFallbackTools: ${INSTALL_FALLBACK_TOOLS}"
if [ "${SUPPRESS_DOTNET_AUTOGEN}" = "true" ]; then
    echo "  DOTNET_GENERATE_ASPNET_CERTIFICATE: false (host generates the dev cert — suppressing dotnet's racing first-run auto-gen)"
else
    echo "  DOTNET_GENERATE_ASPNET_CERTIFICATE: unset (leaving dotnet's default behavior — host is not the dev cert source for this container)"
fi
