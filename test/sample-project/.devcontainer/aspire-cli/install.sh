#!/usr/bin/env bash
set -euo pipefail
set -x

ASPIRE_INSTALL_URL="https://aspire.dev/install.sh"
TARGET_SCRIPT="/tmp/aspire-install.sh"
QUALITY_OPTION="${QUALITY:-release}"

# Install aspire into /opt/aspire/bin so that aspire setup writes its bundle
# to /opt/aspire (parent of the bin dir, matching aspire's layout convention).
# The directory is world-writable so any container user can run aspire setup
# without needing root. No symlink into /usr/local/bin — aspire uses its own
# resolved path to locate the bundle, so a symlink would redirect it back to
# /usr/local.
ASPIRE_DIR="/opt/aspire"
mkdir --parents "$ASPIRE_DIR/bin"

curl --fail --silent --show-error --location "$ASPIRE_INSTALL_URL" --output "$TARGET_SCRIPT"

bash "$TARGET_SCRIPT" --install-path "$ASPIRE_DIR/bin" --quality "$QUALITY_OPTION"
echo "Aspire installer completed."

# Make /opt/aspire world-writable after the upstream installer runs, so that
# any container user can create the bundle lock and extract the bundle there.
chmod 0777 "$ASPIRE_DIR"

# Expose aspire on PATH via a wrapper script rather than a symlink. A symlink
# would make aspire resolve its install root to /usr/local (based on argv[0]);
# with exec the process sees /opt/aspire/bin/aspire as its own path and writes
# the bundle to /opt/aspire instead.
cat > /usr/local/bin/aspire << 'EOF'
#!/bin/sh
exec /opt/aspire/bin/aspire "$@"
EOF
chmod 0755 /usr/local/bin/aspire

install -d -m 0755 /usr/local/share/aspire-cli