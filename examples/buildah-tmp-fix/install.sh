#!/usr/bin/env bash
# Workaround for containers/buildah#6747:
#   https://github.com/containers/buildah/issues/6747
#
# When a devcontainer feature is installed via
#   RUN --mount=type=bind,from=<stage>,target=/tmp/build-features-src/<feat>_0 ...
# buildah/podman can commit the resulting layer with /tmp reset to mode 0755
# root:root instead of its original 1777. A subsequent feature that runs
# apt-get update then fails because _apt (uid 42) can no longer write to /tmp:
#
#   Couldn't create temporary file /tmp/apt.conf.XXX for passing config to apt-key
#
# Place this feature in devcontainer.json between the offending upstream
# feature and the consumer of apt-get update. A bare `chmod 1777 /tmp` is a
# no-op when /tmp is already 1777 in the lower overlay layer, so we first
# force overlayfs to copy /tmp into the upper layer by creating and removing
# a marker file, then re-assert the mode. No-op on Docker.

set -e

if marker="$(mktemp /tmp/.buildah-tmp-fix.XXXXXX 2>/dev/null)"; then
    rm -f -- "${marker}"
fi
chmod 1777 /tmp 2>/dev/null || true
