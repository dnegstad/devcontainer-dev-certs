# Releasing

This repository ships three components together on a single release trigger:

- The devcontainer feature (`ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs`)
- The host VS Code extension (`dnegstad.devcontainer-dev-certs-host`)
- The remote VS Code extension (`dnegstad.devcontainer-dev-certs-remote`)

All three share one repo-wide version. A release is one GitHub Release; everything downstream runs from `.github/workflows/release-feature.yml`.

## Normal release procedure

1. Verify every component is at the version you intend to release. `bump-version.yml` keeps them in lockstep automatically after the previous release, so this usually means "merge the open `chore/bump-X.Y.Z-pre` PR and then promote `X.Y.Z-pre` to `X.Y.Z`" via a separate bump PR.
2. Create a GitHub Release with tag `vX.Y.Z` (must match the component versions exactly — `validate-release` will fail the workflow otherwise).
3. Publish the GitHub Release. The `release: [released]` trigger starts the pipeline.

The workflow:

- Validates that the tag matches every component's `package.json` / `devcontainer-feature.json` version.
- Builds and tests everything via `build-extensions.yml` in production mode, producing VSIX files as workflow artifacts.
- Publishes the devcontainer feature to GHCR with build provenance.
- Attests VSIX provenance via `actions/attest-build-provenance` and attaches both VSIXes to the GitHub Release.

No manual publish commands. The GitHub Release is the trigger; CI does the rest.
