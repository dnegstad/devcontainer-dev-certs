# Releasing

This repository ships four components together on a single release trigger:

- The devcontainer feature (`ghcr.io/dnegstad/devcontainer-dev-certs/devcontainer-dev-certs`)
- The host VS Code extension (`dnegstad.devcontainer-dev-certs-host`)
- The remote VS Code extension (`dnegstad.devcontainer-dev-certs-remote`)
- The host CLI (`@devcontainer-dev-certs/cli`)

All four share one repo-wide version. A release is one GitHub Release; everything downstream runs from `.github/workflows/release-feature.yml`.

## Normal release procedure

1. Verify every component is at the version you intend to release. `bump-version.yml` keeps them in lockstep automatically after the previous release, so this usually means "merge the open `chore/bump-X.Y.Z-pre` PR and then promote `X.Y.Z-pre` to `X.Y.Z`" via a separate bump PR.
2. Create a GitHub Release with tag `vX.Y.Z` (must match the component versions exactly — `validate-release` will fail the workflow otherwise).
3. Publish the GitHub Release. The `release: [released]` trigger starts the pipeline.

The workflow:

- Validates that the tag matches every component's `package.json` / `devcontainer-feature.json` version.
- Builds and tests everything via `build-extensions.yml` in production mode, producing VSIX files and the CLI tarball as workflow artifacts.
- Publishes the devcontainer feature to GHCR with build provenance.
- Attests VSIX provenance via `actions/attest-build-provenance` and attaches both VSIXes to the GitHub Release.
- Publishes the CLI to npm via OIDC trusted publishing (with `--provenance`), attests the tarball via `actions/attest-build-provenance`, and attaches the tarball to the GitHub Release.

No manual publish commands. The GitHub Release is the trigger; CI does the rest.

## One-time bootstrap: CLI npm trusted publishing

npm's trusted publishing requires the package to exist before the trust policy can be configured. The first time we publish `@devcontainer-dev-certs/cli` we have a chicken-and-egg problem: the CI workflow can't authenticate to npm yet (no trust policy), but the trust policy can't be created yet (no package).

We resolve this by publishing a content-stub version manually under a prerelease tag that no consumer's range query will satisfy, then configuring the trust policy, then letting CI publish all real versions from then on.

This procedure happens **once** in the lifetime of the package. After the trust policy is configured the workflow takes over and no maintainer needs to touch npm credentials again.

### Steps

1. Make sure you have `npm` configured with an account that's a member of the `@devcontainer-dev-certs` org.

   ```bash
   npm login
   npm whoami
   ```

2. From a clean checkout, on a throwaway branch (we never push this — the version mangling is local only):

   ```bash
   git checkout -b chore/bootstrap-npm-stub
   cd src/cli
   npm version 0.0.0-bootstrap --no-git-tag-version
   npm publish --access public
   ```

   `prepublishOnly` produces the minified bundle. `npm publish` uploads it under the prerelease tag `0.0.0-bootstrap`. Because it's a prerelease, it doesn't match `^1.0.0`, `*`, or any other default range query — installers asking for the package won't get the stub.

3. Mark the stub as deprecated so anyone who explicitly pins to it sees a warning:

   ```bash
   npm deprecate @devcontainer-dev-certs/cli@0.0.0-bootstrap \
     "Stub version published to bootstrap trusted publishing. Install @devcontainer-dev-certs/cli@latest."
   ```

4. Discard the throwaway branch:

   ```bash
   cd ../..
   git checkout main
   git branch -D chore/bootstrap-npm-stub
   ```

5. Configure the trusted publisher on npmjs.com:

   - Navigate to <https://www.npmjs.com/package/@devcontainer-dev-certs/cli>
   - Open the **Settings** tab on the package page
   - Scroll to the **Trusted Publisher** section
   - Add a publisher with:
     - Publisher type: **GitHub Actions**
     - Organization / user: `dnegstad`
     - Repository: `devcontainer-dev-certs`
     - Workflow filename: `release-feature.yml`
     - Environment: `release`
     - Allowed actions: **npm publish** (required for configs created after May 20, 2026)
   - Save.

6. Cut the first real release (`v1.4.0` or whatever the next coordinated repo-wide version is) through the normal procedure above. CI authenticates via OIDC, publishes with `--provenance`, attaches the tarball to the Release.

7. Verify the first real release end-to-end:

   ```bash
   # Tarball attestation via GitHub
   gh release download v1.4.0 --pattern '*.tgz' --repo dnegstad/devcontainer-dev-certs
   gh attestation verify devcontainer-dev-certs-cli-*.tgz --repo dnegstad/devcontainer-dev-certs

   # Provenance on the npm registry
   npm view @devcontainer-dev-certs/cli@1.4.0
   ```

   Both should report successful verification with the workflow run that produced the artifact.
