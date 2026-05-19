# buildah-tmp-fix

Workaround feature for [containers/buildah#6747](https://github.com/containers/buildah/issues/6747).

## When you need this

You're using podman (or any buildah-based build pipeline) and a devcontainer feature install fails partway through with:

```
Err:N <some-repo> InRelease
  Couldn't create temporary file /tmp/apt.conf.XXX for passing config to apt-key
```

The cause is a buildah bug that resets the mode and ownership of every parent directory of a `RUN --mount=type=bind,target=...` mount target on layer commit. The devcontainer CLI generates exactly this RUN pattern with `target=/tmp/build-features-src/<feature>_0` for every feature, so `/tmp` ends up at `0755 root:root` after the offending feature commits. The next feature that runs `apt-get update` fails because `_apt` (uid 42) can no longer write to `/tmp`.

Docker is not affected. The bug is buildah/podman-specific.

## How to use it

1. Copy this directory into your repo, for example next to your `.devcontainer/`:

   ```
   .devcontainer/
       devcontainer.json
       local-features/
           buildah-tmp-fix/
               devcontainer-feature.json
               install.sh
   ```

2. Reference it from `devcontainer.json`, placed **between** the feature whose install triggers the bug and the next feature that runs `apt-get update`:

   ```json
   {
       "features": {
           "ghcr.io/some/offending-feature:1": {},
           "./local-features/buildah-tmp-fix": {},
           "ghcr.io/jlaundry/devcontainer-features/azure-functions-core-tools:1": {}
       }
   }
   ```

   Declaration order matters: with no explicit `installsAfter` constraints, the devcontainer CLI orders features by the order they appear in `devcontainer.json`. If any of your features declare `installsAfter` that pull them out of declaration order, add a matching `installsAfter` to `buildah-tmp-fix`'s `devcontainer-feature.json` to pin it.

3. Rebuild the container.

## How it works

A bare `chmod 1777 /tmp` doesn't survive the layer commit when `/tmp` is already `1777` in the lower overlay layer — the chmod is a syscall-level no-op and the overlay never copies `/tmp` up with a corrected entry. The fix forces a content-level change by creating and removing a marker file, which forces overlayfs to copy `/tmp` up into the upper layer; the subsequent `chmod` then lands on the upper-layer copy and is captured by the layer commit.

## Limitations

The upstream issue notes that this class of workaround can be non-deterministic in deeper directory hierarchies. For `/tmp` specifically the workaround has been reliable in testing, but if you see a flaky build, rebuilding usually clears it. Track [containers/buildah#6747](https://github.com/containers/buildah/issues/6747) for the upstream fix.
