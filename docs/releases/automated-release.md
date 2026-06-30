# Automated Release

Use the Prepare Release workflow for normal patch, minor, and major releases.
Do not hand-edit `Package.swift` or hand-push a `v*` tag for the normal release
path.

## Why this exists

SwiftPM binary targets require `Package.swift` at the release tag to contain the
exact URL and checksum for the framework zip. That checksum must be computed
from the framework artifact built by CI. The final release tag should therefore
point at a commit that already contains the CI-computed checksum.

## Prepare and publish a release

Start from a clean `main` that already contains the source changes to release.
Then dispatch the prepare workflow:

```bash
gh workflow run prepare-release.yml --ref main -f version=vX.Y.Z
```

The prepare workflow:

- checks out current `origin/main`
- rejects versions that already have a tag, GitHub release, or npm package
- builds `DerpholeMobile.xcframework.zip` on the pinned macOS runner
- updates `Package.swift` with the release URL and checksum
- commits that manifest update to `main`
- creates and pushes the annotated `vX.Y.Z` tag on that commit
- dispatches the Release workflow for the prepared tag

The Release workflow then builds and verifies binaries, publishes npm packages,
and creates the GitHub release with the SwiftPM framework asset.

## Verify publication

After the Release workflow completes, verify the published state:

```bash
git ls-remote origin refs/tags/vX.Y.Z 'refs/tags/vX.Y.Z^{}'
gh release view vX.Y.Z
npm view derphole@X.Y.Z version
npm view derptun@X.Y.Z version
npm view derpssh@X.Y.Z version
```

For the SwiftPM asset, download the release zip and compare it to the checksum
stored in `Package.swift` at the tag:

```bash
tmpdir="$(mktemp -d)"
gh release download vX.Y.Z --pattern DerpholeMobile.xcframework.zip --dir "$tmpdir"
swift package compute-checksum "$tmpdir/DerpholeMobile.xcframework.zip"
git show vX.Y.Z:Package.swift
```

## Recovery

If Prepare Release fails before pushing the tag, fix the workflow or source and
dispatch it again with the same version.

If the tag is pushed but the Release workflow fails, do not create a new local
manifest commit by hand. Fix the release workflow or source on `main`, then use
a new patch version unless the failed tag has not published any GitHub release
or npm packages and you have explicitly decided to replace it.
