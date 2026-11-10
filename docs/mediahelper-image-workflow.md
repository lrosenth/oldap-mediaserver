# Mediahelper image build and publication

From the repository root (or `mediaserver/`):

```sh
make docker-build                 # alias: docker-image
make docker-publish               # alias: docker-push
```

These commands concern the mediahelper and its ingest/export/mobile workers.
SIPI-2 is released separately. The retained `imageserver/` Makefile is the legacy
Cantaloupe fallback and has not been converted by this change.

## Build

Set a new component version in `mediaserver/VERSION` for a new release.
The default bundle is `build/mediahelper/<version>` (ignored by Git).
To keep an alternative build separate, pass the same explicit `IMAGE_BUNDLE`
path to both commands; absolute paths and spaces work.

Build requires a **new** bundle directory. It copies the existing Dockerfile's
explicit input allowlist, excluding local environment files, credentials, media,
and database dumps. It builds and loads AMD64 and ARM64 separately with tags
`lrosenth/oldap-mediahelper:v<version>-amd64` and `-arm64`. It never pushes.
The running containers and the `latest` tag are unchanged.

Each image must pass dependency consistency, import checks and real PID-1
shutdown tests (idle TERM, active TERM, active INT). Only after both succeed is
`accepted.json` written, with exact image IDs and input hashes. This smoke
acceptance complements the repository test suite; it is not a replacement for
release-specific codec, upload, or home functional acceptance.

A failed build has no acceptance receipt. Keep its logs for diagnosis and use a
new bundle path for a retry; an existing bundle is never overwritten implicitly.
The underlying Dockerfile still resolves base/OS packages during build. Therefore
publication promotes existing checked IDs and must never rebuild as a substitute.

`make -C mediaserver docker-build-local` remains the separate quick single-platform
`:local` build; it does not qualify for publication. The component target
`docker-run-local` uses that local tag. Its `docker-run` uses the normal version tag, which is created in the registry only
by publication, not by the multiarchitecture local build.

## Publish

Publication verifies the bundle inputs, both accepted local image IDs and the
selected version/repository. It preflights all three destination tags before
pushing anything. Registry/auth/network failures are failures, never interpreted
as missing tags. Existing tags are refused; `latest` is never written.

After each architecture push, its registry digest is retained in `published.json`.
The version's multiarchitecture index is assembled from those immutable digests.
Docker Hub has no conditional tag-create primitive: run one publisher per version
and exclude other manual/CI pushes to these tags during publication.

If publication is interrupted, retain the bundle and inspect `published.json`
and actual registry digests. A repeat refuses already existing tags rather than
silently overwriting them. Resolve partial publication explicitly; do not delete
or bypass acceptance just to make a retry succeed.

Publication neither changes deployment configuration nor runs Ansible. Promote
reviewed images to home and production as separate actions. No new component
version or actual registry publication is part of implementing these commands.

## Verification on 2026-11-10

Full suite: 410 passed, 20 skipped, four subtests passed. Black, Poetry and
whitespace checks pass (existing Poetry metadata deprecations remain). A real
`make docker-build` with a bundle path containing spaces built both AMD64 and
ARM64 and passed all packaged checks. Six worker signal cases passed across the
two platforms. Registry writes are covered by isolated tests, not a real push.
No publication or deployment occurred. See `mediahelper-image-workflow-results.json`.

The private/local bundle and full logs are retained at
`~/Library/Application Support/OLDAP/releases/20261110-media-build-workflow/`.
This builds the existing component version 0.2.17 for workflow verification; it
does not authorize replacing that existing published version. Choose a new
component version for the next actual release.
