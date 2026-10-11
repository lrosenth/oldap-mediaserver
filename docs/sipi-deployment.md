# SIPI-2 deployment and Cantaloupe fallback

SIPI-2 is the default IIIF backend in `docker-compose.yml` and the Ansible
Compose template. Caddy still forwards `/iiif/*` unchanged to `imageserver:8182`.
Upload, non-image assets, mobile and ZIP workers retain their existing contracts.
No API, oldaplib or frontend release is required solely to select this backend.
The existing `/health` public route remains the **mediahelper** health route.

## Images and policy

The root Makefile selects `SIPI_IMAGE=lrosenth/sipi-2:0.1.0` by default; the local
Compose file has the same default. VM deployment requires a published image
with the target architecture. Use an immutable version tag or a manifest digest;
never overwrite a published version or deploy `latest`. The SIPI version is owned
by the separate sipi-2 repository, not `imageserver/VERSION`. That VERSION and
`IMAGESERVER_TAG` now select only the legacy Cantaloupe fallback. `MEDIAHELPER_TAG`
continues to come from `mediaserver/VERSION` and can be overridden independently.

The generic SIPI image already contains the versioned OLDAP Lua policy and its
environment adapter. There is no derived OLDAP-specific C++ image to rebuild.
`mediaserver.env` supplies the existing media JWT key, issuer, audience and API
URL. The access-token key remains confined to the mediahelper access file.

A valid media capability avoids API calls. A supplied invalid/expired/mismatched
capability is denied, including on cache hits; it never falls back to anonymous.
Tokenless access is enabled by default here and performs OLDAP `unknown` user
permission checks. That reserved pseudo-user has no password; a different service
account needs its configured password. Positive anonymous permissions have a
fixed 600-second lifetime by default; denials/errors are not retained. Restart
clears this in-memory policy cache. Authorization still precedes the image cache.

The IIIF prefix is not a storage prefix. The Lua policy resolves the asset ID to
`<path>/<assetId>/derived/<derivativeName>` under the read-only media root.
`SIPI_PUBLIC_ORIGIN` / `sipi_public_origin` must contain only scheme and authority,
for example `https://media.oldap.org`, without `/iiif/3` or a trailing slash.
SIPI preserves the incoming `/iiif/3` in information/canonical URLs.

## Image upscaling

This OLDAP deployment enables IIIF upscaling for Stories and other viewers that
request sizes prefixed with `^`. Local Compose uses `SIPI_SIZE_UPSCALING=true`;
Ansible uses `sipi_size_upscaling: true`. Set the respective option to false to
restore the generic SIPI default. This does not bypass authorization, preflight
resolution restrictions or configured output limits; it permits enlargement of
the available image pixels. No image rebuild is needed, but the imageserver
container must be recreated through Compose/deployment to apply the environment.

## Local laptop

Put Compose interpolation settings in the ignored root `.env` (not in
`mediaserver.env`):

```dotenv
SIPI_IMAGE=lrosenth/sipi-2:0.1.0
SIPI_PUBLIC_ORIGIN=http://localhost:8088
SIPI_CACHE_MAX_BYTES=1073741824
SIPI_IIIF_WORKERS=4
SIPI_MEMORY_LIMIT=2g
SIPI_SIZE_UPSCALING=true
SIPI_JPEG_QUALITY=90
SIPI_JPEG_SAMPLING=4:4:4
OLDAP_SIPI_ANONYMOUS=true
SIPI_ANONYMOUS_PERMISSION_TTL=600
SIPI_CORS_ORIGINS=*
SIPI_CORS_CREDENTIALS=false
```

A local development image can be selected instead. These `.env` values affect
local Compose; VM settings come from Ansible, not from the laptop's `.env`.
For an image already available locally:

```sh
docker compose config --quiet
docker compose up -d --no-deps imageserver
# Subsequent normal starts use SIPI too:
docker compose up -d
```

There is no need to stop the complete stack. The IIIF container is recreated,
so active image requests can be interrupted briefly; uploads and other services
need not be stopped. `make run-local` retains its additional ZIP worker profiles
and secret-file checks; plain `docker compose up -d` does not enable those profiles.

For a source build, the optional `docker-compose.sipi-test.yml` uses the sibling
`../../sipi-2` checkout. See [local build workflow](sipi-test.md).

The named `sipi_cache` volume stores encoded results and SQLite metadata, survives
container replacement/restarts and ordinary `docker compose down`, and is separate
from originals and the former Cantaloupe cache. Do not use `down -v` during migration.
Old `sipi_test_cache` volumes are left untouched. SIPI runs as the image's UID 10001;
existing media files/directories must be readable/traversable by that user. Do not
recursively change original-file ownership as a migration step.

## VM/home deployment

```sh
make show-versions
make deploy-home SIPI_IMAGE=lrosenth/sipi-2:0.1.0
# After home acceptance:
make deploy-vm SIPI_IMAGE=lrosenth/sipi-2:0.1.0
```

`deploy-home` aliases `deploy-test` (only `media.home.org`). `deploy-vm` aliases
`deploy-production` (only the production inventory group). Both aliases preserve
the explicit Ansible host expression and inventory limit. Existing sudo/Vault
prompts still apply. These are full existing stack deployments: review the
mediahelper tag too, because a changed tag can update that component as well.

The playbook renders the existing Compose project in place, keeps a backup of
its previous Compose file, and lets Compose replace changed services. **Do not
run `docker compose down` first.** Volumes and media paths remain in place. Backend
selection does not automatically convert any stored image or rewrite any ID.
Caddy routes do not change.

SIPI-specific inventory settings are in `ansible/group_vars/all.yml`: public
origin, cache budget, worker count, memory limit, JPEG quality/sampling, CORS,
anonymous enablement/TTL, and optional custom policy. The image is passed by Make
as `sipi_image`; direct Ansible calls must supply it. Wildcard CORS is public
browser access without credentialed cookies. To enable cross-origin cookies,
configure explicit origins and `sipi_cors_credentials: true` together. Normal
OLDAP media query tokens do not require cross-origin cookies.

Deployment checks cover mediahelper version, internal SIPI health via Caddy's
network, and an intentionally invalid media token through the public IIIF route
(403 for SIPI, 401 for legacy Cantaloupe). The invalid token avoids making the
negative authorization probe depend on anonymous OLDAP availability. Afterwards
verify a real public image, an authorized restricted image, denied/expired tokens,
OpenSeadragon zoom and renewal, non-image assets and uploads from the application.
The automated negative probe is not a substitute for that end-to-end acceptance.

## Custom Lua policy

The bundled OLDAP script is the default. For a VM-specific script, set
`sipi_preflight_source` to an absolute controller-side file path. Ansible copies
it to `sipi-preflight.lua`, mounts it read-only at `/etc/sipi/preflight.lua`, and
recreates only the image service when the policy changes (configuration is read
at startup). The script must implement SIPI's preflight contract; secrets belong
in the protected environment/Vault, not in Lua source.

Locally, use an explicit Compose override, for example:

```yaml
services:
  imageserver:
    environment:
      SIPI_PREFLIGHT_SCRIPT: /etc/sipi/preflight.lua
    volumes:
      - ./my-preflight.lua:/etc/sipi/preflight.lua:ro
```

Pass that override with the base file when recreating the service. Merely setting
`SIPI_PREFLIGHT_SCRIPT` does not copy a host file into a container. If changing the
local port exposed by Caddy, also set `SIPI_PUBLIC_ORIGIN` to the browser's origin;
the internal image-server port deliberately stays 8182 in both configurations.

## Explicit fallback

Keep the previous published Cantaloupe image and compatible original deployment
settings available until acceptance. Local fallback (Compose must support
`!reset` and `!override`; tested with Compose 5.2.0):

```sh
docker compose -f docker-compose.yml -f docker-compose.cantaloupe.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.cantaloupe.yml up -d --no-deps imageserver
```

This removes SIPI's entrypoint/security/runtime overrides and selects
`lrosenth/oldap-imageserver:${OLDAP_IMAGESERVER_TAG:-v0.2.1}`. Continue passing that
file while using Cantaloupe; ordinary base Compose switches back to SIPI.
Neither backend's cache is deleted. VM fallback:

```sh
make deploy-home IIIF_BACKEND=cantaloupe IMAGESERVER_TAG=v0.2.1
# Production, when explicitly intended:
make deploy-vm IIIF_BACKEND=cantaloupe IMAGESERVER_TAG=v0.2.1
```

Choose the actual previous mediahelper tag too if the coordinated release needs
that component reverted. The legacy Ansible option `rollback=true` means **stop
and remove the stack**, not restore the preceding version. It is not this fallback.

## Local verification on 2026-10-09

The tested turbo ARM64 image is selected in the laptop's ignored `.env`:
`sipi-benchmark/sipi-2-turbo:verify-0.1.0-arm64`. Release publication and VM rollout
remain separate steps. The registry check for `lrosenth/sipi-2:0.1.0` returned HTTP 500 and
a second inspection stalled; availability was not confirmed; do not assume the default release tag is already published.

An isolated container passed signed and anonymous real-image delivery, JPEG/PNG/
WebP decoding, CORS, HEAD, invalid/expired/wrong-ID/insufficient-permission denial
on warm caches, restart and original TIFF hash preservation. Both backend templates
and local fallback merge were checked. Full Python suite: 331 passed, one skipped;
Black, Poetry metadata and Ansible syntax checks pass (existing Poetry deprecation
warnings). Local activation replaces only `imageserver`; no VM deployment or image
publication is performed by these repository changes. The previous Cantaloupe
`v0.2.1` image is not currently installed on the laptop: its merged configuration
was validated, but its runtime was not relaunched. Pull/retain the actual fallback
image before a remote migration.
