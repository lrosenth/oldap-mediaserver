# oldap-mediaserver
A server infrastructure for media in OLDAP



## Overview

`oldap-mediaserver` provides the media infrastructure around OLDAP, in particular:

- **Upload server** (Flask): receives uploads, checks permissions, converts media when needed, stores files on disk, and creates a `shared:MediaObject` via `oldap-api`.
- **Image server** (Cantaloupe IIIF): serves images via the **IIIF Image API**.
- **Cantaloupe delegate** (`delegates.rb`): maps an IIIF identifier to a file on disk using information stored in the `shared:MediaObject`.

The design goal is a clean separation between:

- **Identity** (stable ID / key)
- **Storage** (where the files live)
- **Representation** (which derived file is served)

This keeps URLs stable even if derivatives are regenerated.

## Storage layout

Files are stored under a project and media-type folder. Each uploaded item gets its own asset folder identified by `assetId` (or more generally `identifier`).

Layout (relative to the media root, e.g. `/data/images`):

```
<projectShortName>/<media_type>/<optional/sub/path>/<assetId>/
    original/
        <original filename as uploaded>
    derived/
        <derivativeName>        # e.g. iiif.jp2 or master.tif
        (more derivatives later: preview.jpg, thumb.jpg, stream.mp4, ...)
```

Notes:

- `original/` always contains the exact uploaded file.
- `derived/` contains generated representations used for delivery (IIIF, previews, etc.).
- For images, the IIIF source file is typically stored as `derived/iiif.jp2` (JPEG2000) or `derived/master.tif` (pyramidal TIFF). Which one is used is declared in the MediaObject.

## How IIIF resolution works

The IIIF URL contains only the stable key (`assetId`):

- `.../iiif/3/<assetId>/info.json`
- `.../iiif/3/<assetId>/full/max/0/default.jpg`

Cantaloupe calls the Ruby delegate to translate `<assetId>` into an on-disk file path.

### Fast path (token present)

If the client supplies a `token` query parameter, the delegate reads the JWT payload and avoids API calls.

The token is expected to contain at least:

- `id` (the `assetId`)
- `path` (base folder, without `assetId`)
- `derivativeName` (the filename inside `<assetId>/derived/`)

### Fallback path (no token)

If no valid token is present, the delegate assumes the user `unknown` and performs **one** `oldap-api` request to fetch the MediaObject.

## Required MediaObject fields

For image delivery via Cantaloupe, the `shared:MediaObject` (or subclass) must provide:

- `shared:assetId` — stable key used in the IIIF URL and for efficient lookup in `oldap-api`
- `shared:path` — base directory containing the `<assetId>/original` and `<imageId>/derived` folders
- `shared:derivativeName` — filename of the served file inside `<assetId>/derived/` (e.g. `iiif.jp2` or `master.tif`)
- `shared:protocol` — typically `iiif` for images (other media may use `http` later)

## Local development notes

When `oldap-api` runs on the host machine (not in Docker) and the image server runs in Docker, **do not use** `http://localhost:8000` inside the container.

Use Docker Desktop’s host gateway instead:

- `OLDAP_API_URLhttp://host.docker.internal:8000`

The `imageserver/Makefile` targets `docker-run` and `docker-run-local` set this accordingly.

### Common Docker commands

```bash
# (re)build local multi-arch image
make -C imageserver docker-build-local

# start image server (local tag)
make -C imageserver docker-run-local

# stop/remove container
docker rm -f oldap-imageserver
```

## Cantaloupe cache

Cantaloupe uses a filesystem-backed derivative cache.

- Inside the container, the cache is stored in `/data/images/cache`.
- In local Docker Compose, this maps to `./data/cache`.
- In the server deployment, this maps to `<media_root>/cache` (for the current Ansible defaults: `/data/media/cache`).

If you need to purge cached IIIF derivatives after changing image-processing settings or delegate logic, it is safe to remove the cache directory contents while the stack is stopped:

```bash
rm -rf data/cache/*
```


## prerequisites
- docker
- poetry with export plugin: `poetry self add poetry-plugin-export`
