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
Explicit identifiers must contain 1–128 URL-safe characters (`A-Z`, `a-z`, `0-9`, `.`, `_`, `~`, `-`). Uploads never overwrite an existing asset directory; duplicate identifiers return `409 Conflict` before any file is written. Failed storage, conversion, or OLDAP registration removes the exclusively reserved asset directory so the identifier can be retried safely.

Layout (relative to the media root, e.g. `/data/images`):

```
<projectShortName>/<media_type>/<optional/sub/path>/<assetId>/
    original/
        <original filename as uploaded>
    derived/
        <derivativeName>        # e.g. iiif.jp2, master.tif, web.mp4, web.mp3
        (optional extra derivatives: preview.jpg, thumb128.jpg, thumb256.jpg, ...)
```

Notes:

- `original/` always contains the exact uploaded file.
- `derived/` contains generated representations used for delivery (IIIF, previews, etc.).
- For images, the IIIF source file is typically stored as `derived/iiif.jp2` (JPEG2000) or `derived/master.tif` (pyramidal TIFF). Which one is used is declared in the MediaObject.
- For video, the HTTP delivery derivative is `derived/web.mp4` (H.264/AAC).
- For audio, the default HTTP delivery derivative is `derived/web.mp3`; `targetFormat=m4a` can produce `derived/web.m4a` when AAC/M4A is preferred.
- For PDF documents, the HTTP delivery derivative is `derived/document.pdf`. The original filename is preserved in `original/`; Poppler also renders first-page previews as `thumb128.jpg` and `thumb256.jpg`.

## How IIIF resolution works

The IIIF URL contains only the stable key (`assetId`):

- `.../iiif/3/<assetId>/info.json`
- `.../iiif/3/<assetId>/full/max/0/default.jpg`

Cantaloupe calls the Ruby delegate to translate `<assetId>` into an on-disk file path.

### Fast path (token present)

If the client supplies a `token` query parameter, the delegate validates the
short-lived media capability JWT and avoids API calls. It requires `typ=media`,
issuer `OLDAP_JWT_ISSUER`, audience `OLDAP_MEDIA_JWT_AUDIENCE`, and a valid
signature from `OLDAP_MEDIA_JWT_SECRET`; an API access token is not accepted.

The token is expected to contain at least:

- `id` (the `assetId`)
- `path` (base folder, without `assetId`)
- `derivativeName` (the filename inside `<assetId>/derived/`)

The Flask upload endpoint has a separate trust path: its
`Authorization: Bearer` token must be an OLDAP access token and is verified
with `OLDAP_ACCESS_JWT_SECRET`. Both keys must match the corresponding values in
the `oldap-api` deployment, but the two keys must never equal each other.

### Fallback path (no token)

If no valid token is present, the delegate assumes the user `unknown` and performs **one** `oldap-api` request to fetch the MediaObject.

## Required MediaObject fields

For image delivery via Cantaloupe, the `shared:MediaObject` (or subclass) must provide:

- `shared:assetId` — stable key used in the IIIF URL and for efficient lookup in `oldap-api`
- `shared:path` — base directory containing the `<assetId>/original` and `<imageId>/derived` folders
- `shared:derivativeName` — filename of the served file inside `<assetId>/derived/` (e.g. `iiif.jp2` or `master.tif`)
- `shared:protocol` — `iiif` for images and `http` for Caddy-served audio/video/document assets

## PDF document uploads

The upload helper treats documents as **PDF-only** assets. A document upload is accepted when media detection identifies a PDF and the stored temporary file contains a PDF header plus EOF marker. This intentionally avoids accepting arbitrary office/document formats until a real conversion and security policy exists.

For a successful PDF upload, the media server creates the same OLDAP-backed asset structure used by the other local media types:

```text
<projectShortName>/document/<optional/sub/path>/<assetId>/
    original/
        <uploaded filename>
    derived/
        document.pdf
        thumb128.jpg
        thumb256.jpg
```

The created MediaObject uses these integration-relevant values:

- `dcterms:type = dcmitype:Text`
- `shared:protocol = http`
- `shared:derivativeName = document.pdf`
- `shared:originalMimeType = application/pdf`
- `shared:serverUrl = MEDIA_BASE_URL`
- `shared:mediaAccessMode = local`

The first PDF page is rendered with Poppler at a bounded resolution and converted into square JPEG thumbnails. Page proportions are preserved and whitespace is added where needed. The upload response includes `thumb128Name`, `thumb256Name`, `thumb128Url`, and `thumb256Url` with the same semantics used for video uploads.

The upload response also includes `mediaType: "document"`, `originalMimeType: "application/pdf"`, `dctermsType: "dcmitype:Text"`, `protocol: "http"`, `assetUrl`, and `derivativeName: "document.pdf"`. Frontends such as FasnachtsPage should use `thumb256Url` for overview previews and render the document itself from `assetUrl` through the normal `/asset/<assetId>` path. IIIF is not involved for PDF documents. Use `/asset/<assetId>/original?download=1` only when the unchanged original file should be downloaded explicitly.

`pdf2image` and Pillow are managed through Poetry. The native Poppler commands cannot be installed by Poetry and are therefore installed as `poppler-utils` inside the media-helper Docker image. No Poppler installation is required on the Docker host.

## Original asset downloads

Original files are served through `/asset/<assetId>/original?token=<jwt>`. The
token must be a valid `typ=media` capability for the asset and include the
storage `path`; for original downloads it should also include `originalName`.
IIIF media may use this original route, but IIIF derivatives stay on
`/iiif/...` and are not served through `/asset/<assetId>` or
`/asset/<assetId>/derived`.

Add `download=1` to request an attachment response:

```bash
curl -I "http://localhost:8088/asset/<assetId>/original?token=<jwt>&download=1"
```

Expected checks:

- `200 OK` for an authorized original.
- `Content-Disposition: attachment; filename="<originalName>"` when `download=1` is present.
- `Access-Control-Allow-Origin` is present only for configured `CORS_ORIGINS`.
- `OPTIONS /asset/<assetId>/original` accepts `GET, HEAD, OPTIONS` for configured browser origins.
- IIIF originals are allowed through `/asset/<assetId>/original`; IIIF derived delivery remains blocked on `/asset/<assetId>` and `/asset/<assetId>/derived`.

Example CORS preflight check:

```bash
curl -i -X OPTIONS \
  -H "Origin: http://localhost:5173" \
  -H "Access-Control-Request-Method: GET" \
  "http://localhost:8088/asset/<assetId>/original?token=<jwt>"
```

## Local development notes

Create the two ignored environment files before starting the stack:

```bash
cp mediaserver.env.example mediaserver.env
cp mediahelper-access.env.example mediahelper-access.env
```

Set `OLDAP_MEDIA_JWT_SECRET` in `mediaserver.env` to the same media key used by
the local `oldap-api`. Set `OLDAP_ACCESS_JWT_SECRET` in
`mediahelper-access.env` to the API's access key. Generate independent values
with `openssl rand -hex 32`; never copy one key into both variables. Docker
Compose gives Cantaloupe only `mediaserver.env`, while the Flask helper receives
both files.

When `oldap-api` runs on the host machine (not in Docker) and the image server runs in Docker, **do not use** `http://localhost:8000` inside the container.

Use Docker Desktop’s host gateway instead:

- `OLDAP_API_URL=http://host.docker.internal:8000`

The `imageserver/Makefile` targets `docker-run` and `docker-run-local` set this accordingly.

### Common Docker commands

```bash
# build the Flask media helper with a tiny Dockerfile-specific context
make -C mediaserver docker-build-local

# (re)build local multi-arch image
make -C imageserver docker-build-local

# start image server (local tag)
make -C imageserver docker-run-local

# stop/remove container
docker rm -f oldap-imageserver
```

The media helper Dockerfile uses the repository root as its build context only
to read `pyproject.toml` and `poetry.lock`. `mediaserver/Dockerfile.dockerignore`
whitelists just those manifests and the helper source files, so local media
data, tar archives, Caddy runtime state, Cantaloupe bundles, and the Git object
store are not sent to Docker during the media helper build.

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
