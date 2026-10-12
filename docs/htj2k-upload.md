# Optional HTJ2K upload target

Ordinary `POST /upload` accepts `targetFormat=htj2k` for a lossless HTJ2K image
in a JPH container, stored as `derived/master.jph`. Omitted `targetFormat` or
`tiff` still produces the recommended uncompressed pyramidal tiled TIFF.
Values are case-insensitive. `jp2`, `j2k`, `jph` and `jpeg` are not aliases.

This is a delivery-format choice, not a change to original preservation:
`original/<filename>` and its checksum remain bit-identical to the upload.
The response and OLDAP `shared:derivativeName` contain `master.jph`; the existing
SIPI Lua resolver uses that name. No OLDAP-specific C++ change is required.
ZIP imports and mobile ingestion keep their TIFF contract. Existing assets are
not rewritten, and no frontend format selector is added here.

## Request

Use the same access token, project, path and permission fields as for TIFF:

```sh
curl --fail-with-body "$MEDIA_URL/upload" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -F 'projectId=fasnacht' \
  -F 'path=bmg' \
  -F 'targetFormat=htj2k' \
  -F 'file=@scan.tif'
```

An HTJ2K repository master is independent of the requested IIIF output format:
clients can still request JPEG, PNG or WebP. Use SIPI-2 as the delivery backend;
the retained Java2D Cantaloupe fallback does not support these masters.
TIFF remains the measured fastest option for this deployment. HTJ2K offers a
smaller losslessly compressed master, without promising faster delivery than TIFF.

## Normalization and encoding

[Shared normalization](image-normalization.md) applies before encoding: orient
pixels, convert valid embedded color profiles to sRGB, reduce unsigned 16-bit
samples to 8-bit and preserve the normalized output profile. Untagged RGB assumes
sRGB; untagged gray retains the documented Gamma 2.2 interpretation. Original
metadata remains in the original file.

SIPI's HTJ2K reader supports unsigned 8-bit gray and RGB. Alpha-bearing images
(including opaque RGBA) return HTTP 400 with `use targetFormat=tiff`; alpha is
never silently removed. Existing restrictions on CMYK profiles, multiple pages,
image dimensions and sample types also apply.

`DerivativeProcessor` writes a private, non-pyramidal uncompressed TIFF to
transfer normalized pixels and ICC to the official Grok 20.4.15 CLI. The encoder
uses `.jph` to enable HT block coding, the reversible 5/3 transform, one lossless
layer, 1024x1024 tiles, and up to six resolution levels (fewer for small images).
No compression-ratio or lossy option is exposed. Lossless refers to the normalized
8-bit pixels, not to recovery of the original bit depth or color gamut.

Grok runs with two threads and a 300-second subprocess timeout. Existing HTTP/
Gunicorn timeouts may impose a shorter request deadline; this route is synchronous.
The temporary TIFF uses request-owned disk space and is removed on success or
caught failure. Plan working storage for that raster as well as the derivative.
Encoding failures return a technical HTTP 500; the route removes its owned asset
and does not register an OLDAP resource. Native diagnostics go to the server log.
A successful encoder exit must also produce a JPH signature/brand; native tests
verify HT markers, pixel equality and ICC preservation, beyond that runtime check.

## Build, tests and release

The mediahelper Dockerfile builds pinned Grok sources and pinned submodules on
the target architecture. Source URLs and SHA-256 digests live in
`mediaserver/grok/fetch_sources.py`. Only native tools, shared libraries and license
files enter `/opt/grok` in the runtime image; no Grok compiler or source tree is
shipped. Grok is AGPL-3.0; upstream licenses and the exact source manifest are
retained under `/opt/grok/licenses`. Builds use system TIFF/PNG/JPEG libraries.

```sh
poetry run pytest -q
poetry check
docker build -f mediaserver/Dockerfile \
  --build-arg MEDIAHELPER_VERSION=htj2k-local \
  -t oldap-mediahelper:htj2k-local .
docker run --rm --network none \
  -v "$PWD/tests:/tests:ro" -w /app --entrypoint python \
  oldap-mediahelper:htj2k-local \
  -m unittest discover -s /tests -p test_htj2k.py -v
```

Native tests require both libvips and Grok; missing tools cause explicit skips.
They cover gray/RGB, profiles, 16-bit reduction, orientation, multi-tile images,
tiny images, original hashes, alpha rejection and failed-encoder cleanup. Flask
tests cover format selection, registration, response fields and failure cleanup.

Publish a new **mediahelper** image and redeploy the upload service to activate.
SIPI's existing Grok reader already supports HTJ2K; no SIPI rebuild is necessary
solely for this upload option. Tests/builds do not alter running services.

### Verification on 2026-10-12

The local suite passed 345 tests (20 native/environment-dependent skips).
Both ARM64 and AMD64 images built successfully; the four HTJ2K and thirteen
normalization tests passed inside both packaged runtimes (AMD64 under emulation).
An isolated real multipart upload preserved RGB/gray originals and registered
`master.jph`. SIPI-2 0.1.3 then served both files as info.json, JPEG thumbnails
and PNG crops (six HTTP 200 responses). No live services or repository assets
were changed. Local verification tags are `oldap-mediahelper:htj2k-local` and
`oldap-mediahelper:htj2k-local-amd64`; neither is published.
