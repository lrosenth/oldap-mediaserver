# Upload image normalization

Image uploads keep the original bit-identical, with its original metadata and
integrity hash. Only `derived/master.tif` is normalized for SIPI delivery.
`DerivativeProcessor` shares this policy across legacy upload, ZIP import and
mobile preparation. Their existing authentication, storage and registration
contracts are unchanged.

## Delivery contract

The derivative is an uncompressed, tiled BigTIFF with 256x256 tiles and reduced
pyramid IFDs, ending when one tile covers a level. libvips constructs the pyramid
with its default mean reduction. These settings are unchanged; compression tuning
is a separate benchmark decision.

Every output is top-left, unsigned 8-bit, contiguous grayscale, RGB or RGBA with
unassociated alpha. `image_normalization.py` owns normalization and postconditions.
The writer fully evaluates the pixel pipeline; a separate Pillow header inspection
then checks every IFD, layout, profile consistency, dimensions and pyramid flags
before the caller can register/publish the derivative.

## Orientation, samples and color

- Apply EXIF/TIFF orientation to pixels, including mirroring. Remove stale
  orientation and EXIF/XMP/IPTC/Photoshop/descriptive metadata from the derivative;
  the original retains all metadata. The output color profile is retained.
- Accept unsigned 8-bit and 16-bit samples. For unprofiled 16-bit data use
  `round(value / 257)` over the full 0..65535 range, never clamp directly to 255
  or stretch the image's observed minimum/maximum. Floating-point, signed and
  coded pixel representations are rejected, not guessed.
- Supported input interpretations are RGB/sRGB/RGB16, grayscale/GRAY16 and CMYK,
  optionally with alpha. Other interpretations/layouts are explicitly rejected.
- Valid embedded ICC profiles must match the input color channels. Transform
  profiled images (including grayscale and CMYK) to 8-bit sRGB with LittleCMS,
  relative colorimetric intent and black-point compensation. This conversion also
  produces the output's matching embedded sRGB profile. A malformed, mismatching,
  untransformable or over-16-MiB profile is rejected instead of silently ignored.
- Untagged RGB is assumed sRGB and stays untagged. Untagged grayscale without alpha
  remains grayscale; SIPI's untagged-gray policy interprets it as Gamma 2.2.
- Untagged grayscale with alpha becomes RGBA because SIPI has no gray+alpha raster.
  Decode the normalized gray value with Gamma 2.2, then encode sRGB. Alpha is
  processed separately and never color-transformed. Its 16-bit reduction uses the
  same full-range rounding. Alpha is preserved, not flattened onto a background.
- Untagged CMYK is rejected: an output profile cannot supply the missing input
  characterization. The user must supply an appropriately profiled source.

No original is overwritten. Normalization is a delivery conversion, not archival
preservation of bit depth or gamut. Existing repository derivatives are not migrated.

## Limits and errors

Before pixel transformations, apply the existing ZIP image limits consistently to
all derivative generation: at most 30,000 pixels on either axis and 100,000,000
pixels total. These are currently policy constants from `ZipImportLimits`, not new
configuration parameters. Byte quotas and worker resource controls remain separate.

A single image or explicitly marked reduced TIFF pyramid is accepted. Ordinary
multi-page TIFFs and image collections are rejected rather than silently dropping
pages (at most 256 main TIFF directories are considered). Existing ZIP admission
can be stricter than this shared converter.

Normalization-policy and output-contract failures raise `InvalidImageError`; the
legacy `/upload` route returns HTTP 400 with a readable explanation and cleans its
owned asset directory without registering it. Import/mobile callers retain their
existing preparation failure/cleanup contracts. Unexpected native I/O/decoder
failures continue through existing technical-error handling.

## Verification and deployment

```sh
poetry run pytest -q
poetry run black --check mediaserver/image_normalization.py mediaserver/derivatives.py mediaserver/app.py tests/test_image_normalization.py tests/test_document_upload.py
poetry check
git diff --check
```

Native tests require libvips. On hosts without it they are explicitly skipped; run
against the mediahelper runtime image with the current source mounted read-only:

```sh
docker run --rm --network none \
  -v "$PWD:/review:ro" -w /review --entrypoint python \
  lrosenth/oldap-mediahelper:v0.2.12 \
  -m unittest discover -s tests -p test_image_normalization.py -v
```

The suite checks real pixels, all eight orientations, original hashes, 16-bit
rounding, profiles/CMYK, transparent pyramid edges, limits and rejected layouts.
Route tests separately verify that a normalization rejection is HTTP 400 and does
not register an asset. A local isolated SIPI smoke additionally delivered seven
normalized input variants as PNG and JPEG with HTTP 200, including orientation,
CMYK and gray-alpha cases.

Build/release the **mediahelper** image to activate this change. SIPI requires no
rebuild. No running service is replaced by the tests above.

### Local activation (2026-10-10)

The local Compose `.env` now selects `OLDAP_MEDIAHELPER_TAG=normalization-local-20261010`.
The image contains the normalizer and reports `0.2.14-normalization-local`.
Only mediahelper was recreated; SIPI, Caddy and MinIO were left running unchanged.
The previous `v0.2.12` image remains available for rollback. No registry publication
or remote deployment was performed. Twelve native tests exercised packaged image
code; an isolated real multipart upload verified normalization and original-byte
preservation with an in-memory registration stand-in. Public health and missing-auth
checks pass; user-facing upload acceptance remains separate.
