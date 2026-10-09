"""Normalize upload derivatives to SIPI's gray/RGB/RGBA8 TIFF contract.

Only derived pixels/metadata are changed; callers retain the bit-identical source.
libvips evaluates pixels lazily. Header limits are checked before transformations;
the TIFF writer forces decoding and a separate header check gates publication.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING

from PIL import Image, ImageCms

from config import ZipImportLimits

if TYPE_CHECKING:
    from pyvips import Image as VipsImage


class InvalidImageError(ValueError):
    """The image cannot be safely normalized under the delivery color policy."""


def _byte_samples(image: VipsImage) -> VipsImage:
    """Round unsigned 16-bit full range to 8-bit without clipping highlights."""
    if image.format == "ushort":
        return (image / 257.0).rint().cast("uchar")
    return image


def validate_source_pages(source: Path, image: VipsImage) -> None:
    """Accept a single image or an explicitly marked TIFF pyramid, never drop pages."""
    pages = image.get("n-pages") if image.get_typeof("n-pages") else 1
    if pages == 1:
        return
    if (
        pages < 1
        or pages > 256
        or not image.get_typeof("vips-loader")
        or image.get("vips-loader") != "tiffload"
    ):
        raise InvalidImageError("Multi-image uploads are not supported.")
    with Image.open(source) as file:
        for index in range(1, file.n_frames):
            file.seek(index)
            if not file.tag_v2.get(254, 0) & 1:
                raise InvalidImageError("Multi-page TIFF uploads are not supported.")


def normalize_image(image: VipsImage) -> VipsImage:
    """Return upright gray/RGB/RGBA8 pixels with consistent color metadata.

    Embedded profiles must parse and match the color channels; LittleCMS converts
    them to sRGB using relative colorimetric intent and black-point compensation.
    Untagged RGB assumes sRGB; gray assumes Gamma 2.2. Alpha is never color-managed.
    Unsupported numeric encodings and ambiguous untagged color spaces are rejected.
    """
    limits = ZipImportLimits()
    if (
        image.width <= 0
        or image.height <= 0
        or max(image.width, image.height) > limits.max_image_axis_pixels
        or image.width * image.height > limits.max_image_pixels
    ):
        raise InvalidImageError("Image dimensions exceed the delivery pixel limits.")
    if image.format not in {"uchar", "ushort"} or image.coding != "none":
        raise InvalidImageError(
            "Only unsigned 8-bit or 16-bit image samples are supported."
        )

    image = image.autorot()
    interpretation = image.interpretation
    color_bands = {
        "srgb": 3,
        "rgb": 3,
        "rgb16": 3,
        "b-w": 1,
        "grey16": 1,
        "cmyk": 4,
    }.get(interpretation)
    if color_bands is None or image.bands not in {color_bands, color_bands + 1}:
        raise InvalidImageError("Unsupported image color space or channel layout.")
    alpha = _byte_samples(image[color_bands]) if image.bands > color_bands else None
    color = image.extract_band(0, n=color_bands)
    profile = (
        image.get("icc-profile-data") if image.get_typeof("icc-profile-data") else None
    )
    if profile is not None:
        try:
            if len(profile) > 16 * 1024 * 1024:
                raise ValueError("ICC profile exceeds the delivery limit")
            parsed = ImageCms.ImageCmsProfile(BytesIO(profile))
            expected = {1: "GRAY", 3: "RGB", 4: "CMYK"}[color_bands]
            if parsed.profile.xcolor_space.strip() != expected:
                raise ValueError("Profile and pixel color space differ")
            color = color.icc_transform(
                "srgb",
                embedded=True,
                depth=8,
                intent="relative",
                black_point_compensation=True,
            )
        except Exception as error:
            raise InvalidImageError(
                "Embedded ICC profile is invalid or incompatible with the image."
            ) from error
    elif color_bands == 4:
        raise InvalidImageError("CMYK images require an embedded ICC profile.")
    else:
        color = _byte_samples(color)
        if color_bands == 1 and alpha is not None:
            # SIPI has no gray+alpha raster. Map Gamma 2.2 gray to linear RGB,
            # then encode sRGB, retaining alpha separately.
            linear = (color / 255.0) ** 2.2
            color = (
                linear.bandjoin([linear, linear])
                .copy(interpretation="scrgb")
                .colourspace("srgb")
            )
        else:
            color = color.copy(interpretation="b-w" if color_bands == 1 else "srgb")
    if alpha is not None:
        color = color.bandjoin(alpha)
    # Original descriptive metadata belongs to the archival source. Avoid stale
    # EXIF/XMP orientation/color claims in the normalized delivery derivative.
    for field in color.get_fields():
        if field.startswith("exif-") or field in {
            "orientation",
            "xmp-data",
            "iptc-data",
            "photoshop-data",
            "image-description",
        }:
            color.remove(field)
    return color


def validate_delivery_tiff(path: Path) -> None:
    """Check every generated IFD before publication, without decoding a full raster.

    The writer has already evaluated pixels. Require tiled uncompressed unsigned
    8-bit gray/RGB/RGBA, top-left orientation and explicitly reduced pyramid levels.
    """
    with Image.open(path) as image:
        if image.format != "TIFF":
            raise InvalidImageError("Image derivative is not TIFF.")
        previous = None
        signature = None
        for index in range(image.n_frames):
            image.seek(index)
            tags = image.tag_v2
            bands = tags.get(277, 1)
            photo = tags.get(262)
            extras = tuple(tags.get(338, ()))
            valid_color = (bands == 1 and photo == 1 and not extras) or (
                photo == 2
                and ((bands == 3 and not extras) or (bands == 4 and extras == (2,)))
            )
            bits = tuple(tags.get(258, (1,)))
            sample_format = tags.get(339, (1,))
            if isinstance(sample_format, int):
                sample_format = (sample_format,)
            current = (bands, photo, extras, tags.get(34675))
            if (
                not valid_color
                or bits != (8,) * bands
                or any(value != 1 for value in sample_format)
                or tags.get(274, 1) != 1
                or tags.get(284, 1) != 1
                or tags.get(259, 1) != 1
                or (tags.get(322), tags.get(323)) != (256, 256)
                or (index > 0 and not tags.get(254, 0) & 1)
                or (signature is not None and current != signature)
                or (
                    previous is not None
                    and image.size
                    != (max(1, previous[0] // 2), max(1, previous[1] // 2))
                )
            ):
                raise InvalidImageError(
                    "Generated TIFF violates the SIPI delivery contract."
                )
            signature = current
            previous = image.size
        if previous is None or max(previous) > 256:
            raise InvalidImageError("Generated TIFF pyramid is incomplete.")
