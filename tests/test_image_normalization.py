"""Real libvips conversion tests; also runnable with unittest in mediahelper Docker.

Local environments without the native library skip these cases. Container execution
is required for changes to the delivery normalization contract.
"""

import hashlib
import struct
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageCms

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mediaserver"))
from image_normalization import (
    InvalidImageError,
    normalize_image,
    validate_delivery_tiff,
)
from derivatives import DerivativeProcessor

try:
    import pyvips
except (ImportError, OSError):
    pyvips = None


@unittest.skipIf(
    pyvips is None, "Native libvips required; run in mediahelper container"
)
class ImageNormalizationTests(unittest.TestCase):
    """Validate real pixels, tags, profiles and unchanged originals."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)

    def convert(self, image, **save_options):
        source, output = self.root / "source.tif", self.root / "master.tif"
        image.save(source, **save_options)
        before = hashlib.sha256(source.read_bytes()).digest()
        DerivativeProcessor()._create_pyramidal_tiff(source, output)
        self.assertEqual(before, hashlib.sha256(source.read_bytes()).digest())
        validate_delivery_tiff(output)
        return Image.open(output)

    def test_rgb_gray_rgba_pyramids(self):
        for mode, pixel in [
            ("RGB", (30, 60, 90)),
            ("L", 128),
            ("RGBA", (30, 60, 90, 80)),
        ]:
            with self.subTest(mode=mode), self.convert(
                Image.new(mode, (1025, 769), pixel)
            ) as out:
                self.assertEqual(out.mode, mode)
                self.assertEqual(out.getpixel((0, 0)), pixel)
                self.assertEqual(out.n_frames, 3)
                out.seek(2)
                self.assertEqual(out.size, (256, 192))

    def test_all_exif_orientations(self):
        operations = {
            1: None,
            2: Image.Transpose.FLIP_LEFT_RIGHT,
            3: Image.Transpose.ROTATE_180,
            4: Image.Transpose.FLIP_TOP_BOTTOM,
            5: Image.Transpose.TRANSPOSE,
            6: Image.Transpose.ROTATE_270,
            7: Image.Transpose.TRANSVERSE,
            8: Image.Transpose.ROTATE_90,
        }
        # Use PNG EXIF so Pillow's TIFF decoder does not apply orientation itself.
        image = Image.new("RGB", (3, 2))
        image.putdata([(i * 40, 0, 0) for i in range(6)])
        for orientation, op in operations.items():
            with self.subTest(orientation=orientation):
                source = self.root / "oriented.png"
                exif = Image.Exif()
                exif[274] = orientation
                image.save(source, exif=exif)
                output = self.root / "oriented.tif"
                DerivativeProcessor()._create_pyramidal_tiff(source, output)
                with Image.open(output) as out:
                    expected = image if op is None else image.transpose(op)
                    self.assertEqual(out.size, expected.size)
                    self.assertEqual(out.tobytes(), expected.tobytes())
                    self.assertEqual(out.tag_v2.get(274, 1), 1)

    def test_ushort_full_range_rounding(self):
        values = [0, 128, 129, 32768, 65535]
        image = Image.frombytes("I;16", (5, 1), struct.pack("<5H", *values))
        with self.convert(image) as out:
            self.assertEqual(list(out.get_flattened_data()), [0, 0, 1, 128, 255])

    def test_gray_alpha_is_srgb_with_unchanged_alpha(self):
        with self.convert(Image.new("LA", (2, 2), (128, 73))) as out:
            self.assertEqual(out.mode, "RGBA")
            r, g, b, a = out.getpixel((0, 0))
            self.assertEqual(a, 73)
            self.assertEqual((r, g, b), (129, 129, 129))

    def test_embedded_srgb_profile(self):
        profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
        with self.convert(
            Image.new("RGBA", (512, 512), (200, 100, 50, 73)), icc_profile=profile
        ) as out:
            self.assertEqual(out.getpixel((0, 0)), (200, 100, 50, 73))
            embedded = ImageCms.ImageCmsProfile(BytesIO(out.info["icc_profile"]))
            self.assertEqual(embedded.profile.xcolor_space.strip(), "RGB")

    def test_cmyk_without_profile_and_corrupt_profiles_rejected(self):
        for image, options in [
            (Image.new("CMYK", (2, 2)), {}),
            (Image.new("RGB", (2, 2)), {"icc_profile": b"not a profile"}),
            (
                Image.new("L", (2, 2)),
                {
                    "icc_profile": ImageCms.ImageCmsProfile(
                        ImageCms.createProfile("sRGB")
                    ).tobytes()
                },
            ),
        ]:
            with self.subTest(mode=image.mode), self.assertRaises(InvalidImageError):
                self.convert(image, **options)

    def test_profiled_cmyk_converts_to_srgb(self):
        # libvips ships a CMYK profile; create a genuine profiled fixture with it.
        source = self.root / "cmyk.tif"
        rgb = pyvips.Image.new_from_memory(bytes([60, 90, 120]), 1, 1, 3, "uchar").copy(
            interpretation="srgb"
        )
        cmyk = rgb.icc_transform("cmyk", input_profile="srgb", embedded=False)
        cmyk.tiffsave(str(source))
        output = self.root / "master.tif"
        DerivativeProcessor()._create_pyramidal_tiff(source, output)
        with Image.open(output) as image:
            self.assertEqual(image.mode, "RGB")
            # The CMYK gamut/round trip need not reproduce the original RGB.
            # Compare against an independent Pillow/LittleCMS conversion instead.
            with Image.open(source) as original:
                expected = ImageCms.profileToProfile(
                    original,
                    ImageCms.ImageCmsProfile(BytesIO(original.info["icc_profile"])),
                    ImageCms.createProfile("sRGB"),
                    outputMode="RGB",
                    renderingIntent=1,
                    flags=ImageCms.Flags.BLACKPOINTCOMPENSATION,
                )
                self.assertEqual(image.getpixel((0, 0)), expected.getpixel((0, 0)))
            self.assertIn("icc_profile", image.info)

    def test_rgba16_preserves_alpha_and_sample_range(self):
        source, output = self.root / "rgba16.tif", self.root / "master.tif"
        data = struct.pack("=4H", 65535, 32768, 0, 32768)
        rgba = pyvips.Image.new_from_memory(data, 1, 1, 4, "ushort").copy(
            interpretation="rgb16"
        )
        rgba.tiffsave(str(source))
        DerivativeProcessor()._create_pyramidal_tiff(source, output)
        with Image.open(output) as image:
            self.assertEqual(image.getpixel((0, 0)), (255, 128, 0, 128))

    def test_pyramid_alpha_does_not_bleed_hidden_colors(self):
        image = Image.new("RGBA", (512, 512), (255, 0, 0, 0))
        image.paste((0, 0, 255, 255), (0, 0, 1, 512))
        with self.convert(image) as output:
            output.seek(1)
            self.assertEqual(output.getpixel((0, 0)), (0, 0, 255, 127))

    def test_multipage_rejected_but_pyramid_can_be_reimported(self):
        source, output = self.root / "pages.tif", self.root / "master.tif"
        first = Image.new("RGB", (512, 512), (20, 40, 60))
        first.save(source, save_all=True, append_images=[first])
        with self.assertRaises(InvalidImageError):
            DerivativeProcessor()._create_pyramidal_tiff(source, output)
        with self.convert(first):
            pass
        DerivativeProcessor()._create_pyramidal_tiff(output, self.root / "again.tif")
        validate_delivery_tiff(self.root / "again.tif")

    def test_float_and_oversized_headers_rejected(self):
        for image in [
            pyvips.Image.black(2, 2).cast("float"),
            pyvips.Image.black(30001, 1),
            pyvips.Image.black(11000, 10000),
        ]:
            with self.assertRaises(InvalidImageError):
                normalize_image(image)

    def test_postcondition_rejects_plain_and_16bit_tiff(self):
        path = self.root / "invalid.tif"
        for mode in ["RGB", "I;16"]:
            Image.new(mode, (2, 2)).save(path)
            with self.assertRaises(InvalidImageError):
                validate_delivery_tiff(path)


if __name__ == "__main__":
    unittest.main()
