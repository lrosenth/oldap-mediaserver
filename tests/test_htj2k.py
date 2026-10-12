"""HTJ2K conversion contract, including native pixel/ICC roundtrips in Docker.

Run natively: python -m unittest discover -s tests -p test_htj2k.py -v
Native cases skip when libvips or the pinned Grok tools are unavailable.
"""

import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from PIL import Image, ImageCms

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mediaserver"))
from derivatives import DerivativeProcessor
from image_normalization import InvalidImageError

try:
    import pyvips
except (ImportError, OSError):
    pyvips = None


class HTJ2KFailureTests(unittest.TestCase):
    """Failed conversions clean their private intermediate and never hide alpha."""

    def test_alpha_is_rejected_before_encoding(self):
        processor = DerivativeProcessor()
        processor._normalized_image = Mock(
            return_value=SimpleNamespace(hasalpha=lambda: True)
        )
        processor.command_runner = Mock()
        with self.assertRaisesRegex(InvalidImageError, "targetFormat=tiff"):
            processor._create_htj2k(Path("input"), Path("output"))
        processor.command_runner.assert_not_called()

    def test_encoder_errors_cleanup_intermediate(self):
        for outcome in ("exit", "timeout", "invalid", "missing"):
            with self.subTest(
                outcome=outcome
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = SimpleNamespace(
                    hasalpha=lambda: False,
                    width=16,
                    height=8,
                    tiffsave=lambda path, **kwargs: Path(path).write_bytes(
                        b"temporary"
                    ),
                )
                processor = DerivativeProcessor()
                processor._normalized_image = Mock(return_value=image)
                processor.logger = Mock()

                def run(command, **kwargs):
                    self.assertEqual(kwargs["timeout"], 300)
                    self.assertTrue(Path(command[2]).exists())
                    if outcome == "timeout":
                        raise subprocess.TimeoutExpired(command, 300)
                    if outcome == "invalid":
                        Path(command[4]).write_bytes(b"not JPH")
                    return subprocess.CompletedProcess(
                        command,
                        1 if outcome == "exit" else 0,
                        "encoder detail on stdout",
                        "",
                    )

                processor.command_runner = run
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    processor._create_htj2k(root / "source", root / "master.jph")
                self.assertEqual(list(root.glob("htj2k-*")), [])
                if outcome == "exit":
                    processor.logger.error.assert_called_once_with(
                        "Grok HTJ2K encoding failed: %s", "encoder detail on stdout"
                    )


@unittest.skipUnless(
    pyvips is not None
    and shutil.which("grk_compress")
    and shutil.which("grk_decompress"),
    "Native libvips and Grok required; run in mediahelper container",
)
class HTJ2KNativeTests(unittest.TestCase):
    """Verify actual HT codestreams, lossless pixels, normalization and profiles."""

    def test_normalized_pixels_profiles_and_originals(self):
        for mode, size, orientation, tagged in (
            ("RGB", (79, 53), 6, True),
            ("RGB", (1057, 1031), 1, False),
            ("L", (73, 39), 8, False),
            ("RGB", (1, 1), 1, False),
            ("L", (2, 1), 1, False),
            ("I;16", (17, 13), 1, False),
        ):
            with self.subTest(
                mode=mode, size=size
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root / "original.tif", root / "master.jph"
                channels = {"RGB": 3, "L": 1, "I;16": 2}[mode]
                data = bytes(
                    (i * 37 + i // 19) % 256
                    for i in range(size[0] * size[1] * channels)
                )
                image = Image.frombytes(mode, size, data)
                options = {"tiffinfo": {274: orientation}}
                if tagged:
                    options["icc_profile"] = ImageCms.ImageCmsProfile(
                        ImageCms.createProfile("sRGB")
                    ).tobytes()
                image.save(source, **options)
                original_hash = hashlib.sha256(source.read_bytes()).digest()
                processor = DerivativeProcessor()
                # TIFF baseline uses the same normalization but an independent encoder.
                reference = root / "reference.tif"
                processor._create_pyramidal_tiff(source, reference)
                processor._create_htj2k(source, output)
                self.assertEqual(
                    hashlib.sha256(source.read_bytes()).digest(), original_hash
                )
                encoded = output.read_bytes()
                self.assertEqual(encoded[16:24], b"ftypjph ")
                # SIZ Rsiz bit 14 identifies Part 15 HT capability, beyond extension/brand.
                siz = encoded.index(b"\xff\x51")
                self.assertTrue(struct.unpack_from(">H", encoded, siz + 4)[0] & 0x4000)
                decoded = root / "decoded.tif"
                subprocess.run(
                    [
                        "grk_decompress",
                        "-i",
                        str(output),
                        "-o",
                        str(decoded),
                        "-H",
                        "2",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=60,
                )
                with Image.open(reference) as expected, Image.open(decoded) as actual:
                    self.assertEqual(actual.size, expected.size)
                    self.assertEqual(actual.mode, expected.mode)
                    self.assertEqual(actual.tobytes(), expected.tobytes())
                    if tagged:
                        self.assertEqual(
                            actual.info.get("icc_profile"),
                            expected.info.get("icc_profile"),
                        )
                        self.assertTrue(actual.info.get("icc_profile"))
                self.assertEqual(list(root.glob("htj2k-*")), [])

    def test_rgba_upload_requires_tiff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "alpha.png"
            Image.new("RGBA", (12, 7), (10, 20, 30, 128)).save(source)
            with self.assertRaisesRegex(InvalidImageError, "transparency"):
                DerivativeProcessor()._create_htj2k(source, root / "master.jph")
            self.assertFalse((root / "master.jph").exists())


if __name__ == "__main__":
    unittest.main()
