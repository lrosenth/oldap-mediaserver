"""One-off migration checks; native conversion also runs in mediahelper Docker."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repair_image_derivatives as repair

try:
    import pyvips
except (ImportError, OSError):
    pyvips = None


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "media"
        self.target = self.root / "project/image/id/derived/master.tif"
        self.source = self.target.parent.parent / "original/image.tif"
        self.source.parent.mkdir(parents=True)
        self.target.parent.mkdir()
        image = Image.new("RGB", (32, 16), (40, 80, 120))
        image.save(self.source, tiffinfo={274: 8})
        self.target.write_bytes(self.source.read_bytes())
        self.old = self.target.read_bytes()
        self.original = self.source.read_bytes()
        self.backups = self.base / "backups"

    def run_script(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = repair.main([str(self.root), *args])
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_audit_is_read_only(self):
        before = sorted(self.base.rglob("*"))
        code, records = self.run_script()
        self.assertEqual(code, 0)
        self.assertEqual(records[0]["status"], "needs_repair")
        self.assertEqual(sorted(self.base.rglob("*")), before)
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_missing_selection_and_unsafe_backup(self):
        code, _ = self.run_script("--asset-id", "missing")
        self.assertEqual(code, 1)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.run_script("--apply", "--backup-dir", str(self.root / "backups"))

    def test_ambiguous_original_and_symlink_rejected(self):
        extra = self.source.with_name("extra.jpg")
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            repair.repair(self.target, self.root, self.backups)
        extra.unlink()
        self.source.unlink()
        self.source.symlink_to(self.target)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            repair.repair(self.target, self.root, self.backups)
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_apple_metadata_is_ignored_and_preserved(self):
        sidecar = self.source.with_name("._" + self.source.name)
        finder = self.source.with_name(".DS_Store")
        for path in (sidecar, finder):
            path.write_bytes(b"Apple metadata")
        with patch.object(
            repair.DerivativeProcessor,
            "generate",
            side_effect=ValueError("decode failed"),
        ) as generate:
            code, records = self.run_script(
                "--apply", "--backup-dir", str(self.backups)
            )
        self.assertEqual(code, 1)
        self.assertEqual(records[0]["message"], "decode failed")
        self.assertEqual(generate.call_args.args[0], self.source.resolve())
        for path in (sidecar, finder):
            self.assertEqual(path.read_bytes(), b"Apple metadata")
        self.source.unlink()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            repair.repair(self.target, self.root, self.backups)

    def test_conversion_failure_preserves_derivative(self):
        with patch.object(
            repair.DerivativeProcessor,
            "generate",
            side_effect=ValueError("decode failed"),
        ):
            code, records = self.run_script(
                "--apply", "--backup-dir", str(self.backups)
            )
        self.assertEqual(code, 1)
        self.assertEqual(records[0]["status"], "error")
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertFalse(list(self.target.parent.glob(".sipi-repair-*")))

    @unittest.skipIf(pyvips is None, "Native libvips required")
    def test_native_repair_backup_and_idempotence(self):
        sidecar = self.source.with_name("._" + self.source.name)
        sidecar.write_bytes(b"Apple metadata")
        self.target.chmod(0o644)
        code, records = self.run_script("--apply", "--backup-dir", str(self.backups))
        self.assertEqual(code, 0, records)
        self.assertEqual(records[0]["status"], "repaired")
        self.assertEqual(Path(records[0]["backup"]).read_bytes(), self.old)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(sidecar.read_bytes(), b"Apple metadata")
        repair.validate_delivery_tiff(self.target)
        with Image.open(self.target) as image:
            self.assertEqual(image.size, (16, 32))
            self.assertEqual(image.getpixel((0, 0)), (40, 80, 120))
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o644)
        new_hash = repair.digest(self.target)
        code, records = self.run_script("--apply", "--backup-dir", str(self.backups))
        self.assertEqual(code, 0)
        self.assertEqual(records[0]["status"], "compatible")
        self.assertEqual(repair.digest(self.target), new_hash)

    @unittest.skipIf(pyvips is None, "Native libvips required")
    def test_failed_publication_can_resume_with_existing_backup(self):
        with patch.object(repair.os, "replace", side_effect=OSError("rename failed")):
            code, _ = self.run_script("--apply", "--backup-dir", str(self.backups))
        self.assertEqual(code, 1)
        self.assertEqual(self.target.read_bytes(), self.old)
        backup = self.backups / self.target.relative_to(self.root)
        self.assertEqual(backup.read_bytes(), self.old)
        code, records = self.run_script("--apply", "--backup-dir", str(self.backups))
        self.assertEqual(code, 0, records)
        self.assertEqual(records[0]["status"], "repaired")
        self.assertEqual(backup.read_bytes(), self.old)

    @unittest.skipIf(pyvips is None, "Native libvips required")
    def test_changed_original_prevents_publication(self):
        generate = repair.DerivativeProcessor.generate

        def changing_source(processor, *args):
            result = generate(processor, *args)
            self.source.write_bytes(self.original + b"changed")
            return result

        with patch.object(repair.DerivativeProcessor, "generate", changing_source):
            code, records = self.run_script(
                "--apply", "--backup-dir", str(self.backups)
            )
        self.assertEqual(code, 1)
        self.assertIn("Original changed", records[0]["message"])
        self.assertEqual(self.target.read_bytes(), self.old)

    @unittest.skipIf(pyvips is None, "Native libvips required")
    def test_conflicting_backup_never_overwritten(self):
        backup = self.backups / self.target.relative_to(self.root)
        backup.parent.mkdir(parents=True)
        backup.write_bytes(b"earlier backup")
        code, _ = self.run_script("--apply", "--backup-dir", str(self.backups))
        self.assertEqual(code, 1)
        self.assertEqual(backup.read_bytes(), b"earlier backup")
        self.assertEqual(self.target.read_bytes(), self.old)


if __name__ == "__main__":
    unittest.main()
