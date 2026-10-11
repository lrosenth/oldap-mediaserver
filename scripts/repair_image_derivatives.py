#!/usr/bin/env python3
"""One-off repository repair; default is a read-only header audit.

Run with the mediahelper dependencies available. Process only */derived/master.tif
with exactly one original in the sibling original/ directory. Reuse the upload
converter, never rewrite originals or contact OLDAP. Run one instance, with
uploads/imports and other repository writers stopped. SIPI readers may stay up.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

# Also works when only this script is mounted into the mediahelper image (/app).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mediaserver"))
sys.path.insert(1, "/app")
from derivatives import DerivativeProcessor
from image_normalization import InvalidImageError, validate_delivery_tiff
from media import MediaType, UploadClassification


def random_access_image(path: str, **kwargs):
    """Use decoder caching for rotations, including with older packaged converters."""
    import pyvips

    return pyvips.Image.new_from_file(path, access="random", revalidate=True)


def digest(path: Path) -> str:
    """Hash a file in bounded memory, including large TIFFs."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fingerprint(path: Path) -> tuple:
    """Detect source replacement/writes during conversion; not a writer lock."""
    s = path.stat()
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def regular(path: Path, root: Path) -> None:
    """Reject symlinks at every path component below the repository root."""
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Symlink is not allowed: {current}")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"Not a regular file: {path}")


def sync_directory(path: Path) -> None:
    """Persist directory entries after backup/publication on the Linux target."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def repair(target: Path, root: Path, backups: Path) -> dict:
    """Validate a replacement, back up the old file, then atomically publish.

    Backup paths mirror repository-relative paths. Existing backups may be reused
    only if identical to the current derivative (retry after failed publication).
    Ownership/mode are retained. Errors leave the old derivative in place until
    os.replace succeeds; a later sync error must be investigated using the backup.
    """
    regular(target, root)
    original_dir = target.parent.parent / "original"
    if original_dir.is_symlink():
        raise ValueError("Symlinked original directory")
    # macOS metadata sidecars are not additional image originals. Leave them intact.
    originals = [
        p
        for p in original_dir.iterdir()
        if p.name != ".DS_Store" and not p.name.startswith("._")
    ]
    if len(originals) != 1:
        raise ValueError("Expected exactly one original; manual selection required")
    source = originals[0]
    regular(source, root)
    source_state, target_state = fingerprint(source), fingerprint(target)
    source_hash, old_hash = digest(source), digest(target)
    attributes = target.stat()
    backup = backups / target.relative_to(root)
    # A backup directory must be private to the operator, never user-controlled.
    for part in [backup, *backup.parents]:
        if part.is_symlink():
            raise ValueError(f"Symlink in backup path: {part}")
        if part == backups:
            break
    backup.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sipi-repair-", dir=target.parent) as tmp:
        processor = DerivativeProcessor()
        # Published v0.2.15 still requests sequential input. Override that hint
        # through the existing injection point: autorotation needs random access.
        processor.vips_loader = random_access_image
        result = processor.generate(
            source,
            Path(tmp),
            UploadClassification(MediaType.IMAGE, "tif", "", "", "iiif"),
        )
        replacement = result.primary
        validate_delivery_tiff(replacement)
        if fingerprint(source) != source_state or digest(source) != source_hash:
            raise ValueError("Original changed during conversion; refusing publication")
        if fingerprint(target) != target_state or digest(target) != old_hash:
            raise ValueError(
                "Derivative changed during conversion; refusing publication"
            )
        if backup.exists():
            if not backup.is_file() or digest(backup) != old_hash:
                raise ValueError("Existing backup differs; use a new backup directory")
        else:
            with target.open("rb") as inp, backup.open("xb") as out:
                shutil.copyfileobj(inp, out)
                out.flush()
                os.fsync(out.fileno())
            shutil.copystat(target, backup)
        if digest(backup) != old_hash:
            raise ValueError("Backup verification failed")
        # Persist newly created backup subdirectories as well as the file entry.
        for directory in [backup.parent, *backup.parent.parents]:
            sync_directory(directory)
            if directory == backups:
                break
        current = replacement.stat()
        if (current.st_uid, current.st_gid) != (attributes.st_uid, attributes.st_gid):
            os.chown(replacement, attributes.st_uid, attributes.st_gid)
        os.chmod(replacement, stat.S_IMODE(attributes.st_mode))
        with replacement.open("rb") as stream:
            os.fsync(stream.fileno())
        new_hash = digest(replacement)
        if fingerprint(target) != target_state or fingerprint(source) != source_state:
            raise ValueError("Repository changed before publication")
        os.replace(replacement, target)
        sync_directory(target.parent)
    return {
        "original": str(source.relative_to(root)),
        "original_sha256": source_hash,
        "previous_sha256": old_hash,
        "new_sha256": new_hash,
        "backup": str(backup),
    }


def main(argv=None) -> int:
    """Emit one JSON record per file and a summary; return 1 on any error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--asset-id", action="append", help="Limit to these asset IDs")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("root must be an existing repository directory")
    backups = args.backup_dir.resolve() if args.backup_dir else None
    if args.apply and backups is None:
        parser.error("--apply requires --backup-dir outside the repository")
    if backups and (backups.is_relative_to(root) or root.is_relative_to(backups)):
        parser.error("backup directory and repository must not overlap")
    counts = dict(compatible=0, needs_repair=0, repaired=0, error=0)
    found = set()

    def emit(record):
        print(json.dumps(record, ensure_ascii=True), flush=True)

    def walk_error(error):
        counts["error"] += 1
        emit({"status": "error", "path": error.filename, "message": str(error)})

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        target = Path(directory) / "master.tif"
        if target.parent.name != "derived" or "master.tif" not in files:
            continue
        asset_id = target.parent.parent.name
        if args.asset_id and asset_id not in args.asset_id:
            continue
        found.add(asset_id)
        record = {"path": str(target.relative_to(root))}
        try:
            regular(target, root)
            try:
                validate_delivery_tiff(target)
                record["status"] = "compatible"
            except (InvalidImageError, OSError, ValueError) as error:
                record.update(status="needs_repair", reason=str(error))
                if args.apply:
                    record.update(repair(target, root, backups), status="repaired")
        except Exception as error:
            record.update(status="error", message=str(error))
        counts[record["status"]] += 1
        emit(record)
    for missing in sorted(set(args.asset_id or []) - found):
        counts["error"] += 1
        emit({"status": "error", "asset_id": missing, "message": "Asset not found"})
    emit({"summary": counts, "apply": args.apply})
    return int(counts["error"] != 0)


if __name__ == "__main__":
    sys.exit(main())
