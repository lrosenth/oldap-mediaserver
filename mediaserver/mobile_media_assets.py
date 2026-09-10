"""Crash-recoverable image preparation and exact-owned publication for mobile v1."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from derivatives import DerivativeProcessor
from media import (
    InvalidHeifError,
    MediaType,
    UploadClassification,
    detect_heif_variant,
    probe_heif_page_count,
)
from storage import AssetAlreadyExistsError, safe_subpath, store_original_with_sha256


OWNER_MARKER = ".oldap-mobile-owner.json"
OWNER_MARKER_TEMP = f"{OWNER_MARKER}.tmp"
DERIVATIVE_NAME = "master.tif"
RENAME_NOREPLACE = 1


class MobileMediaAssetError(RuntimeError):
    """Reject invalid content or an unsafe/inconsistent storage boundary."""


@dataclass(frozen=True, slots=True)
class MobileAssetSpec:
    """Immutable upload facts that own one work and final asset directory."""

    upload_id: str
    client_asset_id: str
    original_name: str
    original_mime_type: str
    byte_length: int
    checksum: str
    storage_path: str
    upload_directory: Path


@dataclass(frozen=True, slots=True)
class MobilePublication:
    """Exact durable evidence accepted by the OLDAP internal commit."""

    owner_upload_id: str
    asset_id: str
    byte_length: int
    checksum: str
    derivative_names: tuple[str, ...]
    storage_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ownerUploadId": self.owner_upload_id,
            "assetId": self.asset_id,
            "byteLength": self.byte_length,
            "checksum": self.checksum,
            "derivativeNames": list(self.derivative_names),
            "storagePath": self.storage_path,
        }


class MobileMediaAssetStore:
    """Prepare in private storage, publish no-replace, and compensate exact ownership."""

    def __init__(
        self,
        media_root: Path,
        *,
        derivatives: DerivativeProcessor | None = None,
    ) -> None:
        self.media_root = media_root.resolve()
        self.derivatives = derivatives or DerivativeProcessor()

    def verify_original(self, spec: MobileAssetSpec) -> str:
        """Verify exact length, SHA-256, MIME signature, and HEIF single-image scope."""

        source = self._source(spec)
        digest = hashlib.sha256()
        size = 0
        header = b""
        with source.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                if not header:
                    header = chunk[:4096]
                size += len(chunk)
                digest.update(chunk)
        checksum = f"sha256:{digest.hexdigest()}"
        if size != spec.byte_length or checksum != spec.checksum:
            raise MobileMediaAssetError(
                "Original bytes do not match the declared digest."
            )
        detected = _detected_mime(header)
        if detected != spec.original_mime_type:
            raise MobileMediaAssetError(
                "Original content does not match its MIME type."
            )
        if detected in {"image/heic", "image/heif"}:
            try:
                if probe_heif_page_count(source) != 1:
                    raise MobileMediaAssetError("HEIF collections are not accepted.")
            except InvalidHeifError as error:
                raise MobileMediaAssetError(
                    "HEIF image structure is invalid."
                ) from error
        return checksum

    def prepare(self, spec: MobileAssetSpec) -> None:
        """Create and fsync one complete upload-owned work asset."""

        work = self._work_root(spec)
        self._remove_owned_work_if_present(work, spec, allow_missing_marker=True)
        work.mkdir(mode=0o700)
        try:
            original = work / "original"
            derived = work / "derived"
            original.mkdir()
            derived.mkdir()
            stored = store_original_with_sha256(
                self._source(spec), original / spec.original_name
            )
            if (
                stored.size_bytes != spec.byte_length
                or f"sha256:{stored.sha256}" != spec.checksum
            ):
                raise MobileMediaAssetError(
                    "Prepared original differs from its upload."
                )
            try:
                result = self.derivatives.generate(
                    stored.path,
                    derived,
                    UploadClassification(
                        media_type=MediaType.IMAGE,
                        target_format="tiff",
                        original_mime_type=spec.original_mime_type,
                        dcterms_type="dcmitype:StillImage",
                        protocol="iiif",
                    ),
                )
            except OSError:
                raise
            except Exception as error:
                raise MobileMediaAssetError("Image rendition failed.") from error
            if result.primary.name != DERIVATIVE_NAME or not result.primary.is_file():
                raise MobileMediaAssetError(
                    "The canonical image derivative is incomplete."
                )
            _write_json_exclusive(work / OWNER_MARKER, _owner_marker(spec))
            _fsync_tree(work)
            _fsync_directory(work.parent)
        except Exception:
            self._remove_owned_work_if_present(work, spec, allow_missing_marker=True)
            raise

    def publish(self, spec: MobileAssetSpec) -> MobilePublication:
        """Copy durably, then atomically publish one exact upload-owned asset.

        Private upload state and final media are separate container mounts in
        production. Linux cannot rename across those mountpoints, even when the
        host paths share a physical filesystem. The complete private work tree
        is therefore copied to an owner-marked staging directory beside the
        final asset before the same-mount no-replace rename.
        """

        final = self.final_root(spec)
        work = self._work_root(spec)
        staging = self.publication_staging_root(spec)
        final.parent.mkdir(parents=True, exist_ok=True)
        _require_within(final.parent.resolve(), self.media_root)
        if final.exists() or final.is_symlink():
            self._verify_asset(final, spec)
            self._remove_owned_staging_if_present(staging, spec)
            self._remove_owned_work_if_present(work, spec)
            return self.publication(spec)
        if work.is_symlink() or not work.is_dir():
            raise MobileMediaAssetError("Prepared mobile asset is unavailable.")
        self._verify_asset(work, spec)
        self._stage_for_publication(work, staging, spec)
        try:
            _rename_directory_noreplace(staging, final)
        except AssetAlreadyExistsError:
            self._verify_asset(final, spec)
            self._remove_owned_staging_if_present(staging, spec)
        _fsync_directory(final.parent)
        self._verify_asset(final, spec)
        self._remove_owned_work_if_present(work, spec)
        return self.publication(spec)

    def compensate(self, spec: MobileAssetSpec) -> None:
        """Atomically hide an exact-owned final and resume safe deletion."""

        final = self.final_root(spec)
        withdrawn = self.compensation_staging_root(spec)
        if final.exists() or final.is_symlink():
            if withdrawn.exists() or withdrawn.is_symlink():
                raise MobileMediaAssetError(
                    "Mobile compensation has conflicting final and withdrawn assets."
                )
            self._verify_asset(final, spec)
            _rename_directory_noreplace(final, withdrawn)
            _fsync_directory(final.parent)
        if not withdrawn.exists() and not withdrawn.is_symlink():
            return
        self._remove_owned_staging_if_present(withdrawn, spec)

    def delete_committed(self, spec: MobileAssetSpec) -> None:
        """Durably remove only the exact mobile-owned committed publication.

        The same owner-marker and rename-first primitive used by compensation
        makes an authoritative staging deletion idempotent across worker crashes.
        A missing final after a repeated, durable lifecycle event is already a
        completed file outcome; unrelated paths are never traversed.
        """

        self.compensate(spec)

    def publication(self, spec: MobileAssetSpec) -> MobilePublication:
        self._verify_asset(self.final_root(spec), spec)
        return MobilePublication(
            owner_upload_id=spec.upload_id,
            asset_id=spec.client_asset_id,
            byte_length=spec.byte_length,
            checksum=spec.checksum,
            derivative_names=(DERIVATIVE_NAME,),
            storage_path=spec.storage_path,
        )

    def final_root(self, spec: MobileAssetSpec) -> Path:
        path = self.media_root / safe_subpath(spec.storage_path) / spec.client_asset_id
        _require_within(path.parent.resolve(), self.media_root)
        return path

    def publication_staging_root(self, spec: MobileAssetSpec) -> Path:
        """Return the deterministic same-filesystem pre-publication directory."""

        final = self.final_root(spec)
        return final.parent / f".{spec.client_asset_id}.{spec.upload_id}.publishing"

    def compensation_staging_root(self, spec: MobileAssetSpec) -> Path:
        """Return the deterministic same-filesystem withdrawn directory."""

        final = self.final_root(spec)
        return final.parent / f".{spec.client_asset_id}.{spec.upload_id}.compensating"

    @staticmethod
    def _source(spec: MobileAssetSpec) -> Path:
        if spec.upload_directory.is_symlink() or not spec.upload_directory.is_dir():
            raise MobileMediaAssetError("Upload directory is unsafe.")
        source = spec.upload_directory / "original.part"
        if source.is_symlink() or not source.is_file():
            raise MobileMediaAssetError("Uploaded original is unavailable.")
        return source

    @staticmethod
    def _work_root(spec: MobileAssetSpec) -> Path:
        return spec.upload_directory / "asset.work"

    def _stage_for_publication(
        self, work: Path, staging: Path, spec: MobileAssetSpec
    ) -> None:
        """Create or recover one complete owner-marked publication staging tree."""

        if staging.exists() or staging.is_symlink():
            if _read_json(staging / OWNER_MARKER) == _owner_marker(spec):
                try:
                    self._verify_asset(staging, spec)
                    return
                except MobileMediaAssetError:
                    self._remove_owned_staging_if_present(staging, spec)
            else:
                self._remove_owned_staging_if_present(staging, spec)

        staging.mkdir(mode=0o700)
        try:
            _write_json_atomic(staging / OWNER_MARKER, _owner_marker(spec))
            original = staging / "original"
            derived = staging / "derived"
            original.mkdir()
            derived.mkdir()
            shutil.copyfile(
                work / "original" / spec.original_name,
                original / spec.original_name,
            )
            shutil.copyfile(
                work / "derived" / DERIVATIVE_NAME,
                derived / DERIVATIVE_NAME,
            )
            _fsync_tree(staging)
            _fsync_directory(staging.parent)
            self._verify_asset(staging, spec)
        except Exception:
            self._remove_owned_staging_if_present(staging, spec)
            raise

    @staticmethod
    def _remove_owned_staging_if_present(staging: Path, spec: MobileAssetSpec) -> None:
        """Remove only a deterministic exact-owned partial tree, marker last."""

        if not staging.exists() and not staging.is_symlink():
            return
        if staging.is_symlink() or not staging.is_dir():
            raise MobileMediaAssetError("Mobile staging path is unsafe.")
        marker = _read_json(staging / OWNER_MARKER)
        entries = {entry.name for entry in staging.iterdir()}
        if marker is None:
            if entries == {OWNER_MARKER_TEMP}:
                temporary_marker = staging / OWNER_MARKER_TEMP
                if temporary_marker.is_symlink() or not temporary_marker.is_file():
                    raise MobileMediaAssetError("Mobile staging content is unsafe.")
                temporary_marker.unlink()
                staging.rmdir()
                _fsync_directory(staging.parent)
                return
            if entries:
                raise MobileMediaAssetError(
                    "Refusing to remove unowned mobile staging data."
                )
            staging.rmdir()
            _fsync_directory(staging.parent)
            return
        if marker != _owner_marker(spec):
            raise MobileMediaAssetError(
                "Refusing to remove foreign mobile staging data."
            )
        expected_root_entries = {OWNER_MARKER, "original", "derived"}
        if not entries.issubset(expected_root_entries):
            raise MobileMediaAssetError(
                "Refusing to remove unexpected mobile staging data."
            )
        _validate_removable_directory(
            staging / "original", allowed_files={spec.original_name}
        )
        _validate_removable_directory(
            staging / "derived", allowed_files={DERIVATIVE_NAME}
        )
        _remove_known_file(staging / "original" / spec.original_name)
        _remove_known_file(staging / "derived" / DERIVATIVE_NAME)
        _remove_empty_directory(staging / "original")
        _remove_empty_directory(staging / "derived")
        (staging / OWNER_MARKER).unlink()
        staging.rmdir()
        _fsync_directory(staging.parent)

    def _verify_asset(self, root: Path, spec: MobileAssetSpec) -> None:
        if root.is_symlink() or not root.is_dir():
            raise MobileMediaAssetError("Mobile asset path is unsafe.")
        if {entry.name for entry in root.iterdir()} != {
            OWNER_MARKER,
            "original",
            "derived",
        }:
            raise MobileMediaAssetError("Mobile asset layout is not closed.")
        if _read_json(root / OWNER_MARKER) != _owner_marker(spec):
            raise MobileMediaAssetError("Mobile asset is not owned by this upload.")
        _require_exact_asset_directory(
            root / "original", expected_file=spec.original_name
        )
        _require_exact_asset_directory(root / "derived", expected_file=DERIVATIVE_NAME)
        original = root / "original" / spec.original_name
        derivative = root / "derived" / DERIVATIVE_NAME
        if (
            original.is_symlink()
            or derivative.is_symlink()
            or not original.is_file()
            or not derivative.is_file()
            or original.stat().st_size != spec.byte_length
            or _file_checksum(original) != spec.checksum
        ):
            raise MobileMediaAssetError("Mobile asset publication is incomplete.")

    @staticmethod
    def _remove_owned_work_if_present(
        work: Path, spec: MobileAssetSpec, *, allow_missing_marker: bool = False
    ) -> None:
        if not work.exists() and not work.is_symlink():
            return
        if work.is_symlink() or not work.is_dir():
            raise MobileMediaAssetError("Mobile work path is unsafe.")
        marker = _read_json(work / OWNER_MARKER)
        if not allow_missing_marker and marker != _owner_marker(spec):
            raise MobileMediaAssetError("Refusing to remove an unowned work directory.")
        if allow_missing_marker and marker not in (None, _owner_marker(spec)):
            raise MobileMediaAssetError("Refusing to remove an unowned work directory.")
        shutil.rmtree(work)


def _detected_mime(header: bytes) -> str | None:
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    variant = detect_heif_variant(header)
    return variant[0] if variant else None


def _owner_marker(spec: MobileAssetSpec) -> dict[str, Any]:
    return {
        "documentType": "oldap.mobile-media.asset-owner",
        "schemaVersion": "1.0.0",
        "uploadId": spec.upload_id,
        "clientAssetId": spec.client_asset_id,
        "byteLength": spec.byte_length,
        "checksum": spec.checksum,
        "originalName": spec.original_name,
        "derivativeName": DERIVATIVE_NAME,
        "storagePath": spec.storage_path,
    }


def _read_json(path: Path) -> dict[str, Any] | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    """Install complete JSON atomically, leaving only a known recovery temp."""

    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    temporary = path.with_name(OWNER_MARKER_TEMP)
    if temporary.exists() or temporary.is_symlink():
        raise MobileMediaAssetError("Mobile ownership marker staging is unsafe.")
    _write_json_exclusive(temporary, value)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _validate_removable_directory(path: Path, *, allowed_files: set[str]) -> None:
    """Reject symlinks, non-directories, and unexpected compensation entries."""

    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise MobileMediaAssetError("Mobile staging content is unsafe.")
    entries = list(path.iterdir())
    if any(entry.name not in allowed_files for entry in entries):
        raise MobileMediaAssetError("Mobile staging contains unexpected data.")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise MobileMediaAssetError("Mobile staging content is unsafe.")


def _require_exact_asset_directory(path: Path, *, expected_file: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise MobileMediaAssetError("Mobile asset layout is unsafe.")
    entries = list(path.iterdir())
    if {entry.name for entry in entries} != {expected_file}:
        raise MobileMediaAssetError("Mobile asset layout is not closed.")
    if entries[0].is_symlink() or not entries[0].is_file():
        raise MobileMediaAssetError("Mobile asset layout is unsafe.")


def _remove_known_file(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_file():
        raise MobileMediaAssetError("Mobile staging content is unsafe.")
    path.unlink()


def _remove_empty_directory(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise MobileMediaAssetError("Mobile staging content is unsafe.")
    path.rmdir()


def _file_checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _fsync_tree(root: Path) -> None:
    for directory, _, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in files:
            with (current / name).open("rb") as handle:
                os.fsync(handle.fileno())
        _fsync_directory(current)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise MobileMediaAssetError(
            "Mobile asset path escapes the media root."
        ) from error


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise MobileMediaAssetError("renameat2 is required for mobile publication.")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if renameat2(
            -100, os.fsencode(source), -100, os.fsencode(destination), RENAME_NOREPLACE
        ):
            number = ctypes.get_errno()
            if number == errno.EEXIST:
                raise AssetAlreadyExistsError(destination.name)
            raise OSError(number, os.strerror(number), destination)
        return
    if destination.exists() or destination.is_symlink():
        raise AssetAlreadyExistsError(destination.name)
    source.rename(destination)
