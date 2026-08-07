"""Idempotent filesystem preparation and promotion for confirmed ZIP imports.

This module deliberately has no API or Flask dependency. It consumes only one
immutable READY manifest and its retained extraction directory, prepares every
asset under a job-owned work root, and promotes complete asset directories with
no-replace semantics. GraphDB commit remains a separate Phase 5 boundary.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID, uuid5

import rfc8785

from derivatives import DerivativeProcessor
from media import MediaType, UploadClassification
from storage import (
    AssetAlreadyExistsError,
    StoragePathEscapeError,
    safe_subpath,
    store_original_with_sha256,
    validate_asset_identifier,
)


OWNER_MARKER = ".oldap-import-owner.json"
RENAME_NOREPLACE = 1


class ImportAssetError(RuntimeError):
    """Raised when a confirmed import cannot prepare a complete asset set."""


@dataclass(frozen=True, slots=True)
class PreparedMediaAsset:
    """One verified asset and its future OLDAP commit facts."""

    entry_index: int
    relative_path: str
    parent_relative_path: str
    asset_id: str
    checksum_sha256: str
    original_name: str
    original_mime_type: str
    dcterms_type: str
    protocol: str
    derivative_name: str
    storage_path: str
    work_root: Path
    final_root: Path | None = None

    def to_commit_item(self) -> dict[str, Any]:
        """Return the closed path-only API commit representation."""

        return {
            "entryIndex": self.entry_index,
            "relativePath": self.relative_path,
            "parentRelativePath": self.parent_relative_path,
            "assetId": self.asset_id,
            "checksumSha256": self.checksum_sha256,
            "originalName": self.original_name,
            "originalMimeType": self.original_mime_type,
            "dctermsType": self.dcterms_type,
            "protocol": self.protocol,
            "derivativeName": self.derivative_name,
            "storagePath": self.storage_path,
        }


@dataclass(frozen=True, slots=True)
class PreparedImportAssets:
    """Complete prepared or promoted media set for one immutable manifest."""

    import_id: str
    manifest_sha256: str
    job_work_root: Path
    media: tuple[PreparedMediaAsset, ...]


class ImportAssetPreparer:
    """Prepare, promote, resume, and compensate job-owned media assets."""

    def __init__(
        self,
        media_root: Path,
        *,
        derivative_processor: DerivativeProcessor | None = None,
    ) -> None:
        self.media_root = media_root
        self.derivatives = derivative_processor or DerivativeProcessor()

    def prepare(
        self,
        import_id: str,
        manifest_sha256: str,
        manifest: dict[str, Any],
        extraction_root: Path,
    ) -> PreparedImportAssets:
        """Prepare every manifest media asset without touching final storage.

        Args:
            import_id: Canonical import UUID.
            manifest_sha256: API-bound lower-case manifest digest.
            manifest: Retained immutable READY manifest.
            extraction_root: Stable validated extraction directory.

        Returns:
            A complete set whose paths remain under the job work directory.

        Raises:
            ImportAssetError: If identity, paths, checksums, or planned media
                facts do not match the retained validation evidence.
        """

        canonical_id = str(UUID(import_id))
        if canonical_id != import_id or not _sha256_value(manifest_sha256):
            raise ImportAssetError("Import identity or manifest digest is invalid.")
        if (
            manifest.get("documentType") != "oldap.zip-import.manifest"
            or manifest.get("schemaVersion") != "1.0.0"
            or manifest.get("importId") != import_id
            or manifest.get("validationOutcome") != "READY"
            or not isinstance(manifest.get("entries"), list)
        ):
            raise ImportAssetError("Only a matching READY manifest can prepare assets.")
        actual_manifest_sha256 = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
        if actual_manifest_sha256 != manifest_sha256:
            raise ImportAssetError("Manifest checksum differs from retained evidence.")
        try:
            project_short_name = _safe_project_short_name(
                manifest["job"]["target"]["projectShortName"]
            )
        except (KeyError, TypeError) as error:
            raise ImportAssetError("Manifest project context is missing.") from error
        extraction = extraction_root.resolve()
        if not extraction_root.is_dir() or extraction_root.is_symlink():
            raise ImportAssetError("Validated extraction root is unavailable.")

        job_root = self.media_root / "_import-work" / import_id
        _reset_owned_job_root(job_root, import_id)
        _write_json_exclusive(job_root / OWNER_MARKER, {"importId": import_id})
        assets_root = job_root / "assets"
        assets_root.mkdir(parents=True)

        prepared: list[PreparedMediaAsset] = []
        indexes: set[int] = set()
        try:
            for entry in manifest["entries"]:
                if not isinstance(entry, dict) or entry.get("disposition") != "IMPORT":
                    continue
                if entry.get("entryType") == "directory":
                    continue
                item = self._prepare_entry(
                    import_id,
                    manifest_sha256,
                    entry,
                    extraction,
                    assets_root,
                    project_short_name,
                )
                if item.entry_index in indexes:
                    raise ImportAssetError("Manifest contains duplicate entry indexes.")
                indexes.add(item.entry_index)
                prepared.append(item)
            if not prepared:
                raise ImportAssetError("READY manifest contains no importable media.")
            _fsync_directory(assets_root)
            _fsync_directory(job_root)
            return PreparedImportAssets(
                import_id=import_id,
                manifest_sha256=manifest_sha256,
                job_work_root=job_root,
                media=tuple(prepared),
            )
        except Exception:
            _remove_owned_job_root(job_root, import_id)
            raise

    def promote(self, prepared: PreparedImportAssets) -> PreparedImportAssets:
        """Promote all complete asset directories without replacing anything.

        Exact job-owned directories left by an interrupted earlier promotion
        are verified and reused. A failure compensates only directories first
        promoted by this call; pre-existing job-owned recovery candidates are
        left for the caller's explicit retry/compensation decision.
        """

        owned_for_attempt: list[PreparedMediaAsset] = []
        result: list[PreparedMediaAsset] = []
        try:
            for item in prepared.media:
                final_parent = (
                    self.media_root / safe_subpath(item.storage_path)
                ).resolve()
                _require_within(final_parent, self.media_root.resolve())
                final_parent.mkdir(parents=True, exist_ok=True)
                final = final_parent / validate_asset_identifier(item.asset_id)
                if final.exists() or final.is_symlink():
                    self._verify_promoted(
                        item, final, prepared.import_id, prepared.manifest_sha256
                    )
                    owned_for_attempt.append(replace(item, final_root=final))
                    shutil.rmtree(item.work_root)
                    result.append(replace(item, final_root=final))
                    continue
                _rename_directory_noreplace(item.work_root, final)
                promoted = replace(item, final_root=final)
                owned_for_attempt.append(promoted)
                result.append(promoted)
                _fsync_directory(final_parent)
            _remove_owned_job_root(prepared.job_work_root, prepared.import_id)
            return replace(prepared, media=tuple(result))
        except Exception:
            self.compensate(replace(prepared, media=tuple(owned_for_attempt)))
            raise

    def compensate(self, promoted: PreparedImportAssets) -> None:
        """Remove only exact asset roots carrying this import's owner marker."""

        for item in reversed(promoted.media):
            if item.final_root is None:
                continue
            marker = _read_owner_marker(item.final_root)
            if marker != _owner_marker(
                promoted.import_id, promoted.manifest_sha256, item
            ):
                raise ImportAssetError("Refusing to remove an unowned asset directory.")
            if item.final_root.is_symlink() or not item.final_root.is_dir():
                raise ImportAssetError("Refusing to remove an unsafe asset path.")
            shutil.rmtree(item.final_root)
            _fsync_directory(item.final_root.parent)

    def _prepare_entry(
        self,
        import_id: str,
        manifest_sha256: str,
        entry: dict[str, Any],
        extraction_root: Path,
        assets_root: Path,
        project_short_name: str,
    ) -> PreparedMediaAsset:
        try:
            index = entry["entryIndex"]
            relative = _safe_manifest_path(entry["normalizedPath"])
            parent = str(entry["parentNormalizedPath"])
            original_name = str(entry["normalizedName"])
            expected_sha256 = str(entry["sha256"])
            content = entry["detectedContent"]
            plan = entry["plannedResource"]
        except (KeyError, TypeError, ValueError) as error:
            raise ImportAssetError("Manifest media entry is incomplete.") from error
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index <= 9_999
            or not _sha256_value(expected_sha256)
            or not isinstance(content, dict)
            or not isinstance(plan, dict)
            or plan.get("kind") != "media"
            or plan.get("resourceClass") != "shared:StagingMediaObject"
            or plan.get("originalName") != original_name
            or not _safe_original_name(original_name)
        ):
            raise ImportAssetError("Manifest media plan is invalid.")
        if str(relative.parent) == ".":
            expected_parent = ""
        else:
            expected_parent = relative.parent.as_posix()
        if parent != expected_parent or relative.name != original_name:
            raise ImportAssetError("Manifest path decomposition is inconsistent.")

        source = extraction_root.joinpath(*relative.parts)
        _require_within(source.resolve(), extraction_root)
        if source.is_symlink() or not source.is_file():
            raise ImportAssetError("Validated source file is unavailable.")

        category = str(content.get("category", ""))
        mime_type = str(content.get("mimeType", ""))
        classification = _classification(category, mime_type, plan)
        asset_id = str(uuid5(UUID(import_id), f"entry:{index}"))
        asset_root = assets_root / asset_id
        original_directory = asset_root / "original"
        derived_directory = asset_root / "derived"
        original_directory.mkdir(parents=True)
        derived_directory.mkdir()
        stored = store_original_with_sha256(source, original_directory / original_name)
        if stored.sha256 != expected_sha256:
            raise ImportAssetError("Extracted original checksum differs from manifest.")
        generated = self.derivatives.generate(
            stored.path, derived_directory, classification
        )
        expected_derivative = str(plan.get("derivativeName", ""))
        if (
            generated.primary.name != expected_derivative
            or not generated.primary.is_file()
        ):
            raise ImportAssetError("Generated derivative differs from manifest plan.")

        storage_path = (
            Path(project_short_name) / classification.media_type.value
        ).as_posix()
        item = PreparedMediaAsset(
            entry_index=index,
            relative_path=relative.as_posix(),
            parent_relative_path=parent,
            asset_id=asset_id,
            checksum_sha256=stored.sha256,
            original_name=original_name,
            original_mime_type=mime_type,
            dcterms_type=classification.dcterms_type,
            protocol=classification.protocol,
            derivative_name=generated.primary.name,
            storage_path=storage_path,
            work_root=asset_root,
        )
        _write_json_exclusive(
            asset_root / OWNER_MARKER,
            _owner_marker(import_id, manifest_sha256, item),
        )
        _fsync_tree(asset_root)
        return item

    @staticmethod
    def _verify_promoted(
        item: PreparedMediaAsset,
        final: Path,
        import_id: str,
        manifest_sha256: str,
    ) -> None:
        if final.is_symlink() or not final.is_dir():
            raise AssetAlreadyExistsError(item.asset_id)
        if _read_owner_marker(final) != _owner_marker(import_id, manifest_sha256, item):
            raise AssetAlreadyExistsError(item.asset_id)
        original = final / "original" / item.original_name
        derivative = final / "derived" / item.derivative_name
        if (
            original.is_symlink()
            or derivative.is_symlink()
            or not original.is_file()
            or not derivative.is_file()
            or _file_sha256(original) != item.checksum_sha256
        ):
            raise ImportAssetError("Existing job-owned asset is incomplete.")


def _classification(
    category: str, mime_type: str, plan: dict[str, Any]
) -> UploadClassification:
    media_types = {
        "image": MediaType.IMAGE,
        "audio": MediaType.AUDIO,
        "video": MediaType.VIDEO,
        "document": MediaType.DOCUMENT,
    }
    target_formats = {
        "image": "tiff",
        "audio": "mp3",
        "video": "mp4",
        "document": "txt" if mime_type == "text/plain" else "pdf",
    }
    expected_facts = {
        "image": ("dcmitype:StillImage", "iiif", "master.tif"),
        "audio": ("dcmitype:Sound", "http", "web.mp3"),
        "video": ("dcmitype:MovingImage", "http", "web.mp4"),
        "document": (
            "dcmitype:Text",
            "http",
            "document.txt" if mime_type == "text/plain" else "document.pdf",
        ),
    }
    try:
        media_type = media_types[category]
        target_format = target_formats[category]
    except KeyError as error:
        raise ImportAssetError(
            "Manifest contains an unsupported media category."
        ) from error
    expected_dcterms, expected_protocol, expected_derivative = expected_facts[category]
    if (
        plan.get("originalMimeType") != mime_type
        or plan.get("dctermsType") != expected_dcterms
        or plan.get("protocol") != expected_protocol
        or plan.get("derivativeName") != expected_derivative
    ):
        raise ImportAssetError("Manifest media delivery facts are inconsistent.")
    return UploadClassification(
        media_type=media_type,
        target_format=target_format,
        original_mime_type=mime_type,
        dcterms_type=expected_dcterms,
        protocol=expected_protocol,
    )


def _owner_marker(
    import_id: str, manifest_sha256: str, item: PreparedMediaAsset
) -> dict[str, Any]:
    return {
        "documentType": "oldap.zip-import.asset-owner",
        "schemaVersion": "1.0.0",
        "importId": import_id,
        "manifestSha256": manifest_sha256,
        "entryIndex": item.entry_index,
        "assetId": item.asset_id,
        "checksumSha256": item.checksum_sha256,
        "derivativeName": item.derivative_name,
    }


def _safe_manifest_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ImportAssetError("Manifest path is invalid.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ImportAssetError("Manifest path is unsafe.")
    return path


def _safe_original_name(value: str) -> bool:
    return (
        bool(value)
        and value not in {".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def _safe_project_short_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ImportAssetError("Manifest project context is invalid.")
    path = safe_subpath(value)
    if len(path.parts) != 1 or path.parts[0] in {".", ".."}:
        raise ImportAssetError("Manifest project context is invalid.")
    return value


def _sha256_value(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise StoragePathEscapeError("Import asset path escapes its root.") from error


def _reset_owned_job_root(path: Path, import_id: str) -> None:
    if path.exists() or path.is_symlink():
        _remove_owned_job_root(path, import_id)
    path.mkdir(parents=True, exist_ok=False)


def _remove_owned_job_root(path: Path, import_id: str) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise ImportAssetError("Import work root is unsafe.")
    marker = _read_json(path / OWNER_MARKER)
    if marker != {"importId": import_id}:
        raise ImportAssetError("Refusing to remove an unowned import workspace.")
    shutil.rmtree(path)


def _read_owner_marker(path: Path) -> dict[str, Any] | None:
    return _read_json(path / OWNER_MARKER)


def _read_json(path: Path) -> dict[str, Any] | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    content = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


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


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Use Linux renameat2 when available, with a controlled host-test fallback."""

    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise ImportAssetError("renameat2 is required for no-replace promotion.")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            RENAME_NOREPLACE,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise AssetAlreadyExistsError(destination.name)
            raise OSError(error_number, os.strerror(error_number), destination)
        return

    # macOS is used only for local unit tests. The media root is process-private
    # there; production refuses to run without the atomic Linux primitive.
    if destination.exists() or destination.is_symlink():
        raise AssetAlreadyExistsError(destination.name)
    source.rename(destination)
