"""Private, atomic ZIP artifact storage and capability authorization."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable
from uuid import UUID

import jwt
import rfc8785

from export_sources import (
    ExportSourceConflictError,
    ExportSourceNotFoundError,
    open_export_source,
)
from storage_capacity import StorageCapacityGuard

MAX_ARCHIVE_BYTES = 50_000_000_000
MAX_ENTRIES = 1_000_000
MAX_PATH_LENGTH = 4_096
COPY_CHUNK_BYTES = 1024 * 1024
METADATA_HEADROOM_BYTES = 16 * 1024 * 1024
DOWNLOAD_TOKEN_TYPE = "export-download"
DOWNLOAD_TOKEN_AUDIENCE = "oldap-media-export-download"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESERVED_ROOT_NAMES = {
    "readme.txt",
    "export.csv",
    "metadata.csv",
    "archive-units.csv",
}
COMMON_METADATA_COLUMNS = (
    "relative_path",
    "included",
    "exclusion_reason",
    "media_iri",
    "asset_id",
    "original_filename",
    "original_mime_type",
    "size_bytes",
    "sha256",
    "recorded_checksum",
    "container_iri",
    "container_path",
    "source_modified_at",
)


class ExportArtifactError(RuntimeError):
    """Base class for safe export artifact failures."""


class ExportManifestRejected(ExportArtifactError):
    """Raised when a canonical API manifest violates worker invariants."""


class ExportSourceChanged(ExportArtifactError):
    """Raised when an original differs from the frozen manifest."""


class ExportArchiveTooLarge(ExportArtifactError):
    """Raised when actual produced ZIP bytes exceed the v1 ceiling."""


class ExportDownloadAuthorizationError(PermissionError):
    """Raised when a download capability is absent, invalid, or mismatched."""


class ExportDownloadAuthenticationUnavailable(RuntimeError):
    """Raised when the download verification key is unsafe."""


@dataclass(frozen=True, slots=True)
class ExportBuildEvidence:
    """Durable evidence for one atomically finalized export archive."""

    export_id: str
    manifest_sha256: str
    archive_size_bytes: int
    archive_sha256: str
    completed_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Return the closed local evidence record."""

        return {
            "documentType": "oldap.zip-export.artifact",
            "schemaVersion": "1.0.0",
            "exportId": self.export_id,
            "manifestSha256": self.manifest_sha256,
            "archiveSizeBytes": self.archive_size_bytes,
            "archiveSha256": self.archive_sha256,
            "completedAt": self.completed_at.astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ExportBuildEvidence":
        """Parse a closed finalized-artifact evidence record."""

        required = {
            "documentType",
            "schemaVersion",
            "exportId",
            "manifestSha256",
            "archiveSizeBytes",
            "archiveSha256",
            "completedAt",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value["documentType"] != "oldap.zip-export.artifact"
            or value["schemaVersion"] != "1.0.0"
        ):
            raise ExportArtifactError("Export artifact evidence is invalid.")
        export_id = _canonical_uuid(value["exportId"])
        manifest_sha = _sha256(value["manifestSha256"])
        archive_sha = _sha256(value["archiveSha256"])
        size = value["archiveSizeBytes"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= MAX_ARCHIVE_BYTES
        ):
            raise ExportArtifactError("Export artifact size evidence is invalid.")
        try:
            completed = datetime.fromisoformat(
                str(value["completedAt"]).replace("Z", "+00:00")
            )
        except ValueError as error:
            raise ExportArtifactError("Export completion time is invalid.") from error
        if completed.tzinfo is None:
            raise ExportArtifactError("Export completion time has no timezone.")
        return cls(
            export_id,
            manifest_sha,
            size,
            archive_sha,
            completed.astimezone(UTC),
        )


@dataclass(frozen=True, slots=True)
class FinalizedExportArtifact:
    """Resolved immutable archive path and its trusted evidence."""

    archive_path: Path
    evidence: ExportBuildEvidence


class ExportArtifactStore:
    """Build, resolve, and remove private export-ID-scoped artifacts."""

    def __init__(
        self,
        export_root: Path,
        media_root: Path,
        *,
        capacity_guard: StorageCapacityGuard | None = None,
    ) -> None:
        self.export_root = export_root
        self.media_root = media_root
        self.capacity_guard = capacity_guard or StorageCapacityGuard()

    def build(
        self,
        manifest: dict[str, Any],
        manifest_sha256: str,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        checkpoint: Callable[[], None] | None = None,
    ) -> ExportBuildEvidence:
        """Stream and finalize a ZIP while honoring lease/cancellation checks."""

        export_id = _validate_manifest(manifest, manifest_sha256)
        max_archive_bytes = manifest["limits"]["maxArchiveBytes"]
        existing = self._existing(export_id, expected_manifest=manifest_sha256)
        if existing is not None:
            self._cleanup_partials(export_id)
            return existing.evidence

        media = manifest["media"]
        expected_bytes = sum(
            item["binarySource"]["expectedSizeBytes"]
            for item in media
            if item["included"]
        )
        self.export_root.mkdir(parents=True, exist_ok=True)
        self.capacity_guard.require(
            self.export_root,
            additional_bytes=min(
                max_archive_bytes, expected_bytes + METADATA_HEADROOM_BYTES
            ),
        )
        workspace = Path(
            tempfile.mkdtemp(prefix=f".part-{export_id}-", dir=self.export_root)
        )
        archive_path = workspace / "archive.zip"
        build_started = started_at or datetime.now(UTC)
        try:
            if checkpoint is not None:
                checkpoint()
            rows: list[dict[str, Any]] = []
            with zipfile.ZipFile(
                archive_path,
                "x",
                allowZip64=True,
                compression=zipfile.ZIP_STORED,
            ) as archive:
                for directory in manifest["directories"]:
                    _write_directory(archive, directory["relativePath"], build_started)
                for item in media:
                    rows.append(
                        self._write_media(
                            archive,
                            item,
                            build_started,
                            archive_path,
                            max_archive_bytes,
                            checkpoint,
                        )
                    )
                _write_support_files(
                    archive,
                    manifest,
                    rows,
                    build_started,
                    archive_path,
                    max_archive_bytes,
                )
                if checkpoint is not None:
                    checkpoint()
            archive_size, archive_sha = _hash_regular_file(archive_path)
            if archive_size > max_archive_bytes:
                raise ExportArchiveTooLarge(
                    "Produced archive exceeds the configured export limit."
                )
            finished = completed_at or datetime.now(UTC)
            evidence = ExportBuildEvidence(
                export_id,
                manifest_sha256,
                archive_size,
                archive_sha,
                finished,
            )
            _write_json_exclusive(workspace / "result.json", evidence.to_dict())
            _fsync_file(archive_path)
            _fsync_directory(workspace)
            final = self.export_root / export_id
            try:
                workspace.rename(final)
            except FileExistsError:
                existing = self._existing(export_id, expected_manifest=manifest_sha256)
                if existing is None:
                    raise ExportArtifactError(
                        "Existing export artifact is inconsistent."
                    )
                shutil.rmtree(workspace, ignore_errors=True)
                self._cleanup_partials(export_id)
                return existing.evidence
            _fsync_directory(self.export_root)
            self._cleanup_partials(export_id)
            return evidence
        except Exception:
            shutil.rmtree(workspace, ignore_errors=True)
            raise

    def resolve(self, export_id: str) -> FinalizedExportArtifact:
        """Return one exact finalized archive without accepting arbitrary paths."""

        identifier = _canonical_uuid(export_id)
        artifact = self._existing(identifier)
        if artifact is None:
            raise FileNotFoundError("Export artifact not found.")
        return artifact

    def cleanup(self, export_id: str) -> None:
        """Idempotently remove only one final directory and its partials."""

        identifier = _canonical_uuid(export_id)
        self.export_root.mkdir(parents=True, exist_ok=True)
        targets = [self.export_root / identifier]
        targets.extend(self._partial_paths(identifier))
        for target in targets:
            try:
                target.relative_to(self.export_root)
            except ValueError as error:
                raise ExportArtifactError(
                    "Export cleanup path escaped its root."
                ) from error
            if target.is_symlink():
                target.unlink(missing_ok=True)
            elif target.exists():
                shutil.rmtree(target)
        _fsync_directory(self.export_root)

    def _partial_paths(self, export_id: str) -> list[Path]:
        """Resolve a bounded list of UUID-scoped partial workspaces."""

        partials = list(self.export_root.glob(f".part-{export_id}-*"))
        if len(partials) > 1_000:
            raise ExportArtifactError("Too many partial export artifacts.")
        return partials

    def _cleanup_partials(self, export_id: str) -> None:
        """Remove retry leftovers without touching the finalized artifact."""

        for partial in self._partial_paths(export_id):
            if partial.is_symlink():
                partial.unlink(missing_ok=True)
            elif partial.exists():
                shutil.rmtree(partial)
        _fsync_directory(self.export_root)

    def _write_media(
        self,
        archive: zipfile.ZipFile,
        item: dict[str, Any],
        timestamp: datetime,
        archive_path: Path,
        max_archive_bytes: int,
        checkpoint: Callable[[], None] | None,
    ) -> dict[str, Any]:
        binary = item.get("binarySource")
        row = _metadata_row(item)
        if not item["included"]:
            return row
        if not isinstance(binary, dict):
            raise ExportManifestRejected("Included media has no binary source.")
        expected_size = binary["expectedSizeBytes"]
        expected_sha = binary.get("recordedChecksum")
        relative_path = item["relativePath"]
        info = _zip_info(relative_path, timestamp)
        info.compress_type = _compression_for(binary["originalMimeType"])
        digest = hashlib.sha256()
        copied = 0
        try:
            with open_export_source(self.media_root, binary["storagePath"]) as source:
                before = os.fstat(source.fileno())
                with archive.open(info, "w", force_zip64=True) as destination:
                    while chunk := source.read(COPY_CHUNK_BYTES):
                        if checkpoint is not None:
                            checkpoint()
                        destination.write(chunk)
                        digest.update(chunk)
                        copied += len(chunk)
                after = os.fstat(source.fileno())
        except (ExportSourceConflictError, ExportSourceNotFoundError) as error:
            raise ExportSourceChanged(
                "Export source is unavailable or unsafe."
            ) from error
        if (
            not stat.S_ISREG(after.st_mode)
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or copied != expected_size
            or (expected_sha is not None and digest.hexdigest() != expected_sha)
        ):
            raise ExportSourceChanged("Export source differs from its snapshot.")
        row["sha256"] = digest.hexdigest()
        row["size_bytes"] = copied
        if archive_path.stat().st_size > max_archive_bytes:
            raise ExportArchiveTooLarge(
                "Produced archive exceeds the configured export limit."
            )
        return row

    def _existing(
        self, export_id: str, *, expected_manifest: str | None = None
    ) -> FinalizedExportArtifact | None:
        directory = self.export_root / export_id
        archive = directory / "archive.zip"
        result = directory / "result.json"
        if not directory.exists():
            return None
        if directory.is_symlink() or archive.is_symlink() or result.is_symlink():
            raise ExportArtifactError("Export artifact contains a symbolic link.")
        try:
            archive_status = archive.stat()
            result_status = result.stat()
        except OSError as error:
            raise ExportArtifactError("Export artifact is incomplete.") from error
        if not stat.S_ISREG(archive_status.st_mode) or not stat.S_ISREG(
            result_status.st_mode
        ):
            raise ExportArtifactError("Export artifact layout is invalid.")
        try:
            evidence = ExportBuildEvidence.from_dict(
                json.loads(result.read_text(encoding="utf-8"))
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExportArtifactError(
                "Export artifact evidence is unreadable."
            ) from error
        if (
            evidence.export_id != export_id
            or archive_status.st_size != evidence.archive_size_bytes
            or (
                expected_manifest is not None
                and evidence.manifest_sha256 != expected_manifest
            )
        ):
            raise ExportArtifactError("Export artifact evidence is inconsistent.")
        return FinalizedExportArtifact(archive, evidence)


def authorize_export_download(
    token: str | None,
    export_id: str,
    *,
    secret: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Validate one exact, short-lived export-download capability."""

    identifier = _canonical_uuid(export_id)
    if not token:
        raise ExportDownloadAuthorizationError("Export capability required.")
    signing_secret = (
        secret
        if secret is not None
        else os.getenv("OLDAP_EXPORT_DOWNLOAD_JWT_SECRET", "")
    )
    if len(signing_secret.encode("utf-8")) < 32:
        raise ExportDownloadAuthenticationUnavailable(
            "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET must contain at least 32 bytes."
        )
    other_names = (
        "OLDAP_ACCESS_JWT_SECRET",
        "OLDAP_REFRESH_JWT_SECRET",
        "OLDAP_MEDIA_JWT_SECRET",
        "OLDAP_IMPORT_UPLOAD_JWT_SECRET",
        "OLDAP_IMPORT_SERVICE_JWT_SECRET",
        "OLDAP_IMPORT_RECORDS_JWT_SECRET",
        "OLDAP_EXPORT_SERVICE_JWT_SECRET",
    )
    if signing_secret in {
        value for name in other_names if (value := os.getenv(name, ""))
    }:
        raise ExportDownloadAuthenticationUnavailable(
            "Export download key is not purpose-specific."
        )
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_secret,
            algorithms=["HS256"],
            audience=DOWNLOAD_TOKEN_AUDIENCE,
            issuer=issuer or os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            options={
                "require": ["typ", "sub", "exportId", "jti", "iat", "exp", "iss", "aud"]
            },
        )
    except jwt.PyJWTError as error:
        raise ExportDownloadAuthorizationError(
            "Invalid or expired export capability."
        ) from error
    if (
        claims.get("typ") != DOWNLOAD_TOKEN_TYPE
        or claims.get("exportId") != identifier
        or not claims.get("sub")
        or not claims.get("jti")
    ):
        raise ExportDownloadAuthorizationError("Export capability scope mismatch.")
    return claims


def digest_header(sha256: str) -> str:
    """Return an RFC-style Digest header for one hexadecimal SHA-256."""

    import base64

    return "sha-256=" + base64.b64encode(bytes.fromhex(_sha256(sha256))).decode("ascii")


def _valid_manifest_limit(value: Any) -> bool:
    """Accept one deployment limit within the immutable v1 safety ceiling."""

    return (
        isinstance(value, dict)
        and set(value) == {"maxArchiveBytes"}
        and not isinstance(value["maxArchiveBytes"], bool)
        and isinstance(value["maxArchiveBytes"], int)
        and 1 <= value["maxArchiveBytes"] <= MAX_ARCHIVE_BYTES
    )


def _validate_manifest(manifest: Any, manifest_sha256: str) -> str:
    required = {
        "documentType",
        "schemaVersion",
        "exportId",
        "generatedAt",
        "kind",
        "projectShortName",
        "requestedByIri",
        "profile",
        "selection",
        "limits",
        "directories",
        "media",
    }
    allowed = required | {"archiveUnits"}
    if (
        not isinstance(manifest, dict)
        or not required <= set(manifest) <= allowed
        or manifest["documentType"] != "oldap.zip-export.manifest"
        or manifest["schemaVersion"] != "1.0.0"
        or not _valid_manifest_limit(manifest.get("limits"))
        or not isinstance(manifest["requestedByIri"], str)
        or not manifest["requestedByIri"]
        or not isinstance(manifest["directories"], list)
        or not isinstance(manifest["media"], list)
        or len(manifest["directories"]) > MAX_ENTRIES
        or len(manifest["media"]) > MAX_ENTRIES
    ):
        raise ExportManifestRejected("Export manifest envelope is invalid.")
    archive_units = manifest.get("archiveUnits", [])
    archive_kind = manifest.get("kind") in {"ARCHIVE_UNIT", "ARCHIVE_ALL"}
    if (
        not isinstance(archive_units, list)
        or len(archive_units) > MAX_ENTRIES
        or archive_kind != ("archiveUnits" in manifest)
    ):
        raise ExportManifestRejected("Export archive-unit envelope is invalid.")
    _sha256(manifest_sha256)
    try:
        canonical = rfc8785.dumps(manifest)
    except (TypeError, rfc8785.CanonicalizationError) as error:
        raise ExportManifestRejected(
            "Export manifest is not canonicalizable."
        ) from error
    if hashlib.sha256(canonical).hexdigest() != manifest_sha256:
        raise ExportManifestRejected("Export manifest digest is inconsistent.")
    export_id = _canonical_uuid(manifest["exportId"])
    paths: set[str] = set()
    portable: set[str] = set()
    directory_iris: set[str] = set()
    directory_paths: set[str] = set()
    for directory in manifest["directories"]:
        if not isinstance(directory, dict) or set(directory) != {
            "relativePath",
            "containerIri",
        }:
            raise ExportManifestRejected("Export directory entry is invalid.")
        _reserve_path(directory["relativePath"], paths, portable, directory=True)
        if directory["containerIri"] in directory_iris:
            raise ExportManifestRejected("Export directory containers are not unique.")
        directory_iris.add(directory["containerIri"])
        directory_paths.add(directory["relativePath"])
    indexes: set[int] = set()
    for item in manifest["media"]:
        _validate_media_item(item)
        index = item["entryIndex"]
        if index in indexes:
            raise ExportManifestRejected("Export entry indexes are not unique.")
        indexes.add(index)
        _reserve_path(item["relativePath"], paths, portable, directory=False)
    unit_iris: set[str] = set()
    unit_paths: set[str] = set()
    for unit in archive_units:
        _validate_archive_unit(unit)
        if unit["unitIri"] in unit_iris or unit["relativePath"] in unit_paths:
            raise ExportManifestRejected("Export archive units are not unique.")
        unit_iris.add(unit["unitIri"])
        unit_paths.add(unit["relativePath"])
    if archive_kind:
        if unit_iris != directory_iris or unit_paths != directory_paths:
            raise ExportManifestRejected(
                "Export archive units differ from directory inventory."
            )
        if any(
            unit.get("parentUnitIri") not in unit_iris
            for unit in archive_units
            if unit.get("parentUnitIri")
        ):
            raise ExportManifestRejected("Export archive-unit parent is unavailable.")
        if any(item["containerIri"] not in unit_iris for item in manifest["media"]):
            raise ExportManifestRejected("Export media container is unavailable.")
    return export_id


def _validate_archive_unit(unit: Any) -> None:
    """Validate one closed archive-unit metadata record for CSV projection."""

    required = {
        "relativePath",
        "unitIri",
        "archiveLevelIri",
        "title",
        "identifier",
        "description",
        "temporal",
        "materialExtent",
        "creatorIris",
        "provenance",
        "conditionsOfAccess",
        "metadata",
    }
    if (
        not isinstance(unit, dict)
        or not required <= set(unit) <= required | {"parentUnitIri"}
        or not isinstance(unit["unitIri"], str)
        or not unit["unitIri"]
        or not isinstance(unit["archiveLevelIri"], str)
        or not unit["archiveLevelIri"]
        or not isinstance(unit["identifier"], str)
        or not isinstance(unit["temporal"], str)
        or not isinstance(unit["creatorIris"], list)
        or len(unit["creatorIris"]) > 10_000
        or not all(isinstance(item, str) for item in unit["creatorIris"])
        or not isinstance(unit["metadata"], dict)
        or len(unit["metadata"]) > 256
    ):
        raise ExportManifestRejected("Export archive unit is invalid.")
    _safe_path(unit["relativePath"])
    for value in (
        unit["title"],
        unit["description"],
        unit["materialExtent"],
        unit["provenance"],
        unit["conditionsOfAccess"],
    ):
        if not _valid_metadata_value(value):
            raise ExportManifestRejected("Export archive-unit metadata is invalid.")
    for key, value in unit["metadata"].items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) is None
            or not _valid_metadata_value(value)
        ):
            raise ExportManifestRejected("Export archive-unit metadata is invalid.")


def _validate_media_item(item: Any) -> None:
    required = {
        "entryIndex",
        "relativePath",
        "mediaIri",
        "containerIri",
        "included",
        "metadata",
    }
    optional = {"exclusionReason", "externalSourceUrl", "binarySource"}
    if not isinstance(item, dict) or not required <= set(item) <= required | optional:
        raise ExportManifestRejected("Export media entry is invalid.")
    index = item["entryIndex"]
    metadata = item["metadata"]
    if (
        isinstance(index, bool)
        or not isinstance(index, int)
        or not 0 <= index < MAX_ENTRIES
        or not isinstance(item["included"], bool)
        or not isinstance(metadata, dict)
        or len(metadata) > 256
    ):
        raise ExportManifestRejected("Export media facts are invalid.")
    for key, value in metadata.items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) is None
            or key in COMMON_METADATA_COLUMNS
            or not _valid_metadata_value(value)
        ):
            raise ExportManifestRejected("Export metadata is invalid.")
    binary = item.get("binarySource")
    if item["included"]:
        required_binary = {
            "assetId",
            "storagePath",
            "originalName",
            "originalMimeType",
            "expectedSizeBytes",
        }
        if (
            not isinstance(binary, dict)
            or not required_binary
            <= set(binary)
            <= required_binary | {"recordedChecksum"}
            or item.get("exclusionReason") is not None
        ):
            raise ExportManifestRejected("Included export media is invalid.")
        _safe_path(binary["storagePath"])
        size = binary["expectedSizeBytes"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_ARCHIVE_BYTES
        ):
            raise ExportManifestRejected("Export source size is invalid.")
        if binary.get("recordedChecksum") is not None:
            _sha256(binary["recordedChecksum"])
    elif binary is not None or item.get("exclusionReason") not in {
        "EXTERNAL_ORIGINAL_UNAVAILABLE",
        "ORIGINAL_NOT_EXPORTABLE",
    }:
        raise ExportManifestRejected("Excluded export media is invalid.")


def _reserve_path(
    value: Any,
    paths: set[str],
    portable: set[str],
    *,
    directory: bool,
) -> None:
    path = _safe_path(value)
    key = "/".join(part.casefold().rstrip(" .") for part in path.parts)
    if path.as_posix() in paths or key in portable:
        raise ExportManifestRejected("Export paths collide.")
    if path.parts[0].casefold() in RESERVED_ROOT_NAMES:
        raise ExportManifestRejected("Export path collides with support files.")
    paths.add(path.as_posix())
    portable.add(key)
    if directory:
        return


def _safe_path(value: Any) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_PATH_LENGTH
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ExportManifestRejected("Export path is unsafe.")
    path = PurePosixPath(value)
    if any(
        part in {"", ".", ".."} or any(ord(character) < 32 for character in part)
        for part in path.parts
    ):
        raise ExportManifestRejected("Export path is unsafe.")
    return path


def _metadata_row(item: dict[str, Any]) -> dict[str, Any]:
    binary = item.get("binarySource") or {}
    path = PurePosixPath(item["relativePath"])
    row = {
        "relative_path": item["relativePath"],
        "included": item["included"],
        "exclusion_reason": item.get("exclusionReason", ""),
        "media_iri": item["mediaIri"],
        "asset_id": binary.get("assetId", ""),
        "original_filename": binary.get("originalName", ""),
        "original_mime_type": binary.get("originalMimeType", ""),
        "size_bytes": binary.get("expectedSizeBytes", ""),
        "sha256": "",
        "recorded_checksum": binary.get("recordedChecksum", ""),
        "container_iri": item["containerIri"],
        "container_path": (
            path.parent.as_posix() if path.parent != PurePosixPath(".") else ""
        ),
        "source_modified_at": "",
    }
    row.update(item["metadata"])
    return row


def _write_support_files(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    started_at: datetime,
    archive_path: Path,
    max_archive_bytes: int,
) -> None:
    extra_columns = sorted(
        {key for row in rows for key in row if key not in COMMON_METADATA_COLUMNS}
    )
    included = [row for row in rows if row["included"]]
    export_row = {
        "export_id": manifest["exportId"],
        "kind": manifest["kind"],
        "project_short_name": manifest["projectShortName"],
        "selection_iri": manifest["selection"].get("iri", ""),
        "selection_path": manifest["selection"]["displayPath"],
        "requested_by_iri": manifest["requestedByIri"],
        "snapshot_at": manifest["generatedAt"],
        "created_at": started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "files_total": len(included),
        "source_bytes": sum(int(row["size_bytes"]) for row in included),
        "warning_count": len(rows) - len(included),
        "schema_version": manifest["schemaVersion"],
        "profile_id": manifest["profile"]["profileId"],
        "profile_version": manifest["profile"]["profileVersion"],
        "metadata_schema_version": manifest["profile"]["metadataSchemaVersion"],
    }
    export_columns = tuple(export_row)
    readme = (
        "OLDAP project-neutral ZIP export\r\n"
        f"Export type: {manifest['kind']}\r\n"
        f"Snapshot: {manifest['generatedAt']}\r\n"
        "CSV encoding: UTF-8 with BOM; RFC 4180 quoting.\r\n"
        "Checksums: SHA-256 over the exact exported original bytes.\r\n"
        "metadata.csv contains one row per manifest media record; rows with "
        "included=false describe exclusions and have no ZIP bitstream.\r\n"
    ).encode("utf-8")
    _write_bytes_entry(archive, "README.txt", readme, started_at, compress=True)
    _write_csv_entry(
        archive,
        "export.csv",
        [export_row],
        export_columns,
        started_at,
    )
    archive_units = manifest.get("archiveUnits")
    if archive_units is not None:
        unit_rows = [_archive_unit_row(unit) for unit in archive_units]
        unit_columns = (
            "relative_path",
            "unit_iri",
            "parent_unit_iri",
            "archive_level_iri",
            "identifier",
            "title",
            "description",
            "temporal",
            "material_extent",
            "creator_iris",
            "provenance",
            "conditions_of_access",
        ) + tuple(
            sorted(
                {
                    key
                    for row in unit_rows
                    for key in row
                    if key
                    not in {
                        "relative_path",
                        "unit_iri",
                        "parent_unit_iri",
                        "archive_level_iri",
                        "identifier",
                        "title",
                        "description",
                        "temporal",
                        "material_extent",
                        "creator_iris",
                        "provenance",
                        "conditions_of_access",
                    }
                }
            )
        )
        _write_csv_entry(
            archive,
            "archive-units.csv",
            unit_rows,
            unit_columns,
            started_at,
        )
    _write_csv_entry(
        archive,
        "metadata.csv",
        rows,
        COMMON_METADATA_COLUMNS + tuple(extra_columns),
        started_at,
    )
    if archive_path.stat().st_size > max_archive_bytes:
        raise ExportArchiveTooLarge(
            "Produced archive exceeds the configured export limit."
        )


def _archive_unit_row(unit: dict[str, Any]) -> dict[str, Any]:
    """Flatten one manifest archive unit without interpreting profile metadata."""

    return {
        "relative_path": unit["relativePath"],
        "unit_iri": unit["unitIri"],
        "parent_unit_iri": unit.get("parentUnitIri", ""),
        "archive_level_iri": unit["archiveLevelIri"],
        "identifier": unit["identifier"],
        "title": unit["title"],
        "description": unit["description"],
        "temporal": unit["temporal"],
        "material_extent": unit["materialExtent"],
        "creator_iris": unit["creatorIris"],
        "provenance": unit["provenance"],
        "conditions_of_access": unit["conditionsOfAccess"],
        **unit["metadata"],
    }


def _write_csv_entry(
    archive: zipfile.ZipFile,
    name: str,
    rows: list[dict[str, Any]],
    columns: tuple[str, ...],
    timestamp: datetime,
) -> None:
    """Stream one UTF-8-BOM RFC-4180 CSV directly into the archive."""

    info = _zip_info(name, timestamp)
    info.compress_type = zipfile.ZIP_DEFLATED
    with archive.open(info, "w", force_zip64=True) as binary:
        binary.write(b"\xef\xbb\xbf")
        text = io.TextIOWrapper(
            binary, encoding="utf-8", newline="", write_through=True
        )
        try:
            writer = csv.DictWriter(
                text, fieldnames=columns, extrasaction="ignore", lineterminator="\r\n"
            )
            writer.writeheader()
            for row in rows:
                writer.writerow({key: _csv_value(row.get(key, "")) for key in columns})
            text.flush()
        finally:
            text.detach()


def _csv_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    if isinstance(value, (str, int, float)):
        return value
    raise ExportManifestRejected("Metadata value cannot be represented in CSV.")


def _valid_metadata_value(value: Any) -> bool:
    if isinstance(value, (str, bool, int, float)):
        return not isinstance(value, str) or len(value) <= 1_000_000
    if isinstance(value, list):
        return len(value) <= 10_000 and all(
            isinstance(item, str) and len(item) <= 10_000 for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 256 and all(
            isinstance(key, str) and isinstance(item, str) and len(item) <= 100_000
            for key, item in value.items()
        )
    return False


def _write_directory(
    archive: zipfile.ZipFile, relative_path: str, timestamp: datetime
) -> None:
    info = _zip_info(f"{relative_path.rstrip('/')}/", timestamp)
    info.external_attr = (0o40750 << 16) | 0x10
    archive.writestr(info, b"")


def _write_bytes_entry(
    archive: zipfile.ZipFile,
    name: str,
    content: bytes,
    timestamp: datetime,
    *,
    compress: bool,
) -> None:
    info = _zip_info(name, timestamp)
    info.compress_type = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    archive.writestr(info, content, compresslevel=6 if compress else None)


def _zip_info(name: str, timestamp: datetime) -> zipfile.ZipInfo:
    current = timestamp.astimezone(UTC)
    year = min(max(current.year, 1980), 2107)
    info = zipfile.ZipInfo(
        name,
        (
            year,
            current.month,
            current.day,
            current.hour,
            current.minute,
            current.second,
        ),
    )
    info.create_system = 3
    info.external_attr = 0o100440 << 16
    info.flag_bits |= 0x800
    return info


def _compression_for(mime_type: str) -> int:
    if mime_type in {
        "image/jpeg",
        "image/png",
        "image/heic",
        "image/heif",
        "audio/mpeg",
        "audio/flac",
        "video/mp4",
        "application/zip",
    }:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def _hash_regular_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(COPY_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    content = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_uuid(value: Any) -> str:
    try:
        canonical = str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("exportId must be a canonical UUID.") from error
    if value != canonical:
        raise ValueError("exportId must be a canonical UUID.")
    return canonical


def _sha256(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError("SHA-256 must be lower-case hexadecimal.")
    return value
