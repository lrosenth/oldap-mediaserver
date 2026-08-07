"""Filesystem primitives shared by media uploads and future ZIP ingest.

This module owns path validation, exclusive asset-directory reservation,
per-operation workspaces, and bit-identical original storage with SHA-256
calculation. It deliberately has no Flask or OLDAP dependencies, so batch
workers can reuse the same invariants without invoking an HTTP handler.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


ASSET_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
COPY_CHUNK_BYTES = 1024 * 1024


class AssetAlreadyExistsError(FileExistsError):
    """Raised when an asset identifier has already been reserved."""


class StoragePathEscapeError(ValueError):
    """Raised when a resolved storage path leaves the configured media root."""


@dataclass(frozen=True, slots=True)
class AssetLayout:
    """Exclusively reserved directories for one media asset.

    Attributes:
        base_relative: Logical project/media/subpath stored on the MediaObject.
        root: Asset-specific directory identified by the technical asset ID.
        original: Directory containing the unchanged uploaded original.
        derived: Directory containing delivery derivatives and thumbnails.
    """

    base_relative: Path
    root: Path
    original: Path
    derived: Path


@dataclass(frozen=True, slots=True)
class StoredOriginal:
    """Integrity metadata produced while storing an original file.

    Attributes:
        path: Destination path of the stored bitstream.
        size_bytes: Number of bytes copied.
        sha256: Lower-case hexadecimal SHA-256 digest of those exact bytes.
    """

    path: Path
    size_bytes: int
    sha256: str


def safe_subpath(raw: str | None) -> Path:
    """Return a safe relative path for client- or metadata-provided subpaths.

    Args:
        raw: Relative POSIX/native path text, or ``None`` for no subpath.

    Returns:
        A relative :class:`Path` without traversal segments.

    Raises:
        ValueError: If the path is absolute or contains an empty/parent segment.
    """

    if not raw:
        return Path()
    path = Path(raw)
    if path.is_absolute():
        raise ValueError("path must be a relative path")
    if any(part in ("..", "") for part in path.parts):
        raise ValueError("path contains invalid segments")
    return path


def validate_asset_path_segment(raw: str) -> str:
    """Validate an existing asset identifier as one safe path segment.

    Legacy identifiers may contain characters that are not accepted for new
    public identifiers, but may never contain traversal syntax or NUL bytes.
    """

    value = str(raw)
    if (
        not value
        or value in (".", "..")
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("asset identifier must be a single non-empty path segment")
    return value


def validate_asset_identifier(raw: str) -> str:
    """Validate a new bounded, URL-safe technical asset identifier."""

    value = validate_asset_path_segment(raw)
    if ASSET_IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(
            "identifier must contain 1-128 URL-safe characters "
            "(letters, digits, '.', '_', '~', or '-')"
        )
    return value


def reserve_asset_layout(
    media_root: Path,
    project_short_name: str,
    media_type: str,
    subpath: str | None,
    identifier: str,
) -> AssetLayout:
    """Resolve and exclusively reserve the storage layout for one new asset.

    The asset directory is created without ``exist_ok`` and therefore acts as
    the filesystem-level ownership claim. If initialization fails after the
    claim, the incomplete asset directory is removed.

    Args:
        media_root: Configured root shared with the delivery services.
        project_short_name: Project folder component obtained from OLDAP.
        media_type: Logical media-family folder name.
        subpath: Optional relative grouping path.
        identifier: New technical asset identifier.

    Returns:
        The fully initialized and exclusively owned asset layout.

    Raises:
        AssetAlreadyExistsError: If the asset directory already exists.
        StoragePathEscapeError: If symlinks or input resolve outside the root.
        OSError: If the directory hierarchy cannot be created.
    """

    root_resolved = media_root.resolve()
    base_relative = Path(project_short_name) / media_type / safe_subpath(subpath)
    base_directory = (media_root / base_relative).resolve()
    try:
        base_directory.relative_to(root_resolved)
    except ValueError as exc:
        raise StoragePathEscapeError("Asset path escapes media root") from exc

    base_directory.mkdir(parents=True, exist_ok=True)
    asset_root = base_directory / validate_asset_identifier(identifier)
    try:
        asset_root.mkdir()
    except FileExistsError as exc:
        raise AssetAlreadyExistsError(identifier) from exc

    original = asset_root / "original"
    derived = asset_root / "derived"
    try:
        original.mkdir()
        derived.mkdir()
    except OSError:
        shutil.rmtree(asset_root, ignore_errors=True)
        raise

    return AssetLayout(
        base_relative=base_relative,
        root=asset_root,
        original=original,
        derived=derived,
    )


@contextmanager
def operation_workspace(work_root: Path, operation_id: str) -> Iterator[Path]:
    """Create and reliably remove an isolated directory for one operation.

    Args:
        work_root: Parent reserved for temporary media processing.
        operation_id: Safe identifier used only as a recognizable prefix.

    Yields:
        A new unpredictable directory owned by this operation.

    Side Effects:
        Creates ``work_root`` if needed and removes the yielded directory on
        every normal, error, and early-return path.
    """

    work_root.mkdir(parents=True, exist_ok=True)
    safe_prefix = validate_asset_identifier(operation_id)
    workspace = Path(tempfile.mkdtemp(prefix=f"{safe_prefix}-", dir=work_root))
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def store_original_with_sha256(
    source: Path,
    destination: Path,
    *,
    chunk_bytes: int = COPY_CHUNK_BYTES,
) -> StoredOriginal:
    """Copy an original bit-identically while calculating its SHA-256 digest.

    The destination is opened exclusively so this primitive can never replace
    an existing original. A partial destination is removed if reading or
    writing fails.

    Args:
        source: Existing source bitstream in an operation workspace.
        destination: New original-file path inside a reserved asset layout.
        chunk_bytes: Positive streaming buffer size.

    Returns:
        Destination path, byte count, and lower-case SHA-256 digest.

    Raises:
        ValueError: If ``chunk_bytes`` is not positive.
        OSError: If the source cannot be read or destination cannot be stored.
    """

    if chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be positive")

    digest = hashlib.sha256()
    size_bytes = 0
    destination_created = False
    try:
        with source.open("rb") as source_handle:
            with destination.open("xb") as destination_handle:
                destination_created = True
                while chunk := source_handle.read(chunk_bytes):
                    destination_handle.write(chunk)
                    digest.update(chunk)
                    size_bytes += len(chunk)
    except Exception:
        if destination_created:
            destination.unlink(missing_ok=True)
        raise

    return StoredOriginal(
        path=destination,
        size_bytes=size_bytes,
        sha256=digest.hexdigest(),
    )
