"""Authenticated, filesystem-authoritative source resolution for ZIP exports.

The public OLDAP API owns export authorization and supplies RDF-derived path
hints.  This module treats those hints as untrusted and resolves only immutable
original files below the configured media root.  It has no Flask dependency so
the authentication and filesystem boundary can be tested independently.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator
from urllib.parse import urlsplit

import jwt

from storage import validate_asset_identifier


EXPORT_SOURCE_TOKEN_TYPE = "export-source-resolver"
EXPORT_SOURCE_TOKEN_AUDIENCE = "oldap-media-export-service"
MAX_RESOLVE_BATCH = 1_000
MAX_MEDIA_IRI_LENGTH = 2_048
MAX_STORAGE_PATH_LENGTH = 4_096
MAX_ORIGINAL_NAME_LENGTH = 255
MAX_SOURCE_BYTES = 50_000_000_000
HASH_CHUNK_BYTES = 1024 * 1024


class ExportSourceAuthorizationError(PermissionError):
    """Raised when the API-to-media resolver credential is not acceptable."""


class ExportSourceAuthenticationUnavailable(RuntimeError):
    """Raised when the resolver key is missing or not purpose-specific."""


class ExportSourceRequestError(ValueError):
    """Raised when a resolver request does not match the closed contract."""


class ExportSourceNotFoundError(FileNotFoundError):
    """Raised when an expected original file is no longer available."""


class ExportSourceConflictError(RuntimeError):
    """Raised when supplied identity facts conflict with stored layout."""


@dataclass(frozen=True, slots=True)
class ExportSourceReference:
    """Validated RDF-derived hints for one local media original."""

    media_iri: str
    asset_id: str
    storage_path_candidate: str
    original_name: str


@dataclass(frozen=True, slots=True)
class ResolvedExportSource:
    """Filesystem-confirmed facts for one immutable original bitstream."""

    media_iri: str
    asset_id: str
    storage_path: str
    original_name: str
    original_mime_type: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, str | int]:
        """Return the closed JSON representation used by the v1 contract."""

        return {
            "mediaIri": self.media_iri,
            "assetId": self.asset_id,
            "storagePath": self.storage_path,
            "originalName": self.original_name,
            "originalMimeType": self.original_mime_type,
            "sizeBytes": self.size_bytes,
            "sha256": self.sha256,
        }


@contextmanager
def open_export_source(media_root: Path, storage_path: str) -> Iterator[BinaryIO]:
    """Open one manifest-confirmed original without following any symlink.

    The caller must still verify the expected size and digest while consuming
    the stream. This function owns path containment and regular-file identity.
    """

    try:
        root = media_root.resolve(strict=True)
    except OSError as error:
        raise ExportSourceConflictError(
            "Configured media root is unavailable."
        ) from error
    relative = PurePosixPath(_storage_path(storage_path))
    candidate = root.joinpath(*relative.parts)
    _reject_symlink_components(root, candidate)
    descriptor = _open_below_root(root, relative)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > MAX_SOURCE_BYTES:
            raise ExportSourceConflictError(
                "Export source original is not a supported regular file."
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            yield handle
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def authorize_export_source_token(
    authorization: str | None,
    *,
    secret: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Validate a short-lived, purpose-specific oldap-api service JWT.

    Args:
        authorization: Complete HTTP Authorization header.
        secret: Optional injected signing key for tests.
        issuer: Optional expected issuer override.

    Returns:
        Verified claims from the service token.

    Raises:
        ExportSourceAuthenticationUnavailable: If key configuration is unsafe.
        ExportSourceAuthorizationError: If the header or token is invalid.
    """

    parts = authorization.split() if authorization else []
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise ExportSourceAuthorizationError("Export source authorization required.")

    signing_secret = (
        secret
        if secret is not None
        else os.getenv("OLDAP_EXPORT_SERVICE_JWT_SECRET", "")
    )
    if len(signing_secret.encode("utf-8")) < 32:
        raise ExportSourceAuthenticationUnavailable(
            "OLDAP_EXPORT_SERVICE_JWT_SECRET must contain at least 32 bytes."
        )
    _assert_purpose_specific_secret(signing_secret)
    try:
        claims: dict[str, Any] = jwt.decode(
            parts[1],
            signing_secret,
            algorithms=["HS256"],
            audience=EXPORT_SOURCE_TOKEN_AUDIENCE,
            issuer=issuer or os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            options={"require": ["typ", "sub", "iat", "exp", "iss", "aud"]},
        )
    except jwt.PyJWTError as error:
        raise ExportSourceAuthorizationError(
            "Invalid or expired export source token."
        ) from error

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        claims.get("typ") != EXPORT_SOURCE_TOKEN_TYPE
        or claims.get("sub") != "oldap-api"
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not 0 < expires_at - issued_at <= 120
    ):
        raise ExportSourceAuthorizationError("Export source token scope mismatch.")
    return claims


def parse_export_source_request(payload: Any) -> tuple[ExportSourceReference, ...]:
    """Parse and validate one closed, bounded resolver request payload."""

    if not isinstance(payload, dict) or set(payload) != {"items"}:
        raise ExportSourceRequestError("Request must contain only items.")
    items = payload["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_RESOLVE_BATCH:
        raise ExportSourceRequestError("Request must contain 1 to 1000 items.")

    result: list[ExportSourceReference] = []
    media_iris: set[str] = set()
    asset_ids: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "mediaIri",
            "assetId",
            "storagePathCandidate",
            "originalName",
        }:
            raise ExportSourceRequestError("Resolver item shape is invalid.")
        media_iri = _media_iri(item["mediaIri"])
        try:
            asset_id = validate_asset_identifier(item["assetId"])
        except (TypeError, ValueError) as error:
            raise ExportSourceRequestError("Resolver assetId is invalid.") from error
        storage_path = _storage_path(item["storagePathCandidate"])
        original_name = _original_name(item["originalName"])
        if media_iri in media_iris or asset_id in asset_ids:
            raise ExportSourceRequestError("Resolver identities must be unique.")
        media_iris.add(media_iri)
        asset_ids.add(asset_id)
        result.append(
            ExportSourceReference(
                media_iri=media_iri,
                asset_id=asset_id,
                storage_path_candidate=storage_path,
                original_name=original_name,
            )
        )
    return tuple(result)


def resolve_export_sources(
    media_root: Path,
    references: tuple[ExportSourceReference, ...],
) -> tuple[ResolvedExportSource, ...]:
    """Resolve and hash every requested original without trusting RDF paths.

    The operation is all-or-nothing: callers receive no partial inventory when
    one item is absent, unsafe, or changes while it is being read.
    """

    try:
        root = media_root.resolve(strict=True)
    except OSError as error:
        raise ExportSourceConflictError(
            "Configured media root is unavailable."
        ) from error
    if not root.is_dir():
        raise ExportSourceConflictError("Configured media root is unsafe.")

    resolved: list[ResolvedExportSource] = []
    for reference in references:
        relative = (
            PurePosixPath(reference.storage_path_candidate)
            / reference.asset_id
            / "original"
            / reference.original_name
        )
        if len(relative.as_posix()) > MAX_STORAGE_PATH_LENGTH:
            raise ExportSourceRequestError(
                "Resolved export source path exceeds the contract limit."
            )
        candidate = root.joinpath(*relative.parts)
        _reject_symlink_components(root, candidate)
        size_bytes, digest, header = _read_regular_file(root, relative)
        resolved.append(
            ResolvedExportSource(
                media_iri=reference.media_iri,
                asset_id=reference.asset_id,
                storage_path=relative.as_posix(),
                original_name=reference.original_name,
                original_mime_type=_detect_mime_type(reference.original_name, header),
                size_bytes=size_bytes,
                sha256=digest,
            )
        )
    return tuple(resolved)


def _read_regular_file(root: Path, relative: PurePosixPath) -> tuple[int, str, bytes]:
    """Open below ``root`` without following links, hash, and detect mutation."""

    descriptor = _open_below_root(root, relative)
    digest = hashlib.sha256()
    header = b""
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ExportSourceConflictError(
                "Export source original is not a regular file."
            )
        if before.st_size > MAX_SOURCE_BYTES:
            raise ExportSourceConflictError(
                "Export source original exceeds the supported size."
            )
        while chunk := os.read(descriptor, HASH_CHUNK_BYTES):
            if not header:
                header = chunk[:1024]
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise ExportSourceConflictError(
            "Export source original could not be read safely."
        ) from error
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ExportSourceConflictError(
            "Export source original changed during resolution."
        )
    return after.st_size, digest.hexdigest(), header


def _open_below_root(root: Path, relative: PurePosixPath) -> int:
    """Open one relative regular-file candidate with no-follow at every level."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor: int | None = None
    try:
        directory_descriptor = os.open(root, directory_flags)
        for component in relative.parts[:-1]:
            child = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = child
        descriptor = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError as error:
        raise ExportSourceNotFoundError(
            "Export source original was not found."
        ) from error
    except OSError as error:
        raise ExportSourceConflictError("Export source original is unsafe.") from error
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    return descriptor


def _detect_mime_type(original_name: str, header: bytes) -> str:
    """Return a conservative MIME type from signatures, then filename hints."""

    signatures = (
        (header.startswith(b"\xff\xd8\xff"), "image/jpeg"),
        (header.startswith(b"\x89PNG\r\n\x1a\n"), "image/png"),
        (header.startswith((b"II*\x00", b"MM\x00*")), "image/tiff"),
        (header.startswith(b"fLaC"), "audio/flac"),
        (header.startswith(b"RIFF") and header[8:12] == b"WAVE", "audio/wav"),
        (
            header.startswith(b"ID3")
            or (len(header) >= 2 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0),
            "audio/mpeg",
        ),
        (len(header) >= 12 and header[4:8] == b"ftyp", "video/mp4"),
        (b"%PDF-" in header, "application/pdf"),
    )
    for matches, mime_type in signatures:
        if matches:
            return mime_type
    guessed, _ = mimetypes.guess_type(original_name, strict=False)
    return guessed or "application/octet-stream"


def _reject_symlink_components(root: Path, candidate: Path) -> None:
    """Reject symlinks at every component below the trusted media root."""

    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ExportSourceConflictError(
            "Export source path escapes media root."
        ) from error
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise ExportSourceConflictError(
                "Export source path contains a symbolic link."
            )


def _media_iri(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_MEDIA_IRI_LENGTH:
        raise ExportSourceRequestError("Resolver mediaIri is invalid.")
    parsed = urlsplit(value)
    if not parsed.scheme or any(ord(character) < 33 for character in value):
        raise ExportSourceRequestError("Resolver mediaIri is invalid.")
    return value


def _storage_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_STORAGE_PATH_LENGTH
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
    ):
        raise ExportSourceRequestError("Resolver storage path is invalid.")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ExportSourceRequestError("Resolver storage path is invalid.")
    return PurePosixPath(*parts).as_posix()


def _original_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_ORIGINAL_NAME_LENGTH
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ExportSourceRequestError("Resolver originalName is invalid.")
    return value


def _assert_purpose_specific_secret(secret: str) -> None:
    other_names = (
        "OLDAP_ACCESS_JWT_SECRET",
        "OLDAP_REFRESH_JWT_SECRET",
        "OLDAP_MEDIA_JWT_SECRET",
        "OLDAP_IMPORT_UPLOAD_JWT_SECRET",
        "OLDAP_IMPORT_SERVICE_JWT_SECRET",
        "OLDAP_IMPORT_RECORDS_JWT_SECRET",
        "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET",
    )
    if secret in {os.getenv(name) for name in other_names if os.getenv(name)}:
        raise ExportSourceAuthenticationUnavailable(
            "Export source resolver key is not purpose-specific."
        )
