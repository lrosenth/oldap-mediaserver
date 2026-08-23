"""Closed request and response domain for the resumable mobile upload v1 API."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping
from urllib.parse import urlparse
from uuid import UUID

import rfc8785


CHECKSUM_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ALLOWED_IMAGE_MIME_TYPES = frozenset(
    {"image/jpeg", "image/png", "image/heic", "image/heif"}
)
UPLOAD_STATES = frozenset(
    {
        "initialized",
        "uploading",
        "verifying",
        "processing",
        "committing",
        "committed",
        "cancelled",
        "failed",
        "expired",
    }
)
TRANSFER_STATES = frozenset({"initialized", "uploading"})
TERMINAL_STATES = frozenset({"committed", "cancelled", "failed", "expired"})


class MobileUploadError(Exception):
    """Stable protocol failure safe to expose through problem+json."""

    def __init__(
        self,
        status: int,
        code: str,
        title: str,
        *,
        detail: str | None = None,
        retryable: bool = False,
        upload_offset: int | None = None,
        retry_after_seconds: int | None = None,
        field_errors: Mapping[str, list[str]] | None = None,
    ) -> None:
        super().__init__(detail or title)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.retryable = retryable
        self.upload_offset = upload_offset
        self.retry_after_seconds = retry_after_seconds
        self.field_errors = dict(field_errors or {})


class MobileUploadInvariantError(RuntimeError):
    """Raised when durable registry and private upload bytes disagree."""


@dataclass(frozen=True, slots=True)
class InitializeUpload:
    """Validated and normalized initialization request."""

    client_asset_id: str
    staging_area_id: str
    original_name: str
    original_mime_type: str
    byte_length: int
    checksum: str
    comment: str | None

    def canonical_payload(self) -> dict[str, object]:
        """Return the closed JSON body used for durable idempotency hashing."""

        payload: dict[str, object] = {
            "clientAssetId": self.client_asset_id,
            "stagingAreaId": self.staging_area_id,
            "originalName": self.original_name,
            "originalMimeType": self.original_mime_type,
            "byteLength": self.byte_length,
            "checksum": self.checksum,
        }
        if self.comment is not None:
            payload["comment"] = self.comment
        return payload


@dataclass(frozen=True, slots=True)
class CommitUpload:
    """Validated commit-request identity repeated by the mobile client."""

    client_asset_id: str
    byte_length: int
    checksum: str

    def canonical_payload(self) -> dict[str, object]:
        """Return the closed JSON body used for durable idempotency hashing."""

        return {
            "clientAssetId": self.client_asset_id,
            "byteLength": self.byte_length,
            "checksum": self.checksum,
        }


@dataclass(frozen=True, slots=True)
class ResolvedMobileInbox:
    """Current OLDAP-authoritative destination facts for one permitted upload."""

    staging_area_id: str
    mobile_folder_id: str
    default_role_id: str


@dataclass(frozen=True, slots=True)
class MobileAccessIdentity:
    """Stable account IRI plus current human-facing OLDAP user identifier."""

    user_id: str
    user_iri: str


@dataclass(frozen=True, slots=True)
class UploadStatus:
    """Durable upload state returned by initialization, status, and commit."""

    upload_id: str
    client_asset_id: str
    staging_area_id: str
    state: str
    offset: int
    byte_length: int
    chunk_size: int
    last_activity_at: datetime
    expires_at: datetime
    declared_checksum: str
    verified_checksum: str | None = None
    asset_id: str | None = None
    resource_iri: str | None = None
    error: dict[str, object] | None = None
    committed_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the exact public UploadStatus representation."""

        value: dict[str, object] = {
            "uploadId": self.upload_id,
            "clientAssetId": self.client_asset_id,
            "stagingAreaId": self.staging_area_id,
            "state": self.state,
            "offset": self.offset,
            "byteLength": self.byte_length,
            "chunkSize": self.chunk_size,
            "lastActivityAt": format_timestamp(self.last_activity_at),
            "expiresAt": format_timestamp(self.expires_at),
            "declaredChecksum": self.declared_checksum,
        }
        if self.verified_checksum is not None:
            value["verifiedChecksum"] = self.verified_checksum
        if self.asset_id is not None:
            value["assetId"] = self.asset_id
        if self.resource_iri is not None:
            value["resourceIri"] = self.resource_iri
        if self.error is not None:
            value["error"] = self.error
        return value

    def committed_result(self) -> dict[str, object]:
        """Return the terminal commit result once Step 11D records it."""

        if (
            self.state != "committed"
            or self.asset_id is None
            or self.resource_iri is None
            or self.verified_checksum is None
            or self.committed_at is None
        ):
            raise MobileUploadInvariantError("Committed upload result is incomplete.")
        return {
            "uploadId": self.upload_id,
            "clientAssetId": self.client_asset_id,
            "stagingAreaId": self.staging_area_id,
            "state": "committed",
            "assetId": self.asset_id,
            "resourceIri": self.resource_iri,
            "checksum": self.verified_checksum,
            "committedAt": format_timestamp(self.committed_at),
        }


def parse_initialize_upload(value: Any, *, max_original_bytes: int) -> InitializeUpload:
    """Validate one closed initialization body without accepting server fields."""

    required = {
        "clientAssetId",
        "stagingAreaId",
        "originalName",
        "originalMimeType",
        "byteLength",
        "checksum",
    }
    allowed = required | {"comment"}
    body = _closed_object(value, required, allowed)
    client_asset_id = canonical_uuid(body["clientAssetId"], "clientAssetId")
    staging_area_id = absolute_identifier(body["stagingAreaId"], "stagingAreaId")
    original_name = normalized_original_name(body["originalName"])
    mime_type = body["originalMimeType"]
    if not isinstance(mime_type, str) or mime_type not in ALLOWED_IMAGE_MIME_TYPES:
        raise invalid_fields(
            {
                "originalMimeType": [
                    "Only JPEG, PNG, HEIC, and HEIF images are accepted."
                ]
            }
        )
    byte_length = bounded_integer(
        body["byteLength"], "byteLength", minimum=1, maximum=max_original_bytes
    )
    checksum = canonical_checksum(body["checksum"])
    comment = body.get("comment")
    if comment is not None:
        if not isinstance(comment, str) or len(comment) > 2000 or has_control(comment):
            raise invalid_fields(
                {
                    "comment": [
                        "The comment must be control-free and at most 2000 characters."
                    ]
                }
            )
        if unicodedata.normalize("NFC", comment) != comment:
            raise invalid_fields(
                {"comment": ["The comment must use NFC normalization."]}
            )
    return InitializeUpload(
        client_asset_id=client_asset_id,
        staging_area_id=staging_area_id,
        original_name=original_name,
        original_mime_type=mime_type,
        byte_length=byte_length,
        checksum=checksum,
        comment=comment,
    )


def parse_commit_upload(value: Any, *, max_original_bytes: int) -> CommitUpload:
    """Validate one closed commit request body."""

    fields = {"clientAssetId", "byteLength", "checksum"}
    body = _closed_object(value, fields, fields)
    return CommitUpload(
        client_asset_id=canonical_uuid(body["clientAssetId"], "clientAssetId"),
        byte_length=bounded_integer(
            body["byteLength"], "byteLength", minimum=1, maximum=max_original_bytes
        ),
        checksum=canonical_checksum(body["checksum"]),
    )


def canonical_request_hash(value: Mapping[str, object]) -> str:
    """Return a SHA-256 hash over RFC 8785 canonical JSON bytes."""

    try:
        encoded = rfc8785.dumps(dict(value))
    except (rfc8785.CanonicalizationError, ValueError, TypeError) as error:
        raise MobileUploadError(
            400,
            "invalid_request",
            "Invalid request",
            detail="The request cannot be canonicalized.",
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def canonical_uuid(value: Any, field: str) -> str:
    """Accept only the canonical lower-case textual UUID representation."""

    if not isinstance(value, str):
        raise invalid_fields({field: ["A canonical UUID is required."]})
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise invalid_fields({field: ["A canonical UUID is required."]}) from error
    if str(parsed) != value:
        raise invalid_fields({field: ["A canonical lower-case UUID is required."]})
    return value


def canonical_checksum(value: Any) -> str:
    """Validate the versioned SHA-256 representation."""

    if not isinstance(value, str) or CHECKSUM_RE.fullmatch(value) is None:
        raise invalid_fields(
            {"checksum": ["Use sha256 followed by 64 lower-case hexadecimal digits."]}
        )
    return value


def absolute_identifier(value: Any, field: str) -> str:
    """Validate one exact absolute URI/URN while preserving its representation."""

    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or has_control(value)
    ):
        raise invalid_fields({field: ["An absolute URI is required."]})
    parsed = urlparse(value)
    if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
        raise invalid_fields({field: ["An absolute URI is required."]})
    return value


def normalized_original_name(value: Any) -> str:
    """Validate one NFC, path-free original filename bounded by UTF-8 bytes."""

    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or has_control(value)
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > 255
    ):
        raise invalid_fields(
            {
                "originalName": [
                    "Use one NFC-normalized, path-free name of at most 255 UTF-8 bytes."
                ]
            }
        )
    return value


def bounded_integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    """Validate a JSON integer without accepting booleans or coercion."""

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise invalid_fields(
            {field: [f"Use an integer between {minimum} and {maximum}."]}
        )
    return value


def has_control(value: str) -> bool:
    """Return whether text contains Unicode control, surrogate, or private-use code points."""

    return any(unicodedata.category(character).startswith("C") for character in value)


def parse_timestamp(value: str) -> datetime:
    """Restore one UTC timestamp stored by this service."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise MobileUploadInvariantError("Stored upload timestamp has no timezone.")
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    """Serialize one timezone-aware timestamp in the API's UTC form."""

    if value.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware.")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def invalid_fields(fields: Mapping[str, list[str]]) -> MobileUploadError:
    """Build the stable validation problem used by all closed request parsers."""

    return MobileUploadError(
        400,
        "invalid_request",
        "Invalid request",
        detail="One or more request fields are invalid.",
        field_errors=fields,
    )


def _closed_object(value: Any, required: set[str], allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise invalid_fields({"body": ["A JSON object is required."]})
    missing = sorted(required - value.keys())
    unexpected = sorted(value.keys() - allowed)
    errors: dict[str, list[str]] = {}
    if missing:
        errors["body"] = [f"Missing fields: {', '.join(missing)}."]
    if unexpected:
        errors.setdefault("body", []).append(
            f"Unexpected fields: {', '.join(unexpected)}."
        )
    if errors:
        raise invalid_fields(errors)
    return value
