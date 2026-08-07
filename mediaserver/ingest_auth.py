"""Purpose-specific authentication for direct ZIP SIP uploads."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import jwt

UPLOAD_TOKEN_TYPE = "ingest-upload"
UPLOAD_TOKEN_AUDIENCE = "oldap-media-ingest"
MAX_COMPRESSED_BYTES = 500_000_000


class UploadAuthenticationUnavailable(RuntimeError):
    """Raised when purpose-specific verification is not safely configured."""


class InvalidUploadCapability(ValueError):
    """Raised for malformed, expired, or wrong-purpose upload credentials."""


class UploadCapabilityMismatch(PermissionError):
    """Raised when a valid capability does not authorize this request target."""


@dataclass(frozen=True, slots=True)
class UploadCapability:
    """Validated immutable authorization facts from an upload JWT."""

    import_id: str
    subject: str
    token_id: str
    max_bytes: int


def decode_upload_capability(
    token: str,
    import_id: str,
    *,
    secret: str | None = None,
    issuer: str | None = None,
) -> UploadCapability:
    """Validate a direct-upload JWT and bind it to the requested import.

    Args:
        token: Raw Bearer credential.
        import_id: UUID from the request path.
        secret: Optional injected signing secret for tests.
        issuer: Optional expected issuer override.

    Returns:
        Closed capability facts safe for authorization decisions.

    Raises:
        UploadAuthenticationUnavailable: If key separation is unsafe.
        InvalidUploadCapability: If JWT signature, time, purpose, or claims fail.
        UploadCapabilityMismatch: If the token belongs to another import.
    """
    _validate_uuid(import_id)
    signing_secret = secret or os.getenv("OLDAP_IMPORT_UPLOAD_JWT_SECRET", "")
    if len(signing_secret.encode("utf-8")) < 32:
        raise UploadAuthenticationUnavailable(
            "OLDAP_IMPORT_UPLOAD_JWT_SECRET must contain at least 32 bytes."
        )
    other_secrets = {
        os.getenv("OLDAP_ACCESS_JWT_SECRET"),
        os.getenv("OLDAP_MEDIA_JWT_SECRET"),
        os.getenv("OLDAP_IMPORT_SERVICE_JWT_SECRET"),
        os.getenv("OLDAP_IMPORT_RECORDS_JWT_SECRET"),
    }
    if signing_secret in {value for value in other_secrets if value}:
        raise UploadAuthenticationUnavailable(
            "The import upload secret must be purpose-specific."
        )
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_secret,
            algorithms=["HS256"],
            audience=UPLOAD_TOKEN_AUDIENCE,
            issuer=issuer or os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            options={
                "require": [
                    "typ",
                    "sub",
                    "importId",
                    "jti",
                    "iat",
                    "exp",
                    "iss",
                    "aud",
                    "maxBytes",
                ]
            },
        )
    except jwt.PyJWTError as error:
        raise InvalidUploadCapability(
            "Invalid or expired upload capability."
        ) from error

    max_bytes = claims.get("maxBytes")
    token_import_id = claims.get("importId")
    if (
        claims.get("typ") != UPLOAD_TOKEN_TYPE
        or not isinstance(claims.get("sub"), str)
        or not claims["sub"]
        or not isinstance(claims.get("jti"), str)
        or not claims["jti"]
        or isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= MAX_COMPRESSED_BYTES
        or not isinstance(token_import_id, str)
    ):
        raise InvalidUploadCapability("Invalid upload capability claims.")
    try:
        _validate_uuid(token_import_id)
    except ValueError as error:
        raise InvalidUploadCapability("Invalid upload capability claims.") from error
    if token_import_id != import_id:
        raise UploadCapabilityMismatch(
            "The upload capability does not authorize this import."
        )
    return UploadCapability(
        import_id=token_import_id,
        subject=claims["sub"],
        token_id=claims["jti"],
        max_bytes=max_bytes,
    )


def _validate_uuid(value: str) -> None:
    parsed = UUID(str(value))
    if str(parsed) != str(value).lower():
        raise ValueError("importId must be a canonical UUID.")
