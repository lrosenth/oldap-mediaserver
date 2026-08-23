"""Purpose-bound OLDAP client for one idempotent mobile-media commit."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Protocol

import jwt
import requests

from mobile_upload_domain import canonical_checksum, canonical_uuid, parse_timestamp


TOKEN_TYPE = "mobile-media-service"
TOKEN_PURPOSE = "mobile-media-commit"
TOKEN_AUDIENCE = "oldap-api-mobile-media"
TOKEN_SUBJECT = "oldap-mediaserver"
TOKEN_LIFETIME_SECONDS = 120
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
OTHER_SECRET_NAMES = (
    "OLDAP_ACCESS_JWT_SECRET",
    "OLDAP_REFRESH_JWT_SECRET",
    "OLDAP_MEDIA_JWT_SECRET",
    "OLDAP_PASSWORD_RESET_JWT_SECRET",
    "OLDAP_IMPORT_UPLOAD_JWT_SECRET",
    "OLDAP_IMPORT_SERVICE_JWT_SECRET",
    "OLDAP_IMPORT_RECORDS_JWT_SECRET",
    "OLDAP_EXPORT_SERVICE_JWT_SECRET",
    "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET",
)
DEFINITIVE_REJECTIONS = frozenset(
    {
        (400, "validation_failed"),
        (403, "staging_area_not_permitted"),
        (403, "staging_upload_not_permitted"),
        (404, "staging_folder_not_found"),
        (409, "staging_folder_not_protected"),
        (409, "staging_destination_changed"),
        (409, "client_asset_conflict"),
    }
)


class HttpSession(Protocol):
    """Minimal requests-compatible transport used by the commit client."""

    def post(self, url: str, **kwargs: Any) -> Any: ...


class MobileMediaCommitFailure(RuntimeError):
    """A classified OLDAP result safe for the worker state machine."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class OldapMobileMediaCommitClient:
    """Submit immutable publication evidence with a fresh service JWT."""

    def __init__(
        self,
        oldap_api_url: str,
        signing_secret: str,
        *,
        issuer: str = "https://oldap.org",
        session: HttpSession | None = None,
        timeout_seconds: float = 30.0,
        clock: Callable[[], datetime] | None = None,
        other_secrets: tuple[str, ...] = (),
    ) -> None:
        self.oldap_api_url = oldap_api_url.rstrip("/")
        self.signing_secret = signing_secret
        self.issuer = issuer
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._validate_secret(other_secrets)

    @classmethod
    def from_environment(cls) -> "OldapMobileMediaCommitClient":
        """Build the client from deployment-provided, purpose-specific settings."""

        return cls(
            os.getenv("OLDAP_API_URL", "http://localhost:8000"),
            os.getenv("OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET", ""),
            issuer=os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            other_secrets=tuple(
                value for name in OTHER_SECRET_NAMES if (value := os.getenv(name, ""))
            ),
        )

    def commit(
        self, upload_id: str, request_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Return the exact permanent receipt or a classified failure."""

        canonical_uuid(upload_id, "uploadId")
        if REQUEST_ID_RE.fullmatch(request_id) is None:
            raise ValueError("Mobile-media request ID is invalid.")
        try:
            response = self.session.post(
                f"{self.oldap_api_url}/internal/mobile-media/v1/uploads/{upload_id}/commit",
                json=dict(payload),
                headers={
                    "Authorization": f"Bearer {self._token()}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Request-ID": request_id,
                },
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as error:
            raise MobileMediaCommitFailure(
                "upstream_unavailable", retryable=True
            ) from error

        status = int(response.status_code)
        if status == 200:
            try:
                value = response.json()
                return _validated_result(value, payload)
            except (TypeError, ValueError, KeyError) as error:
                raise MobileMediaCommitFailure(
                    "upstream_response_ambiguous", retryable=True
                ) from error
        try:
            problem = response.json()
            code = str(problem.get("code", "upstream_unavailable"))
            declared_retryable = problem.get("retryable") is True
        except (TypeError, ValueError, AttributeError):
            code = "upstream_unavailable"
            declared_retryable = status >= 500
        if not declared_retryable and (status, code) in DEFINITIVE_REJECTIONS:
            raise MobileMediaCommitFailure(code, retryable=False)
        raise MobileMediaCommitFailure(code, retryable=True)

    def _token(self) -> str:
        now = self._clock().astimezone(UTC)
        expires = now + timedelta(seconds=TOKEN_LIFETIME_SECONDS)
        return jwt.encode(
            {
                "typ": TOKEN_TYPE,
                "purpose": TOKEN_PURPOSE,
                "sub": TOKEN_SUBJECT,
                "aud": TOKEN_AUDIENCE,
                "iss": self.issuer,
                "iat": int(now.timestamp()),
                "exp": int(expires.timestamp()),
            },
            self.signing_secret,
            algorithm="HS256",
        )

    def _validate_secret(self, other_secrets: tuple[str, ...]) -> None:
        if len(self.signing_secret.encode("utf-8")) < 32:
            raise RuntimeError(
                "OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET must contain at least 32 bytes."
            )
        if self.signing_secret in set(other_secrets):
            raise RuntimeError(
                "The mobile-media service JWT secret must be purpose-specific."
            )


def _validated_result(value: Any, request: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "eventId",
        "uploadId",
        "clientAssetId",
        "stagingAreaId",
        "assetId",
        "resourceIri",
        "checksum",
        "committedAt",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("OLDAP mobile-media result is not closed.")
    for field in ("eventId", "uploadId", "clientAssetId", "assetId"):
        canonical_uuid(value[field], field)
    canonical_checksum(value["checksum"])
    parse_timestamp(value["committedAt"])
    for field in ("eventId", "uploadId", "clientAssetId", "stagingAreaId", "checksum"):
        if value[field] != request[field]:
            raise ValueError(f"OLDAP mobile-media result changed {field}.")
    if value["assetId"] != request["clientAssetId"]:
        raise ValueError("OLDAP mobile-media result changed assetId.")
    resource_iri = value["resourceIri"]
    if not isinstance(resource_iri, str) or not resource_iri.startswith(
        ("urn:", "http://", "https://")
    ):
        raise ValueError("OLDAP mobile-media result has an invalid resource IRI.")
    return dict(value)
