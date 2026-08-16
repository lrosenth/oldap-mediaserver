"""Authenticated control-plane client for the project-neutral export worker."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
import requests
import rfc8785

SERVICE_TOKEN_TYPE = "export-service"
SERVICE_TOKEN_AUDIENCE = "oldap-api-export-service"
WORKER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 256 * 1024 * 1024


class ExportServiceError(RuntimeError):
    """Base class for export worker control-plane failures."""


class ExportServiceUnavailable(ExportServiceError):
    """Raised for retryable transport, server, or malformed-response failures."""


class ExportServiceRejected(ExportServiceError):
    """Raised when oldap-api rejects a claim-bound worker operation."""


@dataclass(frozen=True, slots=True)
class BuildClaim:
    """Strict immutable representation of one BUILD lease."""

    claim_id: str
    export_id: str
    state_version: int
    claimed_at: datetime
    lease_expires_at: datetime
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class CleanupClaim:
    """Strict immutable representation of one CLEANUP lease."""

    claim_id: str
    export_id: str
    state_version: int
    claimed_at: datetime
    lease_expires_at: datetime
    cleanup_reason: str


ExportClaim = BuildClaim | CleanupClaim


@dataclass(frozen=True, slots=True)
class ExportServiceClient:
    """Issue short service JWTs for export claims, manifests, and results."""

    api_base_url: str
    secret: str
    worker_id: str
    issuer: str = "https://oldap.org"
    subject: str = "media.oldap.org"
    timeout_seconds: float = 30.0
    lease_seconds: int = 300
    token_ttl_seconds: int = 60

    @classmethod
    def from_environment(cls) -> "ExportServiceClient":
        """Build the client from purpose-specific deployment settings."""

        return cls(
            api_base_url=os.getenv("OLDAP_API_URL", "http://localhost:8000").rstrip(
                "/"
            ),
            secret=os.getenv("OLDAP_EXPORT_SERVICE_JWT_SECRET", ""),
            worker_id=os.getenv("OLDAP_EXPORT_WORKER_ID", "media-export-1"),
            issuer=os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            subject=os.getenv("OLDAP_EXPORT_SERVICE_SUBJECT", "media.oldap.org"),
            timeout_seconds=float(os.getenv("OLDAP_EXPORT_API_TIMEOUT_SECONDS", "30")),
            lease_seconds=int(os.getenv("OLDAP_EXPORT_LEASE_SECONDS", "300")),
        )

    def validate_configuration(self) -> None:
        """Fail closed for weak/shared credentials and unsafe worker settings."""

        if len(self.secret.encode("utf-8")) < 32:
            raise ExportServiceError("Export service JWT secret must contain 32 bytes.")
        other_names = (
            "OLDAP_ACCESS_JWT_SECRET",
            "OLDAP_REFRESH_JWT_SECRET",
            "OLDAP_MEDIA_JWT_SECRET",
            "OLDAP_IMPORT_UPLOAD_JWT_SECRET",
            "OLDAP_IMPORT_SERVICE_JWT_SECRET",
            "OLDAP_IMPORT_RECORDS_JWT_SECRET",
            "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET",
        )
        if self.secret in {
            value for name in other_names if (value := os.getenv(name, ""))
        }:
            raise ExportServiceError("Export service JWT secret must be isolated.")
        if (
            not self.api_base_url
            or WORKER_ID_RE.fullmatch(self.worker_id) is None
            or not self.subject
            or self.timeout_seconds <= 0
            or not 60 <= self.lease_seconds <= 900
            or not 1 <= self.token_ttl_seconds <= 120
        ):
            raise ExportServiceError("Export worker API settings are invalid.")

    def claim_next(self, *, session: Any = requests) -> ExportClaim | None:
        """Atomically request the next BUILD or CLEANUP task."""

        response = self._request(
            "POST",
            "/internal/export-claims",
            json={
                "workerId": self.worker_id,
                "supportedTasks": ["BUILD", "CLEANUP"],
                "requestedLeaseSeconds": self.lease_seconds,
            },
            session=session,
        )
        self._require_success(response, "claim")
        try:
            value = response.json()
        except (TypeError, ValueError) as error:
            raise ExportServiceUnavailable("API returned an invalid claim.") from error
        if value is None:
            return None
        return _parse_claim(value)

    def heartbeat(self, claim: ExportClaim, *, session: Any = requests) -> datetime:
        """Renew one exact claim and return its new expiry."""

        response = self._request(
            "POST",
            f"/internal/export-claims/{claim.claim_id}/heartbeat",
            json={
                "workerId": self.worker_id,
                "expectedStateVersion": claim.state_version,
            },
            session=session,
        )
        self._require_success(response, "heartbeat")
        try:
            value = response.json()
            if not isinstance(value, dict) or set(value) != {
                "claimId",
                "leaseExpiresAt",
            }:
                raise ValueError
            if value["claimId"] != claim.claim_id:
                raise ValueError
            return _timestamp(value["leaseExpiresAt"])
        except (TypeError, ValueError, KeyError) as error:
            raise ExportServiceUnavailable(
                "API returned an invalid heartbeat acknowledgement."
            ) from error

    def get_manifest(
        self, claim: BuildClaim, *, session: Any = requests
    ) -> dict[str, Any]:
        """Fetch and verify the canonical manifest bound to a BUILD claim."""

        response = self._request(
            "GET",
            f"/internal/exports/{claim.export_id}/manifest",
            params={"claimId": claim.claim_id},
            session=session,
        )
        self._require_success(response, "manifest")
        content = bytes(response.content)
        if not content or len(content) > MAX_MANIFEST_BYTES:
            raise ExportServiceUnavailable("API returned an invalid manifest size.")
        digest = hashlib.sha256(content).hexdigest()
        if digest != claim.manifest_sha256:
            raise ExportServiceUnavailable("Manifest digest differs from its claim.")
        expected_header = "sha-256=" + base64.b64encode(bytes.fromhex(digest)).decode(
            "ascii"
        )
        if response.headers.get("Digest") != expected_header:
            raise ExportServiceUnavailable("Manifest Digest header is inconsistent.")
        try:
            value = response.json()
            canonical = rfc8785.dumps(value)
        except (TypeError, ValueError, rfc8785.CanonicalizationError) as error:
            raise ExportServiceUnavailable(
                "API returned invalid manifest JSON."
            ) from error
        if canonical != content:
            raise ExportServiceUnavailable("Manifest response is not canonical JSON.")
        _validate_manifest_envelope(value, claim)
        return value

    def publish_build_result(
        self, claim: BuildClaim, result: dict[str, Any], *, session: Any = requests
    ) -> None:
        """Publish one idempotent READY or FAILED result."""

        response = self._request(
            "POST",
            f"/internal/exports/{claim.export_id}/result",
            json=result,
            session=session,
        )
        self._require_success(response, "build result")
        _require_job_acknowledgement(response, claim.export_id, {"READY", "FAILED"})

    def publish_cleanup_result(
        self,
        claim: CleanupClaim,
        result: dict[str, Any],
        *,
        session: Any = requests,
    ) -> None:
        """Publish idempotent deletion proof for one CLEANUP claim."""

        response = self._request(
            "POST",
            f"/internal/exports/{claim.export_id}/cleanup-result",
            json=result,
            session=session,
        )
        self._require_success(response, "cleanup result")
        _require_job_acknowledgement(response, claim.export_id, {"DELETED"})

    def _request(
        self,
        method: str,
        path: str,
        *,
        session: Any,
        **kwargs: Any,
    ) -> Any:
        self.validate_configuration()
        try:
            return session.request(
                method,
                f"{self.api_base_url}{path}",
                headers={"Authorization": f"Bearer {self._token()}"},
                timeout=self.timeout_seconds,
                **kwargs,
            )
        except requests.RequestException as error:
            raise ExportServiceUnavailable("oldap-api is unavailable.") from error

    def _token(self, *, now: datetime | None = None) -> str:
        current = now or datetime.now(UTC)
        return jwt.encode(
            {
                "typ": SERVICE_TOKEN_TYPE,
                "sub": self.subject,
                "jti": str(uuid4()),
                "iat": current,
                "exp": current + timedelta(seconds=self.token_ttl_seconds),
                "iss": self.issuer,
                "aud": SERVICE_TOKEN_AUDIENCE,
            },
            self.secret,
            algorithm="HS256",
        )

    @staticmethod
    def _require_success(response: Any, operation: str) -> None:
        status = int(response.status_code)
        if 200 <= status < 300:
            return
        if status >= 500:
            raise ExportServiceUnavailable(
                f"oldap-api {operation} failed with HTTP {status}."
            )
        raise ExportServiceRejected(
            f"oldap-api rejected {operation} with HTTP {status}."
        )


def _parse_claim(value: Any) -> ExportClaim:
    common = {
        "claimId",
        "exportId",
        "task",
        "stateVersion",
        "claimedAt",
        "leaseExpiresAt",
    }
    if not isinstance(value, dict) or value.get("task") not in {"BUILD", "CLEANUP"}:
        raise ExportServiceUnavailable("API returned an invalid export claim.")
    required = common | (
        {"manifestSha256"} if value["task"] == "BUILD" else {"cleanupReason"}
    )
    if set(value) != required:
        raise ExportServiceUnavailable("API returned an invalid export claim.")
    claim_id = _uuid(value["claimId"])
    export_id = _uuid(value["exportId"])
    version = value["stateVersion"]
    claimed_at = _timestamp(value["claimedAt"])
    lease_expires_at = _timestamp(value["leaseExpiresAt"])
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version < 0
        or lease_expires_at <= claimed_at
    ):
        raise ExportServiceUnavailable("API returned invalid export claim facts.")
    if value["task"] == "BUILD":
        digest = _sha256(value["manifestSha256"])
        return BuildClaim(
            claim_id,
            export_id,
            version,
            claimed_at,
            lease_expires_at,
            digest,
        )
    reason = value["cleanupReason"]
    if reason not in {"READY_DELETE", "FAILED", "CANCELLED", "EXPIRED"}:
        raise ExportServiceUnavailable("API returned an invalid cleanup reason.")
    return CleanupClaim(
        claim_id,
        export_id,
        version,
        claimed_at,
        lease_expires_at,
        reason,
    )


def _validate_manifest_envelope(value: Any, claim: BuildClaim) -> None:
    common = {
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
    kind = value.get("kind") if isinstance(value, dict) else None
    expected = common | (
        {"archiveUnits"} if kind in {"ARCHIVE_UNIT", "ARCHIVE_ALL"} else set()
    )
    limits = value.get("limits") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or kind not in {"STAGING_FOLDER", "STAGING_ALL", "ARCHIVE_UNIT", "ARCHIVE_ALL"}
        or set(value) != expected
        or value.get("documentType") != "oldap.zip-export.manifest"
        or value.get("schemaVersion") != "1.0.0"
        or value.get("exportId") != claim.export_id
        or not isinstance(limits, dict)
        or set(limits) != {"maxArchiveBytes"}
        or isinstance(limits["maxArchiveBytes"], bool)
        or not isinstance(limits["maxArchiveBytes"], int)
        or not 1 <= limits["maxArchiveBytes"] <= 50_000_000_000
        or not isinstance(value.get("directories"), list)
        or not isinstance(value.get("media"), list)
        or (
            kind in {"ARCHIVE_UNIT", "ARCHIVE_ALL"}
            and not isinstance(value.get("archiveUnits"), list)
        )
    ):
        raise ExportServiceUnavailable("API returned an invalid export manifest.")


def _require_job_acknowledgement(
    response: Any, export_id: str, states: set[str]
) -> None:
    try:
        value = response.json()
    except (TypeError, ValueError) as error:
        raise ExportServiceUnavailable(
            "API returned an invalid acknowledgement."
        ) from error
    if (
        not isinstance(value, dict)
        or value.get("exportId") != export_id
        or value.get("state") not in states
    ):
        raise ExportServiceUnavailable("API returned a mismatched acknowledgement.")


def _uuid(value: Any) -> str:
    try:
        canonical = str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as error:
        raise ExportServiceUnavailable("API returned a malformed UUID.") from error
    if value != canonical:
        raise ExportServiceUnavailable("API returned a non-canonical UUID.")
    return canonical


def _timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise ExportServiceUnavailable("API returned a malformed timestamp.") from error
    if parsed.tzinfo is None:
        raise ExportServiceUnavailable("API returned a timezone-free timestamp.")
    return parsed.astimezone(UTC)


def _sha256(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ExportServiceUnavailable("API returned an invalid SHA-256 digest.")
    return value
