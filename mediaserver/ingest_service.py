"""Authenticated control-plane client for the sequential ingest worker."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4, uuid5

import jwt
import requests


SERVICE_TOKEN_TYPE = "import-service"
SERVICE_TOKEN_AUDIENCE = "oldap-api-import-service"
WORKER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class IngestServiceError(RuntimeError):
    """Base class for worker control-plane errors."""


class IngestServiceUnavailable(IngestServiceError):
    """Raised for retryable transport and 5xx failures."""


class IngestServiceRejected(IngestServiceError):
    """Raised when the API rejects a claim-bound operation."""


@dataclass(frozen=True, slots=True)
class TargetPreflightFinding:
    """One API-owned target identity or direct-child collision finding."""

    code: str
    blocking: bool
    entry_index: int | None = None
    existing_kind: str | None = None
    existing_name: str | None = None


@dataclass(frozen=True, slots=True)
class ValidationClaim:
    """Strict immutable representation of a VALIDATE lease."""

    claim_id: str
    import_id: str
    state_version: int
    lease_expires_at: datetime
    job_created_at: str
    requested_by_iri: str
    original_file_name: str
    compressed_size_bytes: int
    sip_sha256: str
    target: dict[str, str]

    @classmethod
    def from_dict(cls, value: Any) -> "ValidationClaim":
        """Parse a closed API claim and reject missing validation facts."""

        required = {
            "claimId",
            "importId",
            "task",
            "stateVersion",
            "claimedAt",
            "leaseExpiresAt",
            "target",
            "jobCreatedAt",
            "requestedByIri",
            "originalFileName",
            "compressedSizeBytes",
            "sipSha256",
        }
        optional = {"manifestSha256", "cleanupReason"}
        if (
            not isinstance(value, dict)
            or not required <= set(value) <= required | optional
        ):
            raise IngestServiceUnavailable("API returned an invalid import claim.")
        if value["task"] != "VALIDATE":
            raise IngestServiceUnavailable("API returned a non-validation claim.")
        target_keys = {
            "projectShortName",
            "stagingAreaIri",
            "stagingAreaName",
            "targetRootFolderIri",
            "targetRootFolderName",
        }
        target = value["target"]
        if (
            not isinstance(target, dict)
            or set(target) != target_keys
            or not all(isinstance(item, str) and item for item in target.values())
        ):
            raise IngestServiceUnavailable("API returned an invalid target snapshot.")
        try:
            claim_id = str(UUID(value["claimId"]))
            import_id = str(UUID(value["importId"]))
            lease_expires_at = datetime.fromisoformat(
                str(value["leaseExpiresAt"]).replace("Z", "+00:00")
            )
        except (TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned malformed claim identity."
            ) from error
        version = value["stateVersion"]
        size = value["compressedSizeBytes"]
        sip_sha256 = value["sipSha256"]
        if (
            claim_id != value["claimId"]
            or import_id != value["importId"]
            or lease_expires_at.tzinfo is None
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version < 0
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= 500_000_000
            or not isinstance(sip_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sip_sha256) is None
        ):
            raise IngestServiceUnavailable("API returned invalid validation facts.")
        return cls(
            claim_id=claim_id,
            import_id=import_id,
            state_version=version,
            lease_expires_at=lease_expires_at.astimezone(UTC),
            job_created_at=str(value["jobCreatedAt"]),
            requested_by_iri=str(value["requestedByIri"]),
            original_file_name=str(value["originalFileName"]),
            compressed_size_bytes=size,
            sip_sha256=sip_sha256,
            target=dict(target),
        )


@dataclass(frozen=True, slots=True)
class ImportClaim:
    """Strict immutable representation of an IMPORT lease."""

    claim_id: str
    import_id: str
    state_version: int
    lease_expires_at: datetime
    manifest_sha256: str
    target: dict[str, str]

    @classmethod
    def from_dict(cls, value: Any) -> "ImportClaim":
        """Parse a closed API claim and require its READY manifest binding."""

        if not isinstance(value, dict) or value.get("task") != "IMPORT":
            raise IngestServiceUnavailable("API returned invalid import facts.")
        validation = ValidationClaim.from_dict(value | {"task": "VALIDATE"})
        manifest = value.get("manifestSha256")
        if (
            not isinstance(manifest, str)
            or re.fullmatch(r"[0-9a-f]{64}", manifest) is None
        ):
            raise IngestServiceUnavailable("API returned invalid import facts.")
        return cls(
            claim_id=validation.claim_id,
            import_id=validation.import_id,
            state_version=validation.state_version,
            lease_expires_at=validation.lease_expires_at,
            manifest_sha256=manifest,
            target=validation.target,
        )


@dataclass(frozen=True, slots=True)
class CleanupClaim:
    """Strict immutable representation of an API-selected CLEANUP lease."""

    claim_id: str
    import_id: str
    state_version: int
    lease_expires_at: datetime
    cleanup_reason: str

    @classmethod
    def from_dict(cls, value: Any) -> "CleanupClaim":
        """Parse only the fields required to delete temporary job payload."""

        required = {
            "claimId",
            "importId",
            "task",
            "stateVersion",
            "claimedAt",
            "leaseExpiresAt",
            "target",
            "jobCreatedAt",
            "requestedByIri",
            "originalFileName",
            "compressedSizeBytes",
            "cleanupReason",
        }
        optional = {"sipSha256", "manifestSha256"}
        if (
            not isinstance(value, dict)
            or not required <= set(value) <= required | optional
            or value.get("task") != "CLEANUP"
            or value.get("cleanupReason")
            not in {"CANCELLED", "EXPIRED", "IMPORTED", "FAILED"}
        ):
            raise IngestServiceUnavailable("API returned invalid cleanup facts.")
        target = value["target"]
        target_keys = {
            "projectShortName",
            "stagingAreaIri",
            "stagingAreaName",
            "targetRootFolderIri",
            "targetRootFolderName",
        }
        try:
            claim_id = str(UUID(value["claimId"]))
            import_id = str(UUID(value["importId"]))
            claimed_at = datetime.fromisoformat(
                str(value["claimedAt"]).replace("Z", "+00:00")
            )
            lease_expires_at = datetime.fromisoformat(
                str(value["leaseExpiresAt"]).replace("Z", "+00:00")
            )
            job_created_at = datetime.fromisoformat(
                str(value["jobCreatedAt"]).replace("Z", "+00:00")
            )
        except (TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned malformed cleanup identity."
            ) from error
        version = value["stateVersion"]
        size = value["compressedSizeBytes"]
        if (
            claim_id != value["claimId"]
            or import_id != value["importId"]
            or claimed_at.tzinfo is None
            or lease_expires_at.tzinfo is None
            or job_created_at.tzinfo is None
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version < 0
            or not isinstance(target, dict)
            or set(target) != target_keys
            or not all(isinstance(item, str) and item for item in target.values())
            or not isinstance(value["requestedByIri"], str)
            or not value["requestedByIri"]
            or not isinstance(value["originalFileName"], str)
            or not value["originalFileName"]
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= 500_000_000
            or any(
                digest is not None
                and (
                    not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                )
                for digest in (
                    value.get("sipSha256"),
                    value.get("manifestSha256"),
                )
            )
        ):
            raise IngestServiceUnavailable("API returned invalid cleanup facts.")
        return cls(
            claim_id=claim_id,
            import_id=import_id,
            state_version=version,
            lease_expires_at=lease_expires_at.astimezone(UTC),
            cleanup_reason=value["cleanupReason"],
        )


WorkerClaim = ValidationClaim | ImportClaim | CleanupClaim


@dataclass(frozen=True, slots=True)
class ImportServiceClient:
    """Issue short-lived tokens for claim, heartbeat, and result operations."""

    api_base_url: str
    secret: str
    worker_id: str
    issuer: str = "https://oldap.org"
    subject: str = "media.oldap.org"
    timeout_seconds: float = 10.0
    lease_seconds: int = 300

    @classmethod
    def from_environment(cls) -> "ImportServiceClient":
        """Build the worker client from purpose-specific environment settings."""

        return cls(
            api_base_url=os.getenv("OLDAP_API_URL", "http://localhost:8000").rstrip(
                "/"
            ),
            secret=os.getenv("OLDAP_IMPORT_SERVICE_JWT_SECRET", ""),
            worker_id=os.getenv("OLDAP_INGEST_WORKER_ID", "media-ingest-1"),
            issuer=os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            subject=os.getenv("OLDAP_IMPORT_SERVICE_SUBJECT", "media.oldap.org"),
            timeout_seconds=float(os.getenv("OLDAP_INGEST_API_TIMEOUT_SECONDS", "10")),
            lease_seconds=int(os.getenv("OLDAP_INGEST_LEASE_SECONDS", "300")),
        )

    def validate_configuration(self) -> None:
        """Fail closed for weak/shared credentials and unsafe worker settings."""

        if len(self.secret.encode("utf-8")) < 32:
            raise IngestServiceError("Import service JWT secret must contain 32 bytes.")
        if self.secret in {
            value
            for value in (
                os.getenv("OLDAP_ACCESS_JWT_SECRET"),
                os.getenv("OLDAP_MEDIA_JWT_SECRET"),
                os.getenv("OLDAP_IMPORT_UPLOAD_JWT_SECRET"),
                os.getenv("OLDAP_IMPORT_RECORDS_JWT_SECRET"),
            )
            if value
        }:
            raise IngestServiceError("Import service JWT secret must be isolated.")
        if (
            not self.api_base_url
            or WORKER_ID_RE.fullmatch(self.worker_id) is None
            or not self.subject
            or self.timeout_seconds <= 0
            or not 60 <= self.lease_seconds <= 900
        ):
            raise IngestServiceError("Ingest worker API settings are invalid.")

    def claim_validation(self, *, session: Any = requests) -> ValidationClaim | None:
        """Atomically request at most one validation task from oldap-api."""

        response = self._post(
            "/internal/import-claims",
            {
                "workerId": self.worker_id,
                "supportedTasks": ["VALIDATE"],
                "requestedLeaseSeconds": self.lease_seconds,
            },
            session=session,
        )
        if response.status_code == 204:
            return None
        self._require_success(response, "claim")
        try:
            return ValidationClaim.from_dict(response.json())
        except (TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid claim response."
            ) from error

    def claim_next(self, *, session: Any = requests) -> WorkerClaim | None:
        """Atomically request the next validation, import, or cleanup task."""

        response = self._post(
            "/internal/import-claims",
            {
                "workerId": self.worker_id,
                "supportedTasks": ["VALIDATE", "IMPORT", "CLEANUP"],
                "requestedLeaseSeconds": self.lease_seconds,
            },
            session=session,
        )
        if response.status_code == 204:
            return None
        self._require_success(response, "claim")
        try:
            value = response.json()
            if value.get("task") == "VALIDATE":
                return ValidationClaim.from_dict(value)
            if value.get("task") == "IMPORT":
                return ImportClaim.from_dict(value)
            if value.get("task") == "CLEANUP":
                return CleanupClaim.from_dict(value)
        except (AttributeError, TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid claim response."
            ) from error
        raise IngestServiceUnavailable("API returned an unsupported import task.")

    def publish_cleanup_result(
        self,
        claim: CleanupClaim,
        *,
        completed_at: datetime | None = None,
        session: Any = requests,
    ) -> dict[str, Any]:
        """Prove deletion for one claim and validate its authoritative outcome."""

        current = (completed_at or datetime.now(UTC)).astimezone(UTC)
        event_id = str(uuid5(UUID(claim.import_id), f"cleanup:{claim.cleanup_reason}"))
        response = self._post(
            f"/internal/imports/{claim.import_id}/cleanup-result",
            {
                "eventId": event_id,
                "claimId": claim.claim_id,
                "expectedStateVersion": claim.state_version,
                "reason": claim.cleanup_reason,
                "temporaryPayloadDeleted": True,
                "completedAt": current.isoformat().replace("+00:00", "Z"),
            },
            session=session,
        )
        self._require_success(response, "cleanup result")
        try:
            result = response.json()
            expected_state = (
                "EXPIRED" if claim.cleanup_reason == "EXPIRED" else claim.cleanup_reason
            )
            if (
                result.get("importId") != claim.import_id
                or result.get("state") != expected_state
                or result.get("cleanupPending") is not False
            ):
                raise ValueError
            return result
        except (AttributeError, TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid cleanup result."
            ) from error

    def heartbeat(self, claim: WorkerClaim, *, session: Any = requests) -> datetime:
        """Renew one active claim and return its authoritative expiry."""

        response = self._post(
            f"/internal/import-claims/{claim.claim_id}/heartbeat",
            {"workerId": self.worker_id, "expectedStateVersion": claim.state_version},
            session=session,
        )
        self._require_success(response, "heartbeat")
        try:
            value = response.json()
            if value.get("claimId") != claim.claim_id:
                raise ValueError
            expiry = datetime.fromisoformat(
                str(value["leaseExpiresAt"]).replace("Z", "+00:00")
            )
            if expiry.tzinfo is None:
                raise ValueError
            return expiry.astimezone(UTC)
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid heartbeat."
            ) from error

    def preflight_target(
        self,
        claim: ValidationClaim,
        top_level_entries: tuple[dict[str, Any], ...],
        *,
        timeout_seconds: float | None = None,
        session: Any = requests,
    ) -> tuple[TargetPreflightFinding, ...]:
        """Request API-owned current-target collision analysis for one claim."""

        response = self._post(
            f"/internal/import-claims/{claim.claim_id}/target-preflight",
            {
                "workerId": self.worker_id,
                "expectedStateVersion": claim.state_version,
                "topLevelEntries": list(top_level_entries),
            },
            session=session,
            timeout_seconds=timeout_seconds,
        )
        self._require_success(response, "target preflight")
        try:
            value = response.json()
            if (
                not isinstance(value, dict)
                or set(value) != {"claimId", "targetRootFolderIri", "findings"}
                or value["claimId"] != claim.claim_id
                or value["targetRootFolderIri"] != claim.target["targetRootFolderIri"]
                or not isinstance(value["findings"], list)
                or len(value["findings"]) > len(top_level_entries) + 1
            ):
                raise ValueError
            findings = tuple(
                _parse_target_finding(item, top_level_entries)
                for item in value["findings"]
            )
            indexes = [
                finding.entry_index
                for finding in findings
                if finding.entry_index is not None
            ]
            if len(indexes) != len(set(indexes)) or (
                any(finding.code == "TARGET_CHANGED" for finding in findings)
                and len(findings) != 1
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid target preflight."
            ) from error
        return findings

    def publish_validation_result(
        self,
        claim: ValidationClaim,
        *,
        outcome: str,
        manifest_sha256: str | None,
        report_sha256: str,
        summary: dict[str, Any],
        temporary_payload_deleted: bool,
        failure_code: str | None = None,
        event_id: str | None = None,
        completed_at: datetime | None = None,
        session: Any = requests,
    ) -> dict[str, Any]:
        """Publish a claim-bound idempotent validation result."""

        payload: dict[str, Any] = {
            "eventId": event_id or str(uuid4()),
            "claimId": claim.claim_id,
            "expectedStateVersion": claim.state_version,
            "outcome": outcome,
            "completedAt": (completed_at or datetime.now(UTC))
            .isoformat()
            .replace("+00:00", "Z"),
            "temporaryPayloadDeleted": temporary_payload_deleted,
            "reportSha256": report_sha256,
            "summary": summary,
        }
        if manifest_sha256 is not None:
            payload["manifestSha256"] = manifest_sha256
        if failure_code is not None:
            payload["failureCode"] = failure_code
        response = self._post(
            f"/internal/imports/{claim.import_id}/validation-result",
            payload,
            session=session,
        )
        self._require_success(response, "validation result")
        try:
            result = response.json()
        except (TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid result receipt."
            ) from error
        if result.get("importId") != claim.import_id or result.get("state") != outcome:
            raise IngestServiceUnavailable("API returned a mismatched result receipt.")
        return result

    def commit_import(
        self,
        claim: ImportClaim,
        *,
        folders: tuple[dict[str, Any], ...],
        media: tuple[dict[str, Any], ...],
        session: Any = requests,
    ) -> dict[str, Any]:
        """Submit the deterministic complete staging commit for one IMPORT claim."""

        event_id = str(uuid5(UUID(claim.import_id), "commit-event"))
        payload = {
            "eventId": event_id,
            "claimId": claim.claim_id,
            "expectedStateVersion": claim.state_version,
            "manifestSha256": claim.manifest_sha256,
            "folders": list(folders),
            "media": list(media),
        }
        response = self._post(
            f"/internal/imports/{claim.import_id}/commit", payload, session=session
        )
        self._require_success(response, "import commit")
        try:
            result = response.json()
            job = result["job"]
            resources = result["resources"]
            if (
                set(result) != {"eventId", "job", "resources"}
                or result["eventId"] != event_id
                or not isinstance(job, dict)
                or job.get("importId") != claim.import_id
                or job.get("state") != "IMPORTED"
                or not isinstance(resources, list)
            ):
                raise ValueError
            expected = {
                (item["entryIndex"], item["relativePath"], item.get("assetId"))
                for item in (*folders, *media)
            }
            received = {
                (item["entryIndex"], item["relativePath"], item.get("assetId"))
                for item in resources
                if isinstance(item, dict)
                and set(item)
                <= {"entryIndex", "relativePath", "resourceIri", "assetId"}
                and {"entryIndex", "relativePath", "resourceIri"} <= set(item)
            }
            if received != expected or len(resources) != len(expected):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid import commit receipt."
            ) from error
        return result

    def publish_import_failure(
        self,
        claim: ImportClaim,
        receipt: dict[str, Any],
        *,
        session: Any = requests,
    ) -> dict[str, Any]:
        """Publish durable proof that a rejected import was fully compensated."""

        required = {
            "documentType",
            "schemaVersion",
            "importId",
            "eventId",
            "failureCode",
            "compensated",
            "temporaryPayloadDeleted",
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != required
            or receipt["importId"] != claim.import_id
            or receipt["compensated"] is not True
            or receipt["temporaryPayloadDeleted"] is not True
        ):
            raise IngestServiceError("Import failure receipt is invalid.")
        payload = {
            "eventId": receipt["eventId"],
            "claimId": claim.claim_id,
            "expectedStateVersion": claim.state_version,
            "task": "IMPORT",
            "failureCode": receipt["failureCode"],
            "compensated": True,
            "temporaryPayloadDeleted": True,
        }
        response = self._post(
            f"/internal/imports/{claim.import_id}/failed", payload, session=session
        )
        self._require_success(response, "import failure")
        try:
            result = response.json()
        except (TypeError, ValueError) as error:
            raise IngestServiceUnavailable(
                "API returned an invalid failure receipt."
            ) from error
        if result.get("importId") != claim.import_id or result.get("state") != "FAILED":
            raise IngestServiceUnavailable("API returned a mismatched failure receipt.")
        return result

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        session: Any,
        timeout_seconds: float | None = None,
    ) -> Any:
        self.validate_configuration()
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        if timeout <= 0 or timeout > self.timeout_seconds:
            raise IngestServiceError("API timeout override is outside its boundary.")
        try:
            return session.post(
                f"{self.api_base_url}{path}",
                json=payload,
                headers={"Authorization": f"Bearer {self._token()}"},
                timeout=timeout,
            )
        except requests.RequestException as error:
            raise IngestServiceUnavailable("oldap-api is unavailable.") from error

    @staticmethod
    def _require_success(response: Any, operation: str) -> None:
        if 200 <= response.status_code < 300:
            return
        if response.status_code >= 500:
            raise IngestServiceUnavailable(f"API {operation} is unavailable.")
        raise IngestServiceRejected(
            f"API rejected {operation} with HTTP {response.status_code}."
        )

    def _token(self) -> str:
        current = datetime.now(UTC)
        return jwt.encode(
            {
                "typ": SERVICE_TOKEN_TYPE,
                "sub": self.subject,
                "jti": str(uuid4()),
                "iat": current,
                "exp": current + timedelta(seconds=60),
                "iss": self.issuer,
                "aud": SERVICE_TOKEN_AUDIENCE,
            },
            self.secret,
            algorithm="HS256",
        )


def _parse_target_finding(
    value: Any, top_level_entries: tuple[dict[str, Any], ...]
) -> TargetPreflightFinding:
    """Parse one closed preflight finding and bind it to a submitted entry."""

    if value == {"code": "TARGET_CHANGED", "blocking": True}:
        return TargetPreflightFinding("TARGET_CHANGED", True)
    required = {
        "entryIndex",
        "code",
        "blocking",
        "existingKind",
        "existingName",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Invalid target finding fields.")
    candidates = {entry["entryIndex"]: entry for entry in top_level_entries}
    index = value["entryIndex"]
    code = value["code"]
    blocking = value["blocking"]
    existing_kind = value["existingKind"]
    existing_name = value["existingName"]
    if (
        isinstance(index, bool)
        or index not in candidates
        or code not in {"TARGET_FOLDER_COLLISION", "TARGET_MEDIA_NAME_COLLISION"}
        or not isinstance(blocking, bool)
        or blocking != (code == "TARGET_FOLDER_COLLISION")
        or existing_kind not in {"folder", "media"}
        or not isinstance(existing_name, str)
        or not existing_name
        or len(existing_name.encode("utf-8")) > 255
        or (
            code == "TARGET_MEDIA_NAME_COLLISION"
            and candidates[index]["entryType"] != "file"
        )
    ):
        raise ValueError("Invalid target finding value.")
    return TargetPreflightFinding(
        code=code,
        blocking=blocking,
        entry_index=index,
        existing_kind=existing_kind,
        existing_name=existing_name,
    )
