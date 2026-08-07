"""Immutable validation-record storage and purpose-specific read authorization."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

import jwt
import rfc8785


RECORD_TYPES = frozenset({"manifest", "report"})
RECORDS_TOKEN_TYPE = "import-records"
RECORDS_TOKEN_AUDIENCE = "oldap-media-import-records"


class ImportRecordError(RuntimeError):
    """Base class for immutable record storage failures."""


class ImportRecordConflict(ImportRecordError):
    """Raised when an import already owns different retained records."""


class ImportRecordAuthorizationError(ImportRecordError):
    """Raised when a record-read token is absent, invalid, or mis-scoped."""


@dataclass(frozen=True, slots=True)
class StoredValidationRecords:
    """Checksums and replay facts for one immutable validation outcome."""

    import_id: str
    outcome: str
    manifest_sha256: str | None
    report_sha256: str
    summary: dict[str, Any]
    temporary_payload_deleted: bool
    failure_code: str | None = None


class ImportRecordStore:
    """Publish and retrieve one create-only manifest/report pair per import."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def publish(
        self,
        import_id: str,
        *,
        manifest: dict[str, Any],
        report: dict[str, Any],
        temporary_payload_deleted: bool,
    ) -> StoredValidationRecords:
        """Atomically publish exact JSON bytes and durable replay metadata.

        An exact retry returns the existing record. Different bytes for the
        same import are rejected so API checksum references never become stale.
        """

        _canonical_uuid(import_id)
        if manifest.get("importId") != import_id or report.get("importId") != import_id:
            raise ValueError("Record identity does not match importId.")
        outcome = str(manifest.get("validationOutcome", ""))
        if outcome not in {"READY", "INVALID"} or report.get("status") != outcome:
            raise ValueError("Manifest and report outcomes must match.")

        manifest_bytes = rfc8785.dumps(manifest)
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        bound_report = dict(report)
        bound_report["manifestSha256"] = manifest_sha256
        bound_report["manifestCanonicalization"] = "RFC8785"
        report_bytes = _json_bytes(bound_report)
        report_sha256 = hashlib.sha256(report_bytes).hexdigest()
        metadata = {
            "importId": import_id,
            "outcome": outcome,
            "manifestSha256": manifest_sha256,
            "reportSha256": report_sha256,
            "summary": bound_report["summary"],
            "temporaryPayloadDeleted": temporary_payload_deleted,
            "failureCode": None,
        }

        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        final = self.root / import_id
        existing = self.load_result(import_id)
        if existing is not None:
            if (
                existing.manifest_sha256 == manifest_sha256
                and existing.report_sha256 == report_sha256
                and existing.temporary_payload_deleted == temporary_payload_deleted
            ):
                return existing
            raise ImportRecordConflict("Different records already exist for importId.")

        temporary = Path(tempfile.mkdtemp(prefix=f".part-{import_id}-", dir=self.root))
        try:
            _write_durable(temporary / "manifest.json", manifest_bytes)
            _write_durable(temporary / "report.json", report_bytes)
            _write_durable(temporary / "result.json", _json_bytes(metadata))
            _fsync_directory(temporary)
            try:
                temporary.rename(final)
            except OSError:
                existing = self.load_result(import_id)
                if existing is None:
                    raise
                if (
                    existing.manifest_sha256 == manifest_sha256
                    and existing.report_sha256 == report_sha256
                    and existing.temporary_payload_deleted == temporary_payload_deleted
                ):
                    return existing
                raise ImportRecordConflict(
                    "Different records concurrently claimed importId."
                )
            _fsync_directory(self.root)
            return StoredValidationRecords(
                import_id=import_id,
                outcome=outcome,
                manifest_sha256=manifest_sha256,
                report_sha256=report_sha256,
                summary=bound_report["summary"],
                temporary_payload_deleted=temporary_payload_deleted,
            )
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def publish_failure(
        self,
        import_id: str,
        *,
        report: dict[str, Any],
        failure_code: str,
    ) -> StoredValidationRecords:
        """Atomically retain a FAILED report without inventing a manifest."""

        _canonical_uuid(import_id)
        if (
            report.get("importId") != import_id
            or report.get("status") != "FAILED"
            or "manifestSha256" in report
            or "manifestCanonicalization" in report
            or not failure_code
        ):
            raise ValueError("FAILED record does not match its closed contract.")
        report_bytes = _json_bytes(report)
        report_sha256 = hashlib.sha256(report_bytes).hexdigest()
        metadata = {
            "importId": import_id,
            "outcome": "FAILED",
            "manifestSha256": None,
            "reportSha256": report_sha256,
            "summary": report["summary"],
            "temporaryPayloadDeleted": True,
            "failureCode": failure_code,
        }
        existing = self.load_result(import_id)
        if existing is not None:
            if (
                existing.outcome == "FAILED"
                and existing.report_sha256 == report_sha256
                and existing.failure_code == failure_code
            ):
                return existing
            raise ImportRecordConflict("Different records already exist for importId.")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        final = self.root / import_id
        temporary = Path(tempfile.mkdtemp(prefix=f".part-{import_id}-", dir=self.root))
        try:
            _write_durable(temporary / "report.json", report_bytes)
            _write_durable(temporary / "result.json", _json_bytes(metadata))
            _fsync_directory(temporary)
            try:
                temporary.rename(final)
            except OSError:
                existing = self.load_result(import_id)
                if (
                    existing is not None
                    and existing.outcome == "FAILED"
                    and existing.report_sha256 == report_sha256
                    and existing.failure_code == failure_code
                ):
                    return existing
                raise ImportRecordConflict(
                    "Different records concurrently claimed importId."
                )
            _fsync_directory(self.root)
            return StoredValidationRecords(
                import_id=import_id,
                outcome="FAILED",
                manifest_sha256=None,
                report_sha256=report_sha256,
                summary=dict(report["summary"]),
                temporary_payload_deleted=True,
                failure_code=failure_code,
            )
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def load_result(self, import_id: str) -> StoredValidationRecords | None:
        """Read replay metadata only when all immutable files remain consistent."""

        _canonical_uuid(import_id)
        directory = self.root / import_id
        result_path = directory / "result.json"
        if not result_path.is_file():
            return None
        value = json.loads(result_path.read_text(encoding="utf-8"))
        outcome = str(value["outcome"])
        manifest = directory / "manifest.json"
        report = directory / "report.json"
        if not report.is_file() or (outcome != "FAILED" and not manifest.is_file()):
            raise ImportRecordError("Retained validation record is incomplete.")
        manifest_sha256 = value.get("manifestSha256")
        if (
            (
                outcome == "FAILED"
                and (manifest.is_file() or manifest_sha256 is not None)
            )
            or (
                outcome != "FAILED"
                and hashlib.sha256(manifest.read_bytes()).hexdigest() != manifest_sha256
            )
            or hashlib.sha256(report.read_bytes()).hexdigest()
            != value.get("reportSha256")
        ):
            raise ImportRecordError("Retained validation record checksum mismatch.")
        return StoredValidationRecords(
            import_id=str(value["importId"]),
            outcome=outcome,
            manifest_sha256=(
                str(manifest_sha256) if manifest_sha256 is not None else None
            ),
            report_sha256=str(value["reportSha256"]),
            summary=dict(value["summary"]),
            temporary_payload_deleted=bool(value["temporaryPayloadDeleted"]),
            failure_code=value.get("failureCode"),
        )

    def read(self, import_id: str, record_type: str) -> tuple[bytes, str]:
        """Return exact retained bytes and their lower-case SHA-256 digest."""

        _canonical_uuid(import_id)
        if record_type not in RECORD_TYPES:
            raise ValueError("Unknown import record type.")
        result = self.load_result(import_id)
        if result is None:
            raise FileNotFoundError("Import record does not exist.")
        content = (self.root / import_id / f"{record_type}.json").read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        expected = (
            result.manifest_sha256
            if record_type == "manifest"
            else result.report_sha256
        )
        if expected is None:
            raise FileNotFoundError("Import record does not exist.")
        if digest != expected:
            raise ImportRecordError("Retained validation record checksum mismatch.")
        return content, digest

    def read_manifest(self, import_id: str, expected_sha256: str) -> dict[str, Any]:
        """Return the retained manifest only when its API-bound digest matches.

        Args:
            import_id: Canonical import UUID.
            expected_sha256: Digest carried by the immutable IMPORT claim.

        Returns:
            The decoded manifest object whose exact retained bytes match the
            supplied digest.

        Raises:
            ImportRecordError: If the digest or JSON document is inconsistent.
            FileNotFoundError: If no manifest exists for the import.
        """

        content, actual_sha256 = self.read(import_id, "manifest")
        if actual_sha256 != expected_sha256:
            raise ImportRecordError("IMPORT claim manifest checksum mismatch.")
        try:
            value = json.loads(content)
        except json.JSONDecodeError as error:
            raise ImportRecordError("Retained manifest is not valid JSON.") from error
        if not isinstance(value, dict):
            raise ImportRecordError("Retained manifest must be a JSON object.")
        return value

    def publish_import_failure(
        self, import_id: str, failure_code: str
    ) -> dict[str, Any]:
        """Durably retain deterministic post-compensation failure evidence."""

        canonical = _canonical_uuid(import_id)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", failure_code) is None:
            raise ValueError("Import failure code is invalid.")
        value = {
            "documentType": "oldap.zip-import.failure-receipt",
            "schemaVersion": "1.0.0",
            "importId": canonical,
            "eventId": str(uuid5(UUID(canonical), f"import-failure:{failure_code}")),
            "failureCode": failure_code,
            "compensated": True,
            "temporaryPayloadDeleted": True,
        }
        content = _json_bytes(value)
        directory = self.root / canonical
        if not directory.is_dir() or directory.is_symlink():
            raise ImportRecordError("Validation records are unavailable.")
        path = directory / "import-failure.json"
        try:
            _write_durable(path, content)
            _fsync_directory(directory)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != content:
                raise ImportRecordConflict(
                    "Different import failure evidence already exists."
                )
        return value

    def load_import_failure(self, import_id: str) -> dict[str, Any] | None:
        """Return exact retained post-compensation evidence when present."""

        canonical = _canonical_uuid(import_id)
        path = self.root / canonical / "import-failure.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise ImportRecordError("Import failure evidence is unsafe.")
        try:
            value = json.loads(path.read_bytes())
        except json.JSONDecodeError as error:
            raise ImportRecordError("Import failure evidence is invalid.") from error
        if (
            not isinstance(value, dict)
            or value.get("documentType") != "oldap.zip-import.failure-receipt"
            or value.get("schemaVersion") != "1.0.0"
            or value.get("importId") != canonical
            or value.get("compensated") is not True
            or value.get("temporaryPayloadDeleted") is not True
            or value.get("eventId")
            != str(
                uuid5(
                    UUID(canonical),
                    f"import-failure:{value.get('failureCode', '')}",
                )
            )
        ):
            raise ImportRecordError("Import failure evidence is inconsistent.")
        return value


def authorize_record_token(
    authorization: str | None,
    import_id: str,
    *,
    secret: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Validate the dedicated API-to-media JWT for exactly one import record."""

    _canonical_uuid(import_id)
    parts = authorization.split() if authorization else []
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise ImportRecordAuthorizationError("Import records authorization required.")
    key = (
        secret
        if secret is not None
        else os.getenv("OLDAP_IMPORT_RECORDS_JWT_SECRET", "")
    )
    if len(key.encode("utf-8")) < 32:
        raise ImportRecordAuthorizationError(
            "Import records authorization unavailable."
        )
    other_secrets = {
        os.getenv("OLDAP_ACCESS_JWT_SECRET"),
        os.getenv("OLDAP_MEDIA_JWT_SECRET"),
        os.getenv("OLDAP_IMPORT_UPLOAD_JWT_SECRET"),
        os.getenv("OLDAP_IMPORT_SERVICE_JWT_SECRET"),
    }
    if key in {value for value in other_secrets if value}:
        raise ImportRecordAuthorizationError("Import records key is not isolated.")
    try:
        claims = jwt.decode(
            parts[1],
            key,
            algorithms=["HS256"],
            audience=RECORDS_TOKEN_AUDIENCE,
            issuer=issuer or os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            options={"require": ["typ", "sub", "importId", "iat", "exp", "iss", "aud"]},
        )
    except jwt.PyJWTError as error:
        raise ImportRecordAuthorizationError("Invalid import records token.") from error
    if (
        claims.get("typ") != RECORDS_TOKEN_TYPE
        or claims.get("sub") != "oldap-api"
        or claims.get("importId") != import_id
    ):
        raise ImportRecordAuthorizationError("Import records token scope mismatch.")
    return claims


def digest_header(digest: str) -> str:
    """Return the RFC 9530-style SHA-256 response header value in the contract."""

    return f"sha-256=:{base64.b64encode(bytes.fromhex(digest)).decode('ascii')}:"


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _write_durable(path: Path, content: bytes) -> None:
    with path.open("xb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError) as error:
        raise ValueError("importId must be a UUID.") from error
    canonical = str(parsed)
    if value != canonical:
        raise ValueError("importId must be a canonical UUID.")
    return canonical
