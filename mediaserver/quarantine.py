"""Atomic, immutable filesystem storage for uploaded ZIP SIPs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Any
from uuid import UUID, uuid4

from storage_capacity import StorageCapacityGuard

STREAM_CHUNK_BYTES = 1024 * 1024
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")
ABANDONED_PART_MAX_AGE_SECONDS = 24 * 60 * 60
PART_DIRECTORY_RE = re.compile(
    r"^\.part-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-.+$"
)


class QuarantineError(Exception):
    """Base class for safely reportable quarantine failures."""


class UploadTooLarge(QuarantineError):
    """Raised as soon as streamed bytes exceed the authorized ceiling."""


class InvalidZipContent(QuarantineError):
    """Raised when the restrictive ZIP signature is absent."""


class UploadLengthMismatch(QuarantineError):
    """Raised when actual bytes differ from the declared Content-Length."""


class FinalizedUploadConflict(QuarantineError):
    """Raised when another request ID already finalized this import."""


@dataclass(frozen=True, slots=True)
class UploadReceipt:
    """Durable receipt stored beside one immutable SIP."""

    import_id: str
    upload_request_id: str
    event_id: str
    stored_at: datetime
    size_bytes: int
    sha256: str
    state_notification: str = "PENDING"

    def to_dict(self, *, internal: bool = False) -> dict[str, Any]:
        """Serialize the public receipt, optionally retaining callback facts."""
        result: dict[str, Any] = {
            "importId": self.import_id,
            "uploadRequestId": self.upload_request_id,
            "storedAt": self.stored_at.isoformat().replace("+00:00", "Z"),
            "sizeBytes": self.size_bytes,
            "sha256": self.sha256,
            "stateNotification": self.state_notification,
        }
        if internal:
            result["eventId"] = self.event_id
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "UploadReceipt":
        """Restore and validate a persisted internal receipt."""
        stored_at = datetime.fromisoformat(
            str(value["storedAt"]).replace("Z", "+00:00")
        )
        if stored_at.tzinfo is None:
            raise ValueError("storedAt must include a timezone.")
        receipt = cls(
            import_id=str(value["importId"]),
            upload_request_id=str(value["uploadRequestId"]),
            event_id=str(value["eventId"]),
            stored_at=stored_at.astimezone(UTC),
            size_bytes=int(value["sizeBytes"]),
            sha256=str(value["sha256"]),
            state_notification=str(value["stateNotification"]),
        )
        _validate_uuid(receipt.import_id)
        _validate_uuid(receipt.upload_request_id)
        _validate_uuid(receipt.event_id)
        if (
            receipt.size_bytes < 1
            or len(receipt.sha256) != 64
            or any(character not in "0123456789abcdef" for character in receipt.sha256)
            or receipt.state_notification not in {"PENDING", "DELIVERED"}
        ):
            raise ValueError("Persisted upload receipt is invalid.")
        return receipt


class QuarantineStore:
    """Create one atomically visible, immutable quarantine directory per job."""

    def __init__(
        self,
        root: Path,
        *,
        chunk_bytes: int = STREAM_CHUNK_BYTES,
        capacity_guard: StorageCapacityGuard | None = None,
    ) -> None:
        if chunk_bytes <= 0:
            raise ValueError("chunk_bytes must be positive.")
        self.root = root
        self.chunk_bytes = chunk_bytes
        self.capacity_guard = capacity_guard

    def store(
        self,
        import_id: str,
        upload_request_id: str,
        source: BinaryIO,
        *,
        declared_size_bytes: int,
        max_bytes: int,
        required_capacity_bytes: int | None = None,
        now: datetime | None = None,
    ) -> tuple[UploadReceipt, bool]:
        """Stream and atomically finalize one SIP without exposing partial data.

        Returns:
            The durable receipt and ``True`` only for an exact replay.

        Side Effects:
            A successful first request atomically renames a fully fsynced
            temporary directory to ``<root>/<importId>``. Every ordinary error
            removes its temporary directory.
        """
        _validate_uuid(import_id)
        _validate_uuid(upload_request_id)
        if not 1 <= declared_size_bytes <= max_bytes:
            raise UploadTooLarge("Declared upload size exceeds its capability.")
        self.root.mkdir(parents=True, exist_ok=True)
        existing = self._existing_receipt(import_id)
        if existing is not None:
            return self._replay(existing, upload_request_id)
        if self.capacity_guard is not None:
            self.capacity_guard.require(
                self.root,
                additional_bytes=(
                    declared_size_bytes
                    if required_capacity_bytes is None
                    else required_capacity_bytes
                ),
            )

        temporary = Path(tempfile.mkdtemp(prefix=f".part-{import_id}-", dir=self.root))
        sip_part = temporary / "sip.zip.part"
        try:
            digest = hashlib.sha256()
            size_bytes = 0
            signature = b""
            with sip_part.open("xb") as destination:
                while chunk := source.read(self.chunk_bytes):
                    size_bytes += len(chunk)
                    if size_bytes > max_bytes:
                        raise UploadTooLarge(
                            "Streamed upload exceeds its authorized byte limit."
                        )
                    if len(signature) < 4:
                        signature = (signature + chunk)[:4]
                    destination.write(chunk)
                    digest.update(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if size_bytes != declared_size_bytes:
                raise UploadLengthMismatch(
                    "Streamed bytes differ from the declared Content-Length."
                )
            if signature not in ZIP_SIGNATURES:
                raise InvalidZipContent("Uploaded content is not a supported ZIP.")

            sip_path = temporary / "sip.zip"
            sip_part.rename(sip_path)
            receipt = UploadReceipt(
                import_id=import_id,
                upload_request_id=upload_request_id,
                event_id=str(uuid4()),
                stored_at=now or datetime.now(UTC),
                size_bytes=size_bytes,
                sha256=digest.hexdigest(),
            )
            _write_json_durable(
                temporary / "receipt.json", receipt.to_dict(internal=True)
            )
            _fsync_directory(temporary)
            final_directory = self.root / import_id
            try:
                temporary.rename(final_directory)
            except OSError:
                existing = self._existing_receipt(import_id)
                if existing is None:
                    raise
                return self._replay(existing, upload_request_id)
            _fsync_directory(self.root)
            return receipt, False
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def _existing_receipt(self, import_id: str) -> UploadReceipt | None:
        directory = self.root / import_id
        receipt_path = directory / "receipt.json"
        sip_path = directory / "sip.zip"
        if not receipt_path.is_file() or not sip_path.is_file():
            return None
        receipt = UploadReceipt.from_dict(
            json.loads(receipt_path.read_text(encoding="utf-8"))
        )
        if (
            receipt.import_id != import_id
            or sip_path.stat().st_size != receipt.size_bytes
        ):
            raise OSError("Finalized quarantine receipt is inconsistent.")
        return receipt

    def pending_receipts(self, *, limit: int = 100) -> tuple[UploadReceipt, ...]:
        """Return a bounded deterministic snapshot of undelivered receipts."""
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000.")
        if not self.root.exists():
            return ()
        pending: list[UploadReceipt] = []
        for directory in sorted(self.root.iterdir(), key=lambda path: path.name):
            if len(pending) >= limit:
                break
            if not directory.is_dir():
                continue
            try:
                _validate_uuid(directory.name)
            except ValueError:
                continue
            receipt = self._existing_receipt(directory.name)
            if receipt is not None and receipt.state_notification == "PENDING":
                pending.append(receipt)
        return tuple(pending)

    def mark_notification_delivered(
        self, import_id: str, event_id: str
    ) -> UploadReceipt:
        """Atomically persist callback delivery for the exact retained event."""
        _validate_uuid(import_id)
        _validate_uuid(event_id)
        receipt = self._existing_receipt(import_id)
        if receipt is None:
            raise FileNotFoundError("Finalized import receipt does not exist.")
        if receipt.event_id != event_id:
            raise FinalizedUploadConflict(
                "Callback event does not match the finalized upload receipt."
            )
        if receipt.state_notification == "DELIVERED":
            return receipt
        delivered = UploadReceipt(
            import_id=receipt.import_id,
            upload_request_id=receipt.upload_request_id,
            event_id=receipt.event_id,
            stored_at=receipt.stored_at,
            size_bytes=receipt.size_bytes,
            sha256=receipt.sha256,
            state_notification="DELIVERED",
        )
        _replace_json_durable(
            self.root / import_id / "receipt.json",
            delivered.to_dict(internal=True),
        )
        return delivered

    def cleanup_abandoned_parts(
        self,
        *,
        now: datetime | None = None,
        max_age_seconds: int = ABANDONED_PART_MAX_AGE_SECONDS,
        limit: int = 100,
    ) -> int:
        """Remove only bounded, old, recognizable partial-upload directories.

        Finalized UUID directories, files, symlinks, unknown names, and recent
        partial directories are never touched. The default 24-hour grace is far
        longer than the 15-minute ingress timeout, so age cannot select a live
        request under the supported deployment envelope.

        Args:
            now: Injectable UTC reference time.
            max_age_seconds: Positive grace period before removal.
            limit: Maximum directories removed in one maintenance pass.

        Returns:
            Number of partial directories removed.
        """
        if max_age_seconds < 1:
            raise ValueError("max_age_seconds must be positive.")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000.")
        if not self.root.exists():
            return 0
        cutoff = (now or datetime.now(UTC)).timestamp() - max_age_seconds
        removed = 0
        for candidate in sorted(self.root.iterdir(), key=lambda path: path.name):
            if removed >= limit:
                break
            if (
                PART_DIRECTORY_RE.fullmatch(candidate.name) is None
                or candidate.is_symlink()
            ):
                continue
            try:
                metadata = candidate.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mtime > cutoff:
                continue
            try:
                shutil.rmtree(candidate)
            except FileNotFoundError:
                continue
            removed += 1
        return removed

    @staticmethod
    def _replay(
        receipt: UploadReceipt, upload_request_id: str
    ) -> tuple[UploadReceipt, bool]:
        if receipt.upload_request_id != upload_request_id:
            raise FinalizedUploadConflict(
                "This import was finalized by another upload request."
            )
        return receipt, True


def _write_json_durable(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _replace_json_durable(path: Path, value: dict[str, Any]) -> None:
    """Atomically replace mutable receipt delivery state in one directory."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".receipt-", suffix=".part", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_uuid(value: str) -> None:
    parsed = UUID(str(value))
    if str(parsed) != str(value).lower():
        raise ValueError("Identifier must be a canonical UUID.")
