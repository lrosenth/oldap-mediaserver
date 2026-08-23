"""Durable SQLite registry and private byte store for mobile upload v1."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from uuid import UUID, uuid4, uuid5

from config import MobileUploadLimits
from mobile_upload_domain import (
    CommitUpload,
    InitializeUpload,
    MobileAccessIdentity,
    MobileUploadError,
    MobileUploadInvariantError,
    ResolvedMobileInbox,
    TRANSFER_STATES,
    UploadStatus,
    canonical_request_hash,
    canonical_uuid,
    format_timestamp,
    parse_timestamp,
)
from storage_capacity import PhysicalCapacityInsufficient, StorageCapacityGuard


ACTIVE_STATES = ("initialized", "uploading", "verifying", "processing", "committing")
REOPENABLE_STATES = ("cancelled", "expired")
SCHEMA_VERSION = 2
PREPUBLICATION_PHASES = ("requested", "checksum_verified", "derivatives_ready")


@dataclass(frozen=True, slots=True)
class MobileProcessingClaim:
    """Immutable worker input protected by one renewable registry lease."""

    upload_id: str
    lease_owner: str
    event_id: str
    client_asset_id: str
    owner_user_iri: str
    staging_area_id: str
    original_name: str
    original_mime_type: str
    byte_length: int
    checksum: str
    comment: str | None
    storage_path: str
    upload_directory: Path
    commit_phase: str
    publication: dict[str, Any] | None
    oldap_result: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class MobileCleanupClaim:
    """Exact upload directory atomically claimed for idempotent cleanup."""

    upload_id: str
    lease_owner: str
    state: str
    upload_directory: Path


class MobileUploadRegistry:
    """Coordinate durable upload metadata and append-only private originals.

    SQLite owns authoritative offsets, identities, idempotency records, quota
    reservations, and future worker leases. A per-upload process lock protects
    the file/row boundary. Bytes are flushed before an offset is committed; if
    a process dies after writing but before committing, the next operation
    truncates the unconfirmed suffix back to the durable offset.
    """

    def __init__(
        self,
        root: Path,
        limits: MobileUploadLimits,
        *,
        capacity_guard: StorageCapacityGuard | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not root.is_absolute():
            raise ValueError("Mobile upload root must be a dedicated absolute path.")
        resolved_root = root.resolve(strict=False)
        if resolved_root == Path(resolved_root.anchor):
            raise ValueError("Mobile upload root must be a dedicated absolute path.")
        self.root = resolved_root
        self.limits = limits
        self.capacity_guard = capacity_guard
        self._clock = clock or (lambda: datetime.now(UTC))
        self.database_path = self.root / "registry.sqlite3"
        self.uploads_root = self.root / "uploads"
        self.locks_root = self.root / "locks"
        self._initialize_storage()

    def initialize(
        self,
        owner: MobileAccessIdentity,
        request: InitializeUpload,
        destination: ResolvedMobileInbox,
        idempotency_key: str,
    ) -> tuple[UploadStatus, bool]:
        """Create or exactly replay one upload generation.

        Returns:
            The authoritative status and ``True`` only for a newly created
            upload generation.
        """

        canonical_uuid(idempotency_key, "Idempotency-Key")
        request_hash = canonical_request_hash(request.canonical_payload())
        now = self._now()
        created_directory: Path | None = None
        try:
            with self._transaction() as connection:
                self._expire_inactive(connection, now)
                replay = self._idempotency_replay(
                    connection,
                    owner,
                    request.staging_area_id,
                    idempotency_key,
                    "initialize",
                    request_hash,
                )
                if replay is not None:
                    replay_row = self._row_for_id(connection, replay)
                    self._assert_destination(replay_row, destination)
                    return self._status(replay_row), False

                asset = connection.execute(
                    "SELECT * FROM mobile_assets WHERE client_asset_id = ?",
                    (request.client_asset_id,),
                ).fetchone()
                if asset is not None and (
                    asset["owner_user_iri"] != owner.user_iri
                    or asset["staging_area_id"] != request.staging_area_id
                ):
                    raise self._asset_conflict()

                if asset is not None and asset["current_upload_id"]:
                    current = self._row_for_id(connection, asset["current_upload_id"])
                    if current["state"] not in REOPENABLE_STATES:
                        self._assert_same_asset_request(current, request)
                        self._assert_destination(current, destination)
                        self._insert_idempotency(
                            connection,
                            owner,
                            request.staging_area_id,
                            idempotency_key,
                            "initialize",
                            request_hash,
                            current["upload_id"],
                            now,
                        )
                        return self._status(current), False

                self._require_logical_capacity(
                    connection,
                    owner,
                    request.staging_area_id,
                    request.byte_length,
                )
                remaining_reservations = connection.execute(
                    "SELECT COALESCE(SUM(reserved_bytes - offset), 0) AS bytes "
                    "FROM mobile_uploads WHERE reserved_bytes > offset"
                ).fetchone()["bytes"]
                self._require_physical_capacity(
                    int(remaining_reservations) + request.byte_length
                )

                upload_id = str(uuid4())
                generation = 1 if asset is None else int(asset["generation"]) + 1
                relative_path = f"uploads/{upload_id}/original.part"
                candidate_directory = self.root / "uploads" / upload_id
                self._create_upload_file(candidate_directory)
                created_directory = candidate_directory
                expires_at = now + timedelta(seconds=self.limits.inactivity_seconds)
                if asset is None:
                    connection.execute(
                        """
                        INSERT INTO mobile_assets (
                            client_asset_id, owner_user_id, owner_user_iri, staging_area_id,
                            generation, current_upload_id, created_at
                        ) VALUES (?, ?, ?, ?, ?, NULL, ?)
                        """,
                        (
                            request.client_asset_id,
                            owner.user_id,
                            owner.user_iri,
                            request.staging_area_id,
                            generation,
                            format_timestamp(now),
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO mobile_uploads (
                        upload_id, client_asset_id, generation, owner_user_id,
                        owner_user_iri,
                        staging_area_id, mobile_folder_id, default_role_id, storage_path,
                        original_name, original_mime_type, byte_length, checksum,
                        comment, state, offset, chunk_size, created_at,
                        last_activity_at, expires_at, reserved_bytes, temp_path,
                        commit_phase
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'initialized',
                              0, ?, ?, ?, ?, ?, ?, 'none')
                    """,
                    (
                        upload_id,
                        request.client_asset_id,
                        generation,
                        owner.user_id,
                        owner.user_iri,
                        request.staging_area_id,
                        destination.mobile_folder_id,
                        destination.default_role_id,
                        destination.storage_path,
                        request.original_name,
                        request.original_mime_type,
                        request.byte_length,
                        request.checksum,
                        request.comment,
                        self.limits.chunk_bytes,
                        format_timestamp(now),
                        format_timestamp(now),
                        format_timestamp(expires_at),
                        request.byte_length,
                        relative_path,
                    ),
                )
                connection.execute(
                    """
                    UPDATE mobile_assets
                    SET generation = ?, current_upload_id = ?
                    WHERE client_asset_id = ?
                    """,
                    (generation, upload_id, request.client_asset_id),
                )
                self._insert_idempotency(
                    connection,
                    owner,
                    request.staging_area_id,
                    idempotency_key,
                    "initialize",
                    request_hash,
                    upload_id,
                    now,
                )
                return self._status_for_id(connection, upload_id), True
        except Exception:
            if created_directory is not None:
                shutil.rmtree(created_directory, ignore_errors=True)
            raise

    def get_status(self, upload_id: str, owner: MobileAccessIdentity) -> UploadStatus:
        """Return and repair the authoritative state visible to its owner."""

        canonical_uuid(upload_id, "uploadId")
        with self._upload_lock(upload_id):
            with self._transaction() as connection:
                row = self._owned_row(connection, upload_id, owner)
                row = self._expire_row(connection, row, self._now())
                self._repair_unconfirmed_bytes(connection, row)
                return self._status_for_id(connection, upload_id)

    def append_chunk(
        self,
        upload_id: str,
        owner: MobileAccessIdentity,
        *,
        expected_offset: int,
        upload_length: int,
        chunk: bytes,
        destination: ResolvedMobileInbox,
    ) -> UploadStatus:
        """Append one exact-offset chunk and durably advance its offset."""

        canonical_uuid(upload_id, "uploadId")
        if (
            isinstance(expected_offset, bool)
            or not isinstance(expected_offset, int)
            or expected_offset < 0
        ):
            raise MobileUploadError(
                400, "invalid_upload_offset", "Invalid Upload-Offset"
            )
        if (
            isinstance(upload_length, bool)
            or not isinstance(upload_length, int)
            or upload_length < 1
        ):
            raise MobileUploadError(
                400, "invalid_upload_length", "Invalid Upload-Length"
            )
        if not chunk:
            raise MobileUploadError(400, "empty_chunk", "Chunk body is empty")
        if len(chunk) > self.limits.chunk_bytes:
            raise MobileUploadError(
                413, "chunk_too_large", "Chunk exceeds the v1 chunk size"
            )

        with self._upload_lock(upload_id):
            wrote_path: Path | None = None
            original_offset = 0
            try:
                with self._transaction() as connection:
                    row = self._owned_row(connection, upload_id, owner)
                    row = self._expire_row(connection, row, self._now())
                    self._assert_destination(row, destination)
                    self._repair_unconfirmed_bytes(connection, row)
                    row = self._row_for_id(connection, upload_id)
                    if row["state"] == "expired":
                        raise MobileUploadError(
                            410, "upload_expired", "Upload has expired"
                        )
                    if row["state"] not in TRANSFER_STATES:
                        raise MobileUploadError(
                            409,
                            "upload_not_writable",
                            "Upload no longer accepts chunks",
                            upload_offset=int(row["offset"]),
                        )
                    if upload_length != int(row["byte_length"]):
                        raise MobileUploadError(
                            409,
                            "upload_length_mismatch",
                            "Upload-Length does not match initialization",
                            upload_offset=int(row["offset"]),
                        )
                    original_offset = int(row["offset"])
                    if expected_offset != original_offset:
                        raise MobileUploadError(
                            409,
                            "upload_offset_mismatch",
                            "Upload-Offset does not match the authoritative offset",
                            upload_offset=original_offset,
                        )
                    if original_offset + len(chunk) > int(row["byte_length"]):
                        raise MobileUploadError(
                            413,
                            "upload_too_large",
                            "Chunk would exceed the declared upload length",
                            upload_offset=original_offset,
                        )
                    if len(chunk) != self.limits.chunk_bytes and original_offset + len(
                        chunk
                    ) != int(row["byte_length"]):
                        raise MobileUploadError(
                            400,
                            "invalid_chunk_size",
                            "Only the final chunk may be smaller than 4 MiB",
                            upload_offset=original_offset,
                        )
                    self._require_physical_capacity(len(chunk))
                    wrote_path = self._temp_path(row)
                    self._append_bytes(wrote_path, original_offset, chunk)
                    now = self._now()
                    new_offset = original_offset + len(chunk)
                    state = "uploading" if new_offset > 0 else "initialized"
                    changed = connection.execute(
                        """
                        UPDATE mobile_uploads
                        SET offset = ?, state = ?, last_activity_at = ?, expires_at = ?
                        WHERE upload_id = ? AND offset = ? AND state IN ('initialized', 'uploading')
                        """,
                        (
                            new_offset,
                            state,
                            format_timestamp(now),
                            format_timestamp(
                                now + timedelta(seconds=self.limits.inactivity_seconds)
                            ),
                            upload_id,
                            original_offset,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise MobileUploadInvariantError(
                            "Upload offset compare-and-swap did not update exactly one row."
                        )
                    return self._status_for_id(connection, upload_id)
            except Exception:
                if wrote_path is not None:
                    self._truncate_file(wrote_path, original_offset)
                raise

    def request_commit(
        self,
        upload_id: str,
        owner: MobileAccessIdentity,
        request: CommitUpload,
        destination: ResolvedMobileInbox,
        idempotency_key: str,
    ) -> tuple[UploadStatus, bool]:
        """Durably accept or replay asynchronous commit work for Step 11D."""

        canonical_uuid(upload_id, "uploadId")
        canonical_uuid(idempotency_key, "Idempotency-Key")
        request_hash = canonical_request_hash(request.canonical_payload())
        with self._upload_lock(upload_id):
            stable_failure = False
            accepted_status: UploadStatus | None = None
            with self._transaction() as connection:
                row = self._owned_row(connection, upload_id, owner)
                row = self._expire_row(connection, row, self._now())
                self._assert_destination(row, destination)
                if row["storage_path"] is None:
                    connection.execute(
                        "UPDATE mobile_uploads SET storage_path = ? WHERE upload_id = ?",
                        (destination.storage_path, upload_id),
                    )
                    row = self._row_for_id(connection, upload_id)
                if row["event_id"] is None:
                    connection.execute(
                        "UPDATE mobile_uploads SET event_id = ? WHERE upload_id = ?",
                        (self._event_id(upload_id), upload_id),
                    )
                    row = self._row_for_id(connection, upload_id)
                replay = self._idempotency_replay(
                    connection,
                    owner,
                    row["staging_area_id"],
                    idempotency_key,
                    "commit",
                    request_hash,
                    expected_upload_id=upload_id,
                )
                if replay is not None:
                    row = self._row_for_id(connection, replay)
                self._assert_same_commit_request(row, request)
                if row["state"] == "expired":
                    raise MobileUploadError(410, "upload_expired", "Upload has expired")
                if row["state"] == "cancelled":
                    raise MobileUploadError(
                        410, "upload_cancelled", "Upload was cancelled"
                    )
                if row["state"] == "committed":
                    status = self._status(row)
                    if replay is None:
                        self._insert_idempotency(
                            connection,
                            owner,
                            row["staging_area_id"],
                            idempotency_key,
                            "commit",
                            request_hash,
                            upload_id,
                            self._now(),
                        )
                    return status, True
                if row["state"] in {"verifying", "processing", "committing"}:
                    if replay is None:
                        self._insert_idempotency(
                            connection,
                            owner,
                            row["staging_area_id"],
                            idempotency_key,
                            "commit",
                            request_hash,
                            upload_id,
                            self._now(),
                        )
                    return self._status(row), False
                if row["state"] == "failed":
                    error = self._stored_error(row)
                    if not error or error.get("retryable") is not True:
                        raise MobileUploadError(
                            409,
                            "upload_failed",
                            "Upload has a non-retryable failure",
                        )
                    if self._has_valid_lease(row, self._now()):
                        raise MobileUploadError(
                            409,
                            "upload_busy",
                            "Upload processing is currently active",
                            retryable=True,
                            retry_after_seconds=self.limits.lease_seconds,
                        )
                    resumed_state = self._state_for_phase(row["commit_phase"])
                    resumed_at = self._now()
                    connection.execute(
                        """
                        UPDATE mobile_uploads
                        SET state = ?, error_json = NULL,
                            lease_owner = NULL, lease_expires_at = NULL,
                            last_activity_at = ?, expires_at = ?
                        WHERE upload_id = ?
                        """,
                        (
                            resumed_state,
                            format_timestamp(resumed_at),
                            format_timestamp(
                                resumed_at
                                + timedelta(seconds=self.limits.inactivity_seconds)
                            ),
                            upload_id,
                        ),
                    )
                    if row["commit_phase"] != "none":
                        if replay is None:
                            self._insert_idempotency(
                                connection,
                                owner,
                                row["staging_area_id"],
                                idempotency_key,
                                "commit",
                                request_hash,
                                upload_id,
                                self._now(),
                            )
                        return self._status_for_id(connection, upload_id), False
                    row = self._row_for_id(connection, upload_id)
                if int(row["offset"]) != int(row["byte_length"]):
                    raise MobileUploadError(
                        409,
                        "upload_incomplete",
                        "Upload bytes are incomplete",
                        upload_offset=int(row["offset"]),
                    )
                self._repair_unconfirmed_bytes(connection, row)
                row = self._row_for_id(connection, upload_id)
                if row["state"] == "failed":
                    stable_failure = True
                else:
                    now = self._now()
                    connection.execute(
                        """
                        UPDATE mobile_uploads
                        SET state = 'verifying', commit_phase = 'requested',
                            event_id = COALESCE(event_id, ?), error_json = NULL,
                            last_activity_at = ?, expires_at = ?
                        WHERE upload_id = ?
                        """,
                        (
                            self._event_id(upload_id),
                            format_timestamp(now),
                            format_timestamp(
                                now + timedelta(seconds=self.limits.inactivity_seconds)
                            ),
                            upload_id,
                        ),
                    )
                    if replay is None:
                        self._insert_idempotency(
                            connection,
                            owner,
                            row["staging_area_id"],
                            idempotency_key,
                            "commit",
                            request_hash,
                            upload_id,
                            now,
                        )
                    accepted_status = self._status_for_id(connection, upload_id)
            if stable_failure:
                raise MobileUploadError(
                    409,
                    "upload_failed",
                    "Upload temporary data is unavailable",
                )
            if accepted_status is None:
                raise MobileUploadInvariantError(
                    "Commit request produced no durable status."
                )
            return accepted_status, False

    def cancel(self, upload_id: str, owner: MobileAccessIdentity) -> None:
        """Idempotently cancel non-committed work and release its reservation."""

        canonical_uuid(upload_id, "uploadId")
        with self._upload_lock(upload_id):
            with self._transaction() as connection:
                row = self._owned_row(connection, upload_id, owner)
                if row["state"] == "committed":
                    raise MobileUploadError(
                        409,
                        "upload_already_committed",
                        "Committed media cannot be cancelled",
                    )
                if self._has_valid_lease(row, self._now()):
                    raise MobileUploadError(
                        409,
                        "upload_busy",
                        "Upload processing is currently active",
                        retryable=True,
                        retry_after_seconds=self.limits.lease_seconds,
                    )
                if row["commit_phase"] not in {
                    "none",
                    *PREPUBLICATION_PHASES,
                    "compensated",
                }:
                    raise MobileUploadError(
                        409,
                        "upload_commit_uncertain",
                        "Upload publication must be recovered before cancellation",
                        retryable=True,
                    )
                path = self._temp_path(row)
                self._remove_upload_directory(path.parent)
                connection.execute(
                    """
                    UPDATE mobile_uploads
                    SET state = 'cancelled', reserved_bytes = 0,
                        cleanup_pending = 0, lease_owner = NULL,
                        lease_expires_at = NULL
                    WHERE upload_id = ? AND state != 'committed'
                    """,
                    (upload_id,),
                )

    @contextmanager
    def upload_operation_lock(self, upload_id: str) -> Iterator[None]:
        """Serialize upload-owned file effects with requests and other workers."""

        canonical_uuid(upload_id, "uploadId")
        with self._upload_lock(upload_id):
            yield

    def claim_next_processing(self, worker_id: str) -> MobileProcessingClaim | None:
        """Atomically lease one recoverable commit while enforcing the global cap."""

        canonical_uuid(worker_id, "workerId")
        now = self._now()
        with self._transaction() as connection:
            active = connection.execute(
                """
                SELECT COUNT(*) FROM mobile_uploads
                WHERE state IN ('verifying', 'processing', 'committing')
                  AND storage_path IS NOT NULL AND event_id IS NOT NULL
                  AND lease_owner IS NOT NULL AND lease_expires_at > ?
                """,
                (format_timestamp(now),),
            ).fetchone()[0]
            if int(active) >= self.limits.max_processing_jobs:
                return None
            row = connection.execute(
                """
                SELECT * FROM mobile_uploads
                WHERE state IN ('verifying', 'processing', 'committing')
                  AND storage_path IS NOT NULL AND event_id IS NOT NULL
                  AND (lease_owner IS NULL OR lease_expires_at <= ?)
                ORDER BY last_activity_at, created_at, upload_id
                LIMIT 1
                """,
                (format_timestamp(now),),
            ).fetchone()
            if row is None:
                return None
            target_state = self._state_for_phase(row["commit_phase"])
            changed = connection.execute(
                """
                UPDATE mobile_uploads
                SET state = ?, lease_owner = ?, lease_expires_at = ?,
                    last_activity_at = ?
                WHERE upload_id = ?
                  AND (lease_owner IS NULL OR lease_expires_at <= ?)
                """,
                (
                    target_state,
                    worker_id,
                    format_timestamp(
                        now + timedelta(seconds=self.limits.lease_seconds)
                    ),
                    format_timestamp(now),
                    row["upload_id"],
                    format_timestamp(now),
                ),
            ).rowcount
            if changed != 1:
                return None
            return self._processing_claim(
                self._row_for_id(connection, row["upload_id"]), worker_id
            )

    def renew_processing_lease(self, upload_id: str, worker_id: str) -> None:
        """Extend only the caller's still-valid processing lease."""

        now = self._now()
        with self._transaction() as connection:
            changed = connection.execute(
                """
                UPDATE mobile_uploads
                SET lease_expires_at = ?
                WHERE upload_id = ? AND lease_owner = ? AND lease_expires_at > ?
                  AND state IN ('verifying', 'processing', 'committing')
                """,
                (
                    format_timestamp(
                        now + timedelta(seconds=self.limits.lease_seconds)
                    ),
                    upload_id,
                    worker_id,
                    format_timestamp(now),
                ),
            ).rowcount
            if changed != 1:
                raise MobileUploadInvariantError("Mobile processing lease was lost.")

    def renew_cleanup_lease(self, upload_id: str, worker_id: str) -> None:
        """Extend only the caller's still-valid cleanup lease."""

        now = self._now()
        with self._transaction() as connection:
            changed = connection.execute(
                """
                UPDATE mobile_uploads SET lease_expires_at = ?
                WHERE upload_id = ? AND lease_owner = ? AND lease_expires_at > ?
                  AND cleanup_pending = 1
                """,
                (
                    format_timestamp(
                        now + timedelta(seconds=self.limits.lease_seconds)
                    ),
                    upload_id,
                    worker_id,
                    format_timestamp(now),
                ),
            ).rowcount
            if changed != 1:
                raise MobileUploadInvariantError("Mobile cleanup lease was lost.")

    def record_checksum_verified(
        self, claim: MobileProcessingClaim, checksum: str
    ) -> MobileProcessingClaim:
        """Persist exact byte verification before any rendition work."""

        if checksum != claim.checksum:
            raise MobileUploadInvariantError("Worker checksum differs from its claim.")
        return self._advance_phase(
            claim,
            expected="requested",
            target="checksum_verified",
            state="processing",
            assignments={"verified_checksum": checksum},
        )

    def record_derivatives_ready(
        self, claim: MobileProcessingClaim
    ) -> MobileProcessingClaim:
        """Persist that the complete upload-owned work asset is durable."""

        return self._advance_phase(
            claim,
            expected="checksum_verified",
            target="derivatives_ready",
            state="processing",
        )

    def record_files_published(
        self, claim: MobileProcessingClaim, publication: Mapping[str, Any]
    ) -> MobileProcessingClaim:
        """Persist closed final-file evidence before contacting OLDAP."""

        self._assert_publication(claim, publication)
        return self._advance_phase(
            claim,
            expected="derivatives_ready",
            target="files_published",
            state="committing",
            assignments={"publication_json": self._closed_json(publication)},
        )

    def record_oldap_committed(
        self, claim: MobileProcessingClaim, result: Mapping[str, Any]
    ) -> MobileProcessingClaim:
        """Persist the exact OLDAP receipt before exposing local completion."""

        self._assert_oldap_result(claim, result)
        return self._advance_phase(
            claim,
            expected="files_published",
            target="oldap_committed",
            state="committing",
            assignments={"oldap_result_json": self._closed_json(result)},
        )

    def record_compensation_required(
        self, claim: MobileProcessingClaim, code: str
    ) -> MobileProcessingClaim:
        """Durably prevent another OLDAP call before deleting rejected files."""

        problem = self._failure_problem(claim, code, retryable=False)
        return self._advance_phase(
            claim,
            expected="files_published",
            target="compensating",
            state="committing",
            assignments={"error_json": self._closed_json(problem)},
        )

    def complete_compensation(self, claim: MobileProcessingClaim) -> None:
        """Finalize a durable compensation after the exact final path is absent."""

        with self._transaction() as connection:
            row = self._leased_row(connection, claim)
            if row["commit_phase"] != "compensating" or not row["error_json"]:
                raise MobileUploadInvariantError(
                    "Mobile compensation phase is invalid."
                )
            changed = connection.execute(
                """
                UPDATE mobile_uploads
                SET state = 'failed', commit_phase = 'compensated', cleanup_pending = 1,
                    lease_owner = NULL, lease_expires_at = NULL
                WHERE upload_id = ? AND lease_owner = ? AND commit_phase = 'compensating'
                """,
                (claim.upload_id, claim.lease_owner),
            ).rowcount
            if changed != 1:
                raise MobileUploadInvariantError(
                    "Mobile compensation was not finalized."
                )

    def complete_commit(self, claim: MobileProcessingClaim) -> None:
        """Atomically publish the permanent receipt to upload and asset records."""

        with self._transaction() as connection:
            row = self._leased_row(connection, claim)
            if row["commit_phase"] != "oldap_committed":
                raise MobileUploadInvariantError("OLDAP receipt phase is not durable.")
            result = self._json_object(row["oldap_result_json"], "OLDAP result")
            if (
                result.get("uploadId") != row["upload_id"]
                or result.get("clientAssetId") != row["client_asset_id"]
                or result.get("stagingAreaId") != row["staging_area_id"]
                or result.get("checksum") != row["verified_checksum"]
            ):
                raise MobileUploadInvariantError(
                    "OLDAP result differs from the upload."
                )
            committed_at = format_timestamp(parse_timestamp(result["committedAt"]))
            connection.execute(
                """
                UPDATE mobile_uploads
                SET state = 'committed', commit_phase = 'complete', asset_id = ?,
                    resource_iri = ?, committed_at = ?, cleanup_pending = 1,
                    error_json = NULL, lease_owner = NULL, lease_expires_at = NULL
                WHERE upload_id = ? AND lease_owner = ?
                """,
                (
                    result["assetId"],
                    result["resourceIri"],
                    committed_at,
                    claim.upload_id,
                    claim.lease_owner,
                ),
            )
            changed = connection.execute(
                """
                UPDATE mobile_assets
                SET committed_upload_id = ?, committed_asset_id = ?,
                    committed_resource_iri = ?, committed_at = ?
                WHERE client_asset_id = ? AND current_upload_id = ?
                  AND committed_upload_id IS NULL
                """,
                (
                    claim.upload_id,
                    result["assetId"],
                    result["resourceIri"],
                    committed_at,
                    claim.client_asset_id,
                    claim.upload_id,
                ),
            ).rowcount
            if changed != 1:
                raise MobileUploadInvariantError(
                    "Permanent client asset receipt conflicted."
                )

    def fail_processing(
        self,
        claim: MobileProcessingClaim,
        code: str,
        *,
        retryable: bool,
        cleanup_pending: bool = False,
    ) -> None:
        """Record one privacy-safe worker failure without losing recovery evidence."""

        problem = self._failure_problem(claim, code, retryable=retryable)
        with self._transaction() as connection:
            row = self._leased_row(connection, claim)
            now = self._now()
            connection.execute(
                """
                UPDATE mobile_uploads
                SET state = 'failed', commit_phase = ?, error_json = ?,
                    cleanup_pending = ?, lease_owner = NULL, lease_expires_at = NULL,
                    last_activity_at = ?, expires_at = ?
                WHERE upload_id = ? AND lease_owner = ?
                """,
                (
                    row["commit_phase"],
                    self._closed_json(problem),
                    int(cleanup_pending),
                    format_timestamp(now),
                    format_timestamp(
                        now + timedelta(seconds=self.limits.inactivity_seconds)
                    ),
                    claim.upload_id,
                    claim.lease_owner,
                ),
            )

    def claim_next_cleanup(self, worker_id: str) -> MobileCleanupClaim | None:
        """Expire safe transfers and atomically lease one owned-directory cleanup."""

        canonical_uuid(worker_id, "workerId")
        now = self._now()
        with self._transaction() as connection:
            self._expire_inactive(connection, now)
            row = connection.execute(
                """
                SELECT * FROM mobile_uploads
                WHERE cleanup_pending = 1
                  AND (lease_owner IS NULL OR lease_expires_at <= ?)
                ORDER BY last_activity_at, upload_id LIMIT 1
                """,
                (format_timestamp(now),),
            ).fetchone()
            if row is None:
                return None
            changed = connection.execute(
                """
                UPDATE mobile_uploads SET lease_owner = ?, lease_expires_at = ?
                WHERE upload_id = ? AND cleanup_pending = 1
                  AND (lease_owner IS NULL OR lease_expires_at <= ?)
                """,
                (
                    worker_id,
                    format_timestamp(
                        now + timedelta(seconds=self.limits.lease_seconds)
                    ),
                    row["upload_id"],
                    format_timestamp(now),
                ),
            ).rowcount
            if changed != 1:
                return None
            return MobileCleanupClaim(
                upload_id=row["upload_id"],
                lease_owner=worker_id,
                state=row["state"],
                upload_directory=self.uploads_root / row["upload_id"],
            )

    def complete_cleanup(self, claim: MobileCleanupClaim) -> None:
        """Release reservation only after the exact private directory is absent."""

        path = self.uploads_root / claim.upload_id
        if path.exists() or path.is_symlink():
            raise MobileUploadInvariantError("Claimed upload directory still exists.")
        with self._transaction() as connection:
            changed = connection.execute(
                """
                UPDATE mobile_uploads
                SET cleanup_pending = 0, reserved_bytes = 0,
                    lease_owner = NULL, lease_expires_at = NULL
                WHERE upload_id = ? AND lease_owner = ? AND cleanup_pending = 1
                """,
                (claim.upload_id, claim.lease_owner),
            ).rowcount
            if changed != 1:
                raise MobileUploadInvariantError("Mobile cleanup lease was lost.")

    def remove_claimed_upload_directory(self, claim: MobileCleanupClaim) -> None:
        """Delete only the canonical private directory named by a cleanup claim."""

        expected = self.uploads_root / claim.upload_id
        if claim.upload_directory != expected:
            raise MobileUploadInvariantError("Cleanup path is not registry-owned.")
        if expected.is_symlink():
            raise MobileUploadInvariantError("Cleanup path is a symbolic link.")
        self._remove_upload_directory(expected)

    def _initialize_storage(self) -> None:
        self._ensure_private_directory(self.root, parents=True)
        self._ensure_private_directory(self.uploads_root)
        self._ensure_private_directory(self.locks_root)
        if self.database_path.is_symlink():
            raise MobileUploadInvariantError(
                "Mobile upload registry must not be a symbolic link."
            )
        with self._connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, SCHEMA_VERSION):
                raise MobileUploadInvariantError(
                    f"Unsupported mobile upload registry schema version {version}."
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS mobile_assets (
                    client_asset_id TEXT PRIMARY KEY,
                    owner_user_id TEXT NOT NULL,
                    owner_user_iri TEXT NOT NULL,
                    staging_area_id TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    current_upload_id TEXT,
                    created_at TEXT NOT NULL,
                    committed_upload_id TEXT,
                    committed_asset_id TEXT,
                    committed_resource_iri TEXT,
                    committed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS mobile_uploads (
                    upload_id TEXT PRIMARY KEY,
                    client_asset_id TEXT NOT NULL REFERENCES mobile_assets(client_asset_id),
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    owner_user_id TEXT NOT NULL,
                    owner_user_iri TEXT NOT NULL,
                    staging_area_id TEXT NOT NULL,
                    mobile_folder_id TEXT NOT NULL,
                    default_role_id TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    original_mime_type TEXT NOT NULL,
                    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
                    checksum TEXT NOT NULL,
                    comment TEXT,
                    state TEXT NOT NULL CHECK (
                        state IN ('initialized', 'uploading', 'verifying', 'processing',
                                  'committing', 'committed', 'cancelled', 'failed', 'expired')
                    ),
                    offset INTEGER NOT NULL CHECK (offset >= 0 AND offset <= byte_length),
                    chunk_size INTEGER NOT NULL CHECK (chunk_size > 0),
                    created_at TEXT NOT NULL,
                    last_activity_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
                    temp_path TEXT NOT NULL,
                    verified_checksum TEXT,
                    error_json TEXT,
                    commit_phase TEXT NOT NULL,
                    event_id TEXT,
                    publication_json TEXT,
                    oldap_result_json TEXT,
                    cleanup_pending INTEGER NOT NULL DEFAULT 0
                        CHECK (cleanup_pending IN (0, 1)),
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    asset_id TEXT,
                    resource_iri TEXT,
                    committed_at TEXT,
                    UNIQUE (client_asset_id, generation)
                );

                CREATE TABLE IF NOT EXISTS mobile_idempotency (
                    owner_user_id TEXT NOT NULL,
                    owner_user_iri TEXT NOT NULL,
                    staging_area_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    upload_id TEXT NOT NULL REFERENCES mobile_uploads(upload_id),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (owner_user_iri, staging_area_id, idempotency_key)
                );

                CREATE INDEX IF NOT EXISTS mobile_upload_owner_state
                    ON mobile_uploads(owner_user_iri, state);
                CREATE INDEX IF NOT EXISTS mobile_upload_area_state
                    ON mobile_uploads(staging_area_id, state);
                CREATE INDEX IF NOT EXISTS mobile_upload_expiry
                    ON mobile_uploads(state, expires_at);
                """
            )
            if version == 1:
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(mobile_uploads)"
                    ).fetchall()
                }
                migrations = {
                    "storage_path": "ALTER TABLE mobile_uploads ADD COLUMN storage_path TEXT",
                    "event_id": "ALTER TABLE mobile_uploads ADD COLUMN event_id TEXT",
                    "publication_json": "ALTER TABLE mobile_uploads ADD COLUMN publication_json TEXT",
                    "oldap_result_json": "ALTER TABLE mobile_uploads ADD COLUMN oldap_result_json TEXT",
                    "cleanup_pending": (
                        "ALTER TABLE mobile_uploads ADD COLUMN cleanup_pending INTEGER "
                        "NOT NULL DEFAULT 0 CHECK (cleanup_pending IN (0, 1))"
                    ),
                }
                for column, statement in migrations.items():
                    if column not in columns:
                        connection.execute(statement)
                migrated = connection.execute(
                    """
                    SELECT upload_id, state, commit_phase, storage_path, event_id
                    FROM mobile_uploads
                    WHERE commit_phase != 'none'
                    """
                ).fetchall()
                for row in migrated:
                    event_id = row["event_id"] or self._event_id(row["upload_id"])
                    connection.execute(
                        "UPDATE mobile_uploads SET event_id = ? WHERE upload_id = ?",
                        (event_id, row["upload_id"]),
                    )
                    if (
                        row["state"] in {"verifying", "processing", "committing"}
                        and row["storage_path"] is None
                    ):
                        problem = {
                            "type": (
                                "https://oldap.org/problems/mobile/"
                                "processing-context-refresh-required"
                            ),
                            "title": "Mobile media processing must be resumed",
                            "status": 503,
                            "code": "processing_context_refresh_required",
                            "traceId": event_id,
                            "retryable": True,
                        }
                        connection.execute(
                            """
                            UPDATE mobile_uploads
                            SET state = 'failed', error_json = ?, lease_owner = NULL,
                                lease_expires_at = NULL
                            WHERE upload_id = ?
                            """,
                            (self._closed_json(problem), row["upload_id"]),
                        )
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS mobile_upload_worker_queue
                    ON mobile_uploads(state, commit_phase, lease_expires_at);
                CREATE INDEX IF NOT EXISTS mobile_upload_cleanup_queue
                    ON mobile_uploads(cleanup_pending, lease_expires_at);
                """
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.commit()
        if not stat.S_ISREG(self.database_path.lstat().st_mode):
            raise MobileUploadInvariantError(
                "Mobile upload registry must be a regular file."
            )
        os.chmod(self.database_path, 0o600)

    @staticmethod
    def _ensure_private_directory(path: Path, *, parents: bool = False) -> None:
        """Create one managed directory and reject replacement filesystem types."""

        path.mkdir(parents=parents, exist_ok=True, mode=0o700)
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise MobileUploadInvariantError(
                "Mobile upload storage entry must be a real directory."
            )
        os.chmod(path, 0o700)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _upload_lock(self, upload_id: str) -> Iterator[None]:
        lock_path = self.locks_root / f"{upload_id}.lock"
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            self._assert_regular_descriptor(descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _owned_row(
        self,
        connection: sqlite3.Connection,
        upload_id: str,
        owner: MobileAccessIdentity,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM mobile_uploads
            WHERE upload_id = ? AND owner_user_iri = ?
            """,
            (upload_id, owner.user_iri),
        ).fetchone()
        if row is None:
            raise MobileUploadError(404, "upload_not_found", "Upload was not found")
        return row

    def _row_for_id(
        self, connection: sqlite3.Connection, upload_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM mobile_uploads WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        if row is None:
            raise MobileUploadInvariantError("Referenced upload row is missing.")
        return row

    def _status_for_id(
        self, connection: sqlite3.Connection, upload_id: str
    ) -> UploadStatus:
        return self._status(self._row_for_id(connection, upload_id))

    def _status(self, row: sqlite3.Row) -> UploadStatus:
        return UploadStatus(
            upload_id=row["upload_id"],
            client_asset_id=row["client_asset_id"],
            staging_area_id=row["staging_area_id"],
            state=row["state"],
            offset=int(row["offset"]),
            byte_length=int(row["byte_length"]),
            chunk_size=int(row["chunk_size"]),
            last_activity_at=parse_timestamp(row["last_activity_at"]),
            expires_at=parse_timestamp(row["expires_at"]),
            declared_checksum=row["checksum"],
            verified_checksum=row["verified_checksum"],
            asset_id=row["asset_id"],
            resource_iri=row["resource_iri"],
            error=self._stored_error(row),
            committed_at=(
                parse_timestamp(row["committed_at"]) if row["committed_at"] else None
            ),
        )

    def _stored_error(self, row: sqlite3.Row) -> dict[str, object] | None:
        if not row["error_json"]:
            return None
        value = json.loads(row["error_json"])
        if not isinstance(value, dict):
            raise MobileUploadInvariantError("Stored upload error is invalid.")
        return value

    def _processing_claim(
        self, row: sqlite3.Row, worker_id: str
    ) -> MobileProcessingClaim:
        if (
            row["lease_owner"] != worker_id
            or not row["event_id"]
            or not row["storage_path"]
        ):
            raise MobileUploadInvariantError("Claimed mobile upload is incomplete.")
        return MobileProcessingClaim(
            upload_id=row["upload_id"],
            lease_owner=worker_id,
            event_id=row["event_id"],
            client_asset_id=row["client_asset_id"],
            owner_user_iri=row["owner_user_iri"],
            staging_area_id=row["staging_area_id"],
            original_name=row["original_name"],
            original_mime_type=row["original_mime_type"],
            byte_length=int(row["byte_length"]),
            checksum=row["checksum"],
            comment=row["comment"],
            storage_path=row["storage_path"],
            upload_directory=self.uploads_root / row["upload_id"],
            commit_phase=row["commit_phase"],
            publication=(
                self._json_object(row["publication_json"], "publication")
                if row["publication_json"]
                else None
            ),
            oldap_result=(
                self._json_object(row["oldap_result_json"], "OLDAP result")
                if row["oldap_result_json"]
                else None
            ),
        )

    def _advance_phase(
        self,
        claim: MobileProcessingClaim,
        *,
        expected: str,
        target: str,
        state: str,
        assignments: Mapping[str, Any] | None = None,
    ) -> MobileProcessingClaim:
        allowed_columns = {
            "verified_checksum",
            "publication_json",
            "oldap_result_json",
            "error_json",
        }
        values = dict(assignments or {})
        if not set(values) <= allowed_columns:
            raise ValueError("Unsupported mobile phase assignment.")
        with self._transaction() as connection:
            row = self._leased_row(connection, claim)
            if row["commit_phase"] != expected:
                raise MobileUploadInvariantError(
                    "Mobile commit phase changed unexpectedly."
                )
            now = self._now()
            set_parts = [
                "state = ?",
                "commit_phase = ?",
                "last_activity_at = ?",
                "expires_at = ?",
            ]
            parameters: list[Any] = [
                state,
                target,
                format_timestamp(now),
                format_timestamp(
                    now + timedelta(seconds=self.limits.inactivity_seconds)
                ),
            ]
            for column, value in values.items():
                set_parts.append(f"{column} = ?")
                parameters.append(value)
            parameters.extend([claim.upload_id, claim.lease_owner, expected])
            changed = connection.execute(
                f"""
                UPDATE mobile_uploads SET {', '.join(set_parts)}
                WHERE upload_id = ? AND lease_owner = ? AND commit_phase = ?
                """,
                tuple(parameters),
            ).rowcount
            if changed != 1:
                raise MobileUploadInvariantError(
                    "Mobile phase compare-and-swap failed."
                )
            return self._processing_claim(
                self._row_for_id(connection, claim.upload_id), claim.lease_owner
            )

    def _leased_row(
        self, connection: sqlite3.Connection, claim: MobileProcessingClaim
    ) -> sqlite3.Row:
        row = self._row_for_id(connection, claim.upload_id)
        if (
            row["lease_owner"] != claim.lease_owner
            or not row["lease_expires_at"]
            or parse_timestamp(row["lease_expires_at"]) <= self._now()
        ):
            raise MobileUploadInvariantError("Mobile processing lease was lost.")
        return row

    @staticmethod
    def _closed_json(value: Mapping[str, Any]) -> str:
        return json.dumps(
            dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )

    @staticmethod
    def _json_object(value: str, label: str) -> dict[str, Any]:
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise MobileUploadInvariantError(f"Stored {label} is invalid.")
        return parsed

    @staticmethod
    def _failure_problem(
        claim: MobileProcessingClaim, code: str, *, retryable: bool
    ) -> dict[str, Any]:
        return {
            "type": f"https://oldap.org/problems/mobile/{code.replace('_', '-')}",
            "title": "Mobile media processing failed",
            "status": 503 if retryable else 422,
            "code": code,
            "traceId": claim.event_id,
            "retryable": retryable,
        }

    @staticmethod
    def _assert_publication(
        claim: MobileProcessingClaim, value: Mapping[str, Any]
    ) -> None:
        required = {
            "ownerUploadId",
            "assetId",
            "byteLength",
            "checksum",
            "derivativeNames",
            "storagePath",
        }
        if set(value) != required or (
            value.get("ownerUploadId") != claim.upload_id
            or value.get("assetId") != claim.client_asset_id
            or value.get("byteLength") != claim.byte_length
            or value.get("checksum") != claim.checksum
            or value.get("derivativeNames") != ["master.tif"]
            or value.get("storagePath") != claim.storage_path
        ):
            raise MobileUploadInvariantError(
                "Publication evidence differs from its claim."
            )

    @staticmethod
    def _assert_oldap_result(
        claim: MobileProcessingClaim, value: Mapping[str, Any]
    ) -> None:
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
        if set(value) != required or (
            value.get("eventId") != claim.event_id
            or value.get("uploadId") != claim.upload_id
            or value.get("clientAssetId") != claim.client_asset_id
            or value.get("stagingAreaId") != claim.staging_area_id
            or value.get("assetId") != claim.client_asset_id
            or value.get("checksum") != claim.checksum
            or not isinstance(value.get("resourceIri"), str)
        ):
            raise MobileUploadInvariantError("OLDAP result differs from its claim.")
        try:
            parse_timestamp(value["committedAt"])
        except (TypeError, ValueError) as error:
            raise MobileUploadInvariantError(
                "OLDAP result timestamp is invalid."
            ) from error

    def _expire_inactive(self, connection: sqlite3.Connection, now: datetime) -> None:
        rows = connection.execute(
            """
            SELECT * FROM mobile_uploads
            WHERE state IN ('initialized', 'uploading', 'failed') AND expires_at <= ?
            """,
            (format_timestamp(now),),
        ).fetchall()
        for row in rows:
            if self._is_safe_to_expire(row, now):
                connection.execute(
                    """
                    UPDATE mobile_uploads
                    SET state = 'expired', cleanup_pending = 1,
                        lease_owner = NULL, lease_expires_at = NULL
                    WHERE upload_id = ?
                    """,
                    (row["upload_id"],),
                )

    def _expire_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row, now: datetime
    ) -> sqlite3.Row:
        if parse_timestamp(row["expires_at"]) <= now and self._is_safe_to_expire(
            row, now
        ):
            connection.execute(
                "UPDATE mobile_uploads SET state = 'expired' WHERE upload_id = ?",
                (row["upload_id"],),
            )
            connection.execute(
                "UPDATE mobile_uploads SET cleanup_pending = 1 WHERE upload_id = ?",
                (row["upload_id"],),
            )
            return self._row_for_id(connection, row["upload_id"])
        return row

    def _is_safe_to_expire(self, row: sqlite3.Row, now: datetime) -> bool:
        """Return whether expiry can remove only unambiguous private work."""

        if self._has_valid_lease(row, now):
            return False
        if row["state"] in TRANSFER_STATES:
            return True
        return (
            row["state"] == "failed"
            and row["commit_phase"] in PREPUBLICATION_PHASES
            and (error := self._stored_error(row)) is not None
            and error.get("retryable") is True
        )

    def _require_logical_capacity(
        self,
        connection: sqlite3.Connection,
        owner: MobileAccessIdentity,
        staging_area_id: str,
        requested_bytes: int,
    ) -> None:
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        user_active = connection.execute(
            f"""
            SELECT COUNT(*) AS active
            FROM mobile_uploads
            WHERE owner_user_iri = ? AND state IN ({placeholders})
            """,
            (owner.user_iri, *ACTIVE_STATES),
        ).fetchone()
        area_active = connection.execute(
            f"""
            SELECT COUNT(*) AS active
            FROM mobile_uploads
            WHERE staging_area_id = ? AND state IN ({placeholders})
            """,
            (staging_area_id, *ACTIVE_STATES),
        ).fetchone()
        user_reserved = connection.execute(
            "SELECT COALESCE(SUM(reserved_bytes), 0) AS reserved "
            "FROM mobile_uploads WHERE owner_user_iri = ?",
            (owner.user_iri,),
        ).fetchone()
        area_reserved = connection.execute(
            "SELECT COALESCE(SUM(reserved_bytes), 0) AS reserved "
            "FROM mobile_uploads WHERE staging_area_id = ?",
            (staging_area_id,),
        ).fetchone()
        if int(user_active["active"]) >= self.limits.max_active_per_user:
            raise MobileUploadError(
                429,
                "user_upload_limit",
                "Too many active uploads for this account",
                retryable=True,
            )
        if int(area_active["active"]) >= self.limits.max_active_per_staging_area:
            raise MobileUploadError(
                429,
                "staging_area_upload_limit",
                "Too many active uploads for this StagingArea",
                retryable=True,
            )
        if (
            int(user_reserved["reserved"]) + requested_bytes
            > self.limits.max_reserved_bytes_per_user
        ):
            raise MobileUploadError(
                429,
                "user_reservation_limit",
                "Temporary upload reservation limit reached for this account",
                retryable=True,
            )
        if (
            int(area_reserved["reserved"]) + requested_bytes
            > self.limits.max_reserved_bytes_per_staging_area
        ):
            raise MobileUploadError(
                429,
                "staging_area_reservation_limit",
                "Temporary upload reservation limit reached for this StagingArea",
                retryable=True,
            )

    def _require_physical_capacity(self, additional_bytes: int) -> None:
        if self.capacity_guard is None:
            return
        try:
            self.capacity_guard.require(self.root, additional_bytes=additional_bytes)
        except PhysicalCapacityInsufficient as error:
            raise MobileUploadError(
                507,
                "physical_capacity_insufficient",
                "Insufficient temporary storage capacity",
                retryable=True,
            ) from error

    def _create_upload_file(self, upload_directory: Path) -> None:
        """Durably create one private, empty upload before its registry row."""

        upload_directory.mkdir(mode=0o700)
        try:
            self._fsync_directory(self.uploads_root)
            path = upload_directory / "original.part"
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            try:
                self._assert_regular_descriptor(descriptor)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._fsync_directory(upload_directory)
        except Exception:
            shutil.rmtree(upload_directory, ignore_errors=True)
            raise

    def _remove_upload_directory(self, upload_directory: Path) -> None:
        """Remove one upload-owned directory before releasing its reservation."""

        try:
            shutil.rmtree(upload_directory)
        except FileNotFoundError:
            pass
        self._fsync_directory(self.uploads_root)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _temp_path(self, row: sqlite3.Row) -> Path:
        expected_relative = f"uploads/{row['upload_id']}/original.part"
        if row["temp_path"] != expected_relative:
            raise MobileUploadInvariantError(
                "Stored temporary path is not upload-owned."
            )
        return self.uploads_root / row["upload_id"] / "original.part"

    def _repair_unconfirmed_bytes(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> None:
        if row["state"] in {"committed", "cancelled", "failed", "expired"}:
            return
        path = self._temp_path(row)
        expected = int(row["offset"])
        try:
            actual = self._regular_file_size(path)
        except FileNotFoundError:
            actual = -1
        if actual < 0 or actual < expected:
            problem = {
                "type": "https://oldap.org/problems/mobile/upload-data-missing",
                "title": "Temporary upload data is missing",
                "status": 500,
                "code": "upload_data_missing",
                "traceId": "retained",
                "retryable": False,
            }
            connection.execute(
                """
                UPDATE mobile_uploads
                SET state = 'failed', error_json = ?
                WHERE upload_id = ?
                """,
                (
                    json.dumps(problem, separators=(",", ":"), sort_keys=True),
                    row["upload_id"],
                ),
            )
            return
        if actual > expected:
            self._truncate_file(path, expected)

    @staticmethod
    def _append_bytes(path: Path, offset: int, chunk: bytes) -> None:
        flags = os.O_WRONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            MobileUploadRegistry._assert_regular_descriptor(descriptor)
            if os.lseek(descriptor, 0, os.SEEK_END) != offset:
                raise MobileUploadInvariantError(
                    "Temporary file offset changed outside the upload lock."
                )
            view = memoryview(chunk)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("Could not append upload chunk.")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _truncate_file(path: Path, offset: int) -> None:
        flags = os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return
        try:
            MobileUploadRegistry._assert_regular_descriptor(descriptor)
            os.ftruncate(descriptor, offset)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _regular_file_size(path: Path) -> int:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            MobileUploadRegistry._assert_regular_descriptor(descriptor)
            return int(os.fstat(descriptor).st_size)
        finally:
            os.close(descriptor)

    @staticmethod
    def _assert_regular_descriptor(descriptor: int) -> None:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MobileUploadInvariantError(
                "Mobile upload storage entry is not a regular file."
            )

    def _idempotency_replay(
        self,
        connection: sqlite3.Connection,
        owner: MobileAccessIdentity,
        staging_area_id: str,
        key: str,
        operation: str,
        request_hash: str,
        *,
        expected_upload_id: str | None = None,
    ) -> str | None:
        row = connection.execute(
            """
            SELECT * FROM mobile_idempotency
            WHERE owner_user_iri = ? AND staging_area_id = ? AND idempotency_key = ?
            """,
            (owner.user_iri, staging_area_id, key),
        ).fetchone()
        if row is None:
            return None
        if (
            row["operation"] != operation
            or row["request_hash"] != request_hash
            or (
                expected_upload_id is not None
                and row["upload_id"] != expected_upload_id
            )
        ):
            raise MobileUploadError(
                409,
                "idempotency_conflict",
                "Idempotency key was reused with another request",
            )
        return str(row["upload_id"])

    @staticmethod
    def _insert_idempotency(
        connection: sqlite3.Connection,
        owner: MobileAccessIdentity,
        staging_area_id: str,
        key: str,
        operation: str,
        request_hash: str,
        upload_id: str,
        now: datetime,
    ) -> None:
        connection.execute(
            """
            INSERT INTO mobile_idempotency (
                owner_user_id, owner_user_iri, staging_area_id, idempotency_key,
                operation, request_hash, upload_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner.user_id,
                owner.user_iri,
                staging_area_id,
                key,
                operation,
                request_hash,
                upload_id,
                format_timestamp(now),
            ),
        )

    @staticmethod
    def _assert_same_asset_request(row: sqlite3.Row, request: InitializeUpload) -> None:
        if (
            row["original_name"] != request.original_name
            or row["original_mime_type"] != request.original_mime_type
            or int(row["byte_length"]) != request.byte_length
            or row["checksum"] != request.checksum
            or row["comment"] != request.comment
        ):
            raise MobileUploadRegistry._asset_conflict()

    @staticmethod
    def _assert_same_commit_request(row: sqlite3.Row, request: CommitUpload) -> None:
        if (
            row["client_asset_id"] != request.client_asset_id
            or int(row["byte_length"]) != request.byte_length
            or row["checksum"] != request.checksum
        ):
            raise MobileUploadError(
                409,
                "commit_request_mismatch",
                "Commit request does not match the initialized upload",
            )

    @staticmethod
    def _assert_destination(row: sqlite3.Row, destination: ResolvedMobileInbox) -> None:
        if (
            row["staging_area_id"] != destination.staging_area_id
            or row["mobile_folder_id"] != destination.mobile_folder_id
            or row["default_role_id"] != destination.default_role_id
            or (
                row["storage_path"] is not None
                and row["storage_path"] != destination.storage_path
            )
        ):
            raise MobileUploadError(
                409,
                "destination_changed",
                "The protected mobile destination changed",
            )

    @staticmethod
    def _asset_conflict() -> MobileUploadError:
        return MobileUploadError(
            409,
            "client_asset_conflict",
            "Client asset identity is unavailable",
        )

    @staticmethod
    def _has_valid_lease(row: sqlite3.Row, now: datetime) -> bool:
        return bool(
            row["lease_owner"]
            and row["lease_expires_at"]
            and parse_timestamp(row["lease_expires_at"]) > now
        )

    @staticmethod
    def _state_for_phase(phase: str) -> str:
        if phase == "requested":
            return "verifying"
        if phase in {"checksum_verified", "derivatives_ready"}:
            return "processing"
        if phase in {"files_published", "oldap_committed", "compensating"}:
            return "committing"
        raise MobileUploadInvariantError(f"Unsupported mobile commit phase {phase!r}.")

    @staticmethod
    def _event_id(upload_id: str) -> str:
        return str(uuid5(UUID(upload_id), "mobile-media-commit"))

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Mobile upload clock must return a timezone-aware value.")
        return value.astimezone(UTC)
