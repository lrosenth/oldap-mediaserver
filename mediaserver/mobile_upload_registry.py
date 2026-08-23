"""Durable SQLite registry and private byte store for mobile upload v1."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import sqlite3
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable, Iterator
from uuid import uuid4

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
SCHEMA_VERSION = 1


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
                        staging_area_id, mobile_folder_id, default_role_id,
                        original_name, original_mime_type, byte_length, checksum,
                        comment, state, offset, chunk_size, created_at,
                        last_activity_at, expires_at, reserved_bytes, temp_path,
                        commit_phase
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'initialized',
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
                    connection.execute(
                        """
                        UPDATE mobile_uploads
                        SET state = 'uploading', error_json = NULL,
                            lease_owner = NULL, lease_expires_at = NULL
                        WHERE upload_id = ?
                        """,
                        (upload_id,),
                    )
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
                            error_json = NULL, last_activity_at = ?, expires_at = ?
                        WHERE upload_id = ?
                        """,
                        (
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
                path = self._temp_path(row)
                self._remove_upload_directory(path.parent)
                connection.execute(
                    """
                    UPDATE mobile_uploads
                    SET state = 'cancelled', reserved_bytes = 0,
                        lease_owner = NULL, lease_expires_at = NULL
                    WHERE upload_id = ? AND state != 'committed'
                    """,
                    (upload_id,),
                )

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
            if version not in (0, SCHEMA_VERSION):
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

    def _expire_inactive(self, connection: sqlite3.Connection, now: datetime) -> None:
        connection.execute(
            """
            UPDATE mobile_uploads
            SET state = 'expired'
            WHERE state IN ('initialized', 'uploading') AND expires_at <= ?
            """,
            (format_timestamp(now),),
        )

    def _expire_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row, now: datetime
    ) -> sqlite3.Row:
        if (
            row["state"] in TRANSFER_STATES
            and parse_timestamp(row["expires_at"]) <= now
        ):
            connection.execute(
                "UPDATE mobile_uploads SET state = 'expired' WHERE upload_id = ?",
                (row["upload_id"],),
            )
            return self._row_for_id(connection, row["upload_id"])
        return row

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
        if row["state"] in {"cancelled", "expired"}:
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

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Mobile upload clock must return a timezone-aware value.")
        return value.astimezone(UTC)
