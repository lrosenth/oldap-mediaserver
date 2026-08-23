"""Protocol-level persistence, race, expiry, and capacity tests for mobile uploads."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid5

import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from config import MobileUploadLimits  # noqa: E402
import mobile_upload_registry as registry_module  # noqa: E402
from mobile_upload_domain import (  # noqa: E402
    CommitUpload,
    InitializeUpload,
    MobileAccessIdentity,
    MobileUploadError,
    MobileUploadInvariantError,
    ResolvedMobileInbox,
    canonical_request_hash,
    parse_initialize_upload,
)
from mobile_upload_registry import MobileUploadRegistry  # noqa: E402
from storage_capacity import DiskUsage, StorageCapacityGuard  # noqa: E402


OWNER = MobileAccessIdentity("alice", "https://oldap.org/users/alice")
OTHER_OWNER = MobileAccessIdentity("bob", "https://oldap.org/users/bob")
AREA = "urn:uuid:11111111-1111-4111-8111-111111111111"
OTHER_AREA = "urn:uuid:22222222-2222-4222-8222-222222222222"
ASSET = "33333333-3333-4333-8333-333333333333"
INIT_KEY = "44444444-4444-4444-8444-444444444444"
COMMIT_KEY = "55555555-5555-4555-8555-555555555555"
NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


def limits(**changes: int) -> MobileUploadLimits:
    values = {
        "max_original_bytes": 100,
        "chunk_bytes": 4,
        "inactivity_seconds": 60,
        "lease_seconds": 30,
        "max_active_per_user": 20,
        "max_active_per_staging_area": 100,
        "max_reserved_bytes_per_user": 200,
        "max_reserved_bytes_per_staging_area": 1000,
        "max_processing_jobs": 2,
    }
    values.update(changes)
    return MobileUploadLimits(**values)


def initialize_request(**changes: object) -> InitializeUpload:
    values: dict[str, object] = {
        "client_asset_id": ASSET,
        "staging_area_id": AREA,
        "original_name": "photo.jpg",
        "original_mime_type": "image/jpeg",
        "byte_length": 8,
        "checksum": "sha256:" + "a" * 64,
        "comment": "Keller",
    }
    values.update(changes)
    return InitializeUpload(**values)  # type: ignore[arg-type]


def destination(area: str = AREA) -> ResolvedMobileInbox:
    return ResolvedMobileInbox(
        staging_area_id=area,
        mobile_folder_id="urn:uuid:66666666-6666-4666-8666-666666666666",
        default_role_id="urn:uuid:77777777-7777-4777-8777-777777777777",
        storage_path="fasnacht/image/bmg",
    )


def changed_destination() -> ResolvedMobileInbox:
    return ResolvedMobileInbox(
        staging_area_id=AREA,
        mobile_folder_id="urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        default_role_id="urn:uuid:77777777-7777-4777-8777-777777777777",
        storage_path="fasnacht/image/bmg",
    )


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def registry(tmp_path: Path, clock: Clock) -> MobileUploadRegistry:
    return MobileUploadRegistry(tmp_path / "mobile", limits(), clock=clock)


def test_request_validation_and_rfc8785_hash_are_closed_and_stable() -> None:
    body = {
        "clientAssetId": ASSET,
        "stagingAreaId": AREA,
        "originalName": "Fasnacht.jpg",
        "originalMimeType": "image/jpeg",
        "byteLength": 8,
        "checksum": "sha256:" + "a" * 64,
    }
    parsed = parse_initialize_upload(body, max_original_bytes=100)
    reordered = dict(reversed(list(body.items())))

    assert canonical_request_hash(parsed.canonical_payload()) == canonical_request_hash(
        parse_initialize_upload(reordered, max_original_bytes=100).canonical_payload()
    )
    with pytest.raises(MobileUploadError) as unexpected:
        parse_initialize_upload(
            {**body, "folderId": "forbidden"}, max_original_bytes=100
        )
    with pytest.raises(MobileUploadError) as path:
        parse_initialize_upload(
            {**body, "originalName": "../photo.jpg"}, max_original_bytes=100
        )
    assert unexpected.value.code == "invalid_request"
    assert path.value.code == "invalid_request"


def test_initialization_is_exactly_replayable_and_persistent(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    first, created = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    replay, replay_created = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    reconciled, reconciled_created = registry.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "88888888-8888-4888-8888-888888888888",
    )
    restarted = MobileUploadRegistry(registry.root, limits(), clock=clock)

    assert created is True
    assert replay_created is False
    assert reconciled_created is False
    assert replay == first == reconciled
    assert restarted.get_status(first.upload_id, OWNER) == first


def test_simultaneous_initialization_creates_one_generation(
    registry: MobileUploadRegistry,
) -> None:
    def create() -> tuple[str, bool]:
        status, created = registry.initialize(
            OWNER, initialize_request(), destination(), INIT_KEY
        )
        return status.upload_id, created

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: create(), range(2)))

    assert len({upload_id for upload_id, _ in results}) == 1
    assert sorted(created for _, created in results) == [False, True]
    assert len(list(registry.uploads_root.iterdir())) == 1


def test_idempotency_and_permanent_asset_scope_conflicts_are_private(
    registry: MobileUploadRegistry,
) -> None:
    registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    with pytest.raises(MobileUploadError) as key_conflict:
        registry.initialize(
            OWNER,
            initialize_request(comment="anderer Text"),
            destination(),
            INIT_KEY,
        )
    with pytest.raises(MobileUploadError) as owner_conflict:
        registry.initialize(
            OTHER_OWNER,
            initialize_request(staging_area_id=OTHER_AREA),
            destination(OTHER_AREA),
            "99999999-9999-4999-8999-999999999999",
        )

    assert key_conflict.value.code == "idempotency_conflict"
    assert owner_conflict.value.code == "client_asset_conflict"
    assert ASSET not in str(owner_conflict.value)


def test_account_iri_and_resolved_destination_are_immutable(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    reused_user_id = MobileAccessIdentity("alice", "https://oldap.org/users/reused")

    with pytest.raises(MobileUploadError) as identity_conflict:
        registry.initialize(
            reused_user_id,
            initialize_request(),
            destination(),
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
    with pytest.raises(MobileUploadError) as replay_destination_conflict:
        registry.initialize(
            OWNER, initialize_request(), changed_destination(), INIT_KEY
        )
    with pytest.raises(MobileUploadError) as chunk_destination_conflict:
        registry.append_chunk(
            status.upload_id,
            OWNER,
            expected_offset=0,
            upload_length=8,
            chunk=b"abcd",
            destination=changed_destination(),
        )

    assert identity_conflict.value.code == "client_asset_conflict"
    assert replay_destination_conflict.value.code == "destination_changed"
    assert chunk_destination_conflict.value.code == "destination_changed"
    assert registry.get_status(status.upload_id, OWNER).offset == 0
    with sqlite3.connect(registry.database_path) as connection:
        assert (
            connection.execute(
                "SELECT owner_user_iri FROM mobile_uploads WHERE upload_id = ?",
                (status.upload_id,),
            ).fetchone()[0]
            == OWNER.user_iri
        )


def test_same_account_iri_can_resume_after_user_id_rename(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    renamed_owner = MobileAccessIdentity("alice-renamed", OWNER.user_iri)

    replay, created = registry.initialize(
        renamed_owner, initialize_request(), destination(), INIT_KEY
    )
    resumed = registry.append_chunk(
        status.upload_id,
        renamed_owner,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )

    assert replay == status
    assert created is False
    assert resumed.offset == 4


def test_preexisting_upload_directory_is_never_removed_on_uuid_collision(
    registry: MobileUploadRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    existing = registry.uploads_root / upload_id
    existing.mkdir()
    sentinel = existing / "belongs-to-another-operation"
    sentinel.write_bytes(b"keep")
    monkeypatch.setattr(registry_module, "uuid4", lambda: UUID(upload_id))

    with pytest.raises(FileExistsError):
        registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)

    assert sentinel.read_bytes() == b"keep"
    with sqlite3.connect(registry.database_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM mobile_uploads").fetchone()[0] == 0
        )


def test_chunks_use_authoritative_offsets_and_survive_restart(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    first = registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    with pytest.raises(MobileUploadError) as stale:
        registry.append_chunk(
            status.upload_id,
            OWNER,
            expected_offset=0,
            upload_length=8,
            chunk=b"abcd",
            destination=destination(),
        )

    restarted = MobileUploadRegistry(registry.root, limits(), clock=clock)
    complete = restarted.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    stored = registry.root / "uploads" / status.upload_id / "original.part"
    assert first.offset == 4
    assert stale.value.code == "upload_offset_mismatch"
    assert stale.value.upload_offset == 4
    assert complete.offset == 8
    assert stored.read_bytes() == b"abcdefgh"


def test_concurrent_chunks_cannot_double_advance(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )

    def append(value: bytes) -> str:
        try:
            registry.append_chunk(
                status.upload_id,
                OWNER,
                expected_offset=0,
                upload_length=8,
                chunk=value,
                destination=destination(),
            )
        except MobileUploadError as error:
            return error.code
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(append, (b"aaaa", b"bbbb")))

    assert sorted(results) == ["accepted", "upload_offset_mismatch"]
    current = registry.get_status(status.upload_id, OWNER)
    assert current.offset == 4
    assert (
        registry.root / "uploads" / status.upload_id / "original.part"
    ).stat().st_size == 4


def test_unconfirmed_crash_suffix_is_truncated_to_durable_offset(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    path = registry.root / "uploads" / status.upload_id / "original.part"
    path.write_bytes(b"unconfirmed")

    repaired = registry.get_status(status.upload_id, OWNER)

    assert repaired.offset == 0
    assert path.read_bytes() == b""


def test_commit_request_is_durable_idempotent_and_requires_complete_bytes(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    commit = CommitUpload(ASSET, 8, "sha256:" + "a" * 64)
    with pytest.raises(MobileUploadError) as incomplete:
        registry.request_commit(
            status.upload_id, OWNER, commit, destination(), COMMIT_KEY
        )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    accepted, committed = registry.request_commit(
        status.upload_id, OWNER, commit, destination(), COMMIT_KEY
    )
    replay, replay_committed = registry.request_commit(
        status.upload_id, OWNER, commit, destination(), COMMIT_KEY
    )

    assert incomplete.value.code == "upload_incomplete"
    assert accepted.state == "verifying"
    assert committed is False
    assert replay == accepted
    assert replay_committed is False


def test_same_commit_key_restarts_only_a_retryable_unleased_failure(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    commit = CommitUpload(ASSET, 8, "sha256:" + "a" * 64)
    registry.request_commit(status.upload_id, OWNER, commit, destination(), COMMIT_KEY)
    retryable_error = json.dumps(
        {"code": "oldap_unavailable", "retryable": True}, separators=(",", ":")
    )
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            "UPDATE mobile_uploads SET state = 'failed', error_json = ? "
            "WHERE upload_id = ?",
            (retryable_error, status.upload_id),
        )

    retried, committed = registry.request_commit(
        status.upload_id, OWNER, commit, destination(), COMMIT_KEY
    )

    assert retried.state == "verifying"
    assert retried.error is None
    assert committed is False


def test_commit_replay_respects_a_later_cancellation(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    commit = CommitUpload(ASSET, 8, "sha256:" + "a" * 64)
    registry.request_commit(status.upload_id, OWNER, commit, destination(), COMMIT_KEY)
    registry.cancel(status.upload_id, OWNER)

    with pytest.raises(MobileUploadError) as cancelled:
        registry.request_commit(
            status.upload_id, OWNER, commit, destination(), COMMIT_KEY
        )

    assert cancelled.value.status == 410
    assert cancelled.value.code == "upload_cancelled"


def test_commit_persists_missing_data_failure_before_returning_the_error(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    (registry.uploads_root / status.upload_id / "original.part").unlink()

    with pytest.raises(MobileUploadError) as missing:
        registry.request_commit(
            status.upload_id,
            OWNER,
            CommitUpload(ASSET, 8, "sha256:" + "a" * 64),
            destination(),
            COMMIT_KEY,
        )

    with sqlite3.connect(registry.database_path) as connection:
        persisted_state = connection.execute(
            "SELECT state FROM mobile_uploads WHERE upload_id = ?",
            (status.upload_id,),
        ).fetchone()[0]
    assert missing.value.code == "upload_failed"
    assert persisted_state == "failed"


def test_expiry_does_not_follow_token_lifetime_and_cancellation_is_idempotent(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    clock.value += timedelta(seconds=61)

    expired = registry.get_status(status.upload_id, OWNER)
    path = registry.root / "uploads" / status.upload_id
    assert expired.state == "expired"
    assert path.exists()
    registry.cancel(status.upload_id, OWNER)
    registry.cancel(status.upload_id, OWNER)
    assert not path.exists()
    assert registry.get_status(status.upload_id, OWNER).state == "cancelled"


def test_failed_cancellation_keeps_state_bytes_and_reservation(
    registry: MobileUploadRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    path = registry.uploads_root / status.upload_id / "original.part"

    def fail_removal(_path: Path) -> None:
        raise OSError("simulated removal failure")

    monkeypatch.setattr(registry, "_remove_upload_directory", fail_removal)
    with pytest.raises(OSError, match="simulated removal failure"):
        registry.cancel(status.upload_id, OWNER)

    assert registry.get_status(status.upload_id, OWNER).state == "initialized"
    assert path.exists()
    with sqlite3.connect(registry.database_path) as connection:
        reserved = connection.execute(
            "SELECT reserved_bytes FROM mobile_uploads WHERE upload_id = ?",
            (status.upload_id,),
        ).fetchone()[0]
    assert reserved == 8


def test_missing_upload_data_remains_reserved_until_cancellation(
    registry: MobileUploadRegistry,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    upload_directory = registry.uploads_root / status.upload_id
    (upload_directory / "original.part").unlink()

    failed = registry.get_status(status.upload_id, OWNER)

    assert failed.state == "failed"
    with sqlite3.connect(registry.database_path) as connection:
        reserved = connection.execute(
            "SELECT reserved_bytes FROM mobile_uploads WHERE upload_id = ?",
            (status.upload_id,),
        ).fetchone()[0]
    assert reserved == 8
    registry.cancel(status.upload_id, OWNER)
    assert not upload_directory.exists()


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires O_NOFOLLOW")
def test_repair_never_follows_a_replaced_upload_symlink(
    registry: MobileUploadRegistry, tmp_path: Path
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    path = registry.uploads_root / status.upload_id / "original.part"
    target = tmp_path / "unrelated-original"
    target.write_bytes(b"must-survive")
    path.unlink()
    path.symlink_to(target)

    with pytest.raises(OSError):
        registry.get_status(status.upload_id, OWNER)

    assert target.read_bytes() == b"must-survive"
    registry.cancel(status.upload_id, OWNER)
    assert target.read_bytes() == b"must-survive"


def test_registry_enforces_private_storage_modes_and_absolute_root(
    tmp_path: Path, clock: Clock
) -> None:
    root = tmp_path / "private-mobile"
    root.mkdir(mode=0o777)
    root.chmod(0o777)

    registry = MobileUploadRegistry(root, limits(), clock=clock)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(registry.uploads_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(registry.locks_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(registry.database_path.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="dedicated absolute path"):
        MobileUploadRegistry(Path("relative-mobile"), limits(), clock=clock)
    with pytest.raises(ValueError, match="dedicated absolute path"):
        MobileUploadRegistry(Path("/"), limits(), clock=clock)
    disguised_root = Path(tmp_path.anchor) / tmp_path.parts[1] / ".."
    with pytest.raises(ValueError, match="dedicated absolute path"):
        MobileUploadRegistry(disguised_root, limits(), clock=clock)


def test_registry_rejects_managed_storage_symlinks(
    tmp_path: Path, clock: Clock
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "mobile"
    root.mkdir()
    (root / "uploads").symlink_to(outside, target_is_directory=True)

    with pytest.raises(MobileUploadInvariantError, match="real directory"):
        MobileUploadRegistry(root, limits(), clock=clock)

    assert list(outside.iterdir()) == []


def test_registry_migrates_step_11c_schema_without_dropping_transport_data(
    tmp_path: Path, clock: Clock
) -> None:
    root = tmp_path / "mobile"
    root.mkdir()
    database = root / "registry.sqlite3"
    legacy_upload = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    legacy_asset = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE mobile_assets (
                client_asset_id TEXT PRIMARY KEY,
                owner_user_id TEXT NOT NULL,
                owner_user_iri TEXT NOT NULL,
                staging_area_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                current_upload_id TEXT,
                created_at TEXT NOT NULL,
                committed_upload_id TEXT,
                committed_asset_id TEXT,
                committed_resource_iri TEXT,
                committed_at TEXT
            );
            CREATE TABLE mobile_uploads (
                upload_id TEXT PRIMARY KEY,
                client_asset_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                owner_user_id TEXT NOT NULL,
                owner_user_iri TEXT NOT NULL,
                staging_area_id TEXT NOT NULL,
                mobile_folder_id TEXT NOT NULL,
                default_role_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                original_mime_type TEXT NOT NULL,
                byte_length INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                comment TEXT,
                state TEXT NOT NULL,
                offset INTEGER NOT NULL,
                chunk_size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_activity_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                reserved_bytes INTEGER NOT NULL,
                temp_path TEXT NOT NULL,
                verified_checksum TEXT,
                error_json TEXT,
                commit_phase TEXT NOT NULL,
                lease_owner TEXT,
                lease_expires_at TEXT,
                asset_id TEXT,
                resource_iri TEXT,
                committed_at TEXT
            );
            PRAGMA user_version = 1;
            """
        )
        connection.execute(
            """
            INSERT INTO mobile_assets (
                client_asset_id, owner_user_id, owner_user_iri, staging_area_id,
                generation, current_upload_id, created_at
            ) VALUES (?, 'alice', ?, ?, 1, ?, ?)
            """,
            (legacy_asset, OWNER.user_iri, AREA, legacy_upload, NOW.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO mobile_uploads (
                upload_id, client_asset_id, generation, owner_user_id,
                owner_user_iri, staging_area_id, mobile_folder_id, default_role_id,
                original_name, original_mime_type, byte_length, checksum, comment,
                state, offset, chunk_size, created_at, last_activity_at, expires_at,
                reserved_bytes, temp_path, verified_checksum, error_json,
                commit_phase, lease_owner, lease_expires_at
            ) VALUES (?, ?, 1, 'alice', ?, ?, ?, ?, 'legacy.jpg', 'image/jpeg',
                      8, ?, NULL, 'verifying', 8, 4, ?, ?, ?, 8, ?, NULL, NULL,
                      'requested', ?, ?)
            """,
            (
                legacy_upload,
                legacy_asset,
                OWNER.user_iri,
                AREA,
                destination().mobile_folder_id,
                destination().default_role_id,
                "sha256:" + "a" * 64,
                NOW.isoformat(),
                NOW.isoformat(),
                (NOW + timedelta(seconds=60)).isoformat(),
                f"uploads/{legacy_upload}/original.part",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                (NOW + timedelta(seconds=30)).isoformat(),
            ),
        )

    registry = MobileUploadRegistry(root, limits(), clock=clock)

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(mobile_uploads)")
        }
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        migrated = connection.execute(
            "SELECT * FROM mobile_uploads WHERE upload_id = ?", (legacy_upload,)
        ).fetchone()
    assert {
        "storage_path",
        "event_id",
        "publication_json",
        "oldap_result_json",
        "cleanup_pending",
    } <= columns
    expected_event = str(uuid5(UUID(legacy_upload), "mobile-media-commit"))
    assert migrated["state"] == "failed"
    assert migrated["storage_path"] is None
    assert migrated["event_id"] == expected_event
    assert json.loads(migrated["error_json"])["retryable"] is True
    assert migrated["lease_owner"] is None

    current, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    registry.append_chunk(
        current.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        current.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    registry.request_commit(
        current.upload_id,
        OWNER,
        CommitUpload(ASSET, 8, "sha256:" + "a" * 64),
        destination(),
        COMMIT_KEY,
    )
    claim = registry.claim_next_processing(INIT_KEY)
    assert claim is not None and claim.upload_id == current.upload_id


def test_active_and_reservation_limits_are_transactional(
    tmp_path: Path, clock: Clock
) -> None:
    constrained = MobileUploadRegistry(
        tmp_path / "mobile",
        limits(max_active_per_user=1, max_reserved_bytes_per_user=8),
        clock=clock,
    )
    constrained.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    with pytest.raises(MobileUploadError) as active:
        constrained.initialize(
            OWNER,
            initialize_request(client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            destination(),
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )
    assert active.value.code == "user_upload_limit"


def test_physical_capacity_rejects_before_registry_or_bytes_are_created(
    tmp_path: Path, clock: Clock
) -> None:
    guard = StorageCapacityGuard(
        disk_usage=lambda path: DiskUsage(total=100, used=80, free=20)
    )
    registry = MobileUploadRegistry(
        tmp_path / "mobile", limits(), capacity_guard=guard, clock=clock
    )

    with pytest.raises(MobileUploadError) as rejected:
        registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)

    assert rejected.value.code == "physical_capacity_insufficient"
    with sqlite3.connect(registry.database_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM mobile_uploads").fetchone()[0] == 0
        )
    assert list(registry.uploads_root.iterdir()) == []
