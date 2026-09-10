"""Protocol-level persistence, race, expiry, and capacity tests for mobile uploads."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from time import sleep
from uuid import UUID, uuid5

import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from config import MobileUploadLimits  # noqa: E402
import mobile_upload_registry as registry_module  # noqa: E402
from mobile_upload_domain import (  # noqa: E402
    CommitUpload,
    ContentDuplicateResult,
    InitializeUpload,
    MobileAccessIdentity,
    MobileUploadError,
    MobileUploadInvariantError,
    ResolvedMobileInbox,
    canonical_request_hash,
    parse_initialize_upload,
)
from mobile_media_lifecycle import MobileMediaLifecycleEvent  # noqa: E402
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
LIFECYCLE_EVENT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
LIFECYCLE_CLAIM = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"


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


def commit_upload(
    registry: MobileUploadRegistry,
    request: InitializeUpload | None = None,
    *,
    owner: MobileAccessIdentity = OWNER,
    target: ResolvedMobileInbox | None = None,
    init_key: str = INIT_KEY,
    commit_key: str = COMMIT_KEY,
) -> str:
    """Advance one fixture through the durable registry commit boundary."""

    upload_request = request or initialize_request()
    upload_target = target or destination(upload_request.staging_area_id)
    status, created = registry.initialize(
        owner, upload_request, upload_target, init_key
    )
    assert created is True and not isinstance(status, ContentDuplicateResult)
    complete_initialized_upload(
        registry,
        status.upload_id,
        upload_request,
        owner=owner,
        target=upload_target,
        commit_key=commit_key,
    )
    return status.upload_id


def complete_initialized_upload(
    registry: MobileUploadRegistry,
    upload_id: str,
    request: InitializeUpload,
    *,
    owner: MobileAccessIdentity = OWNER,
    target: ResolvedMobileInbox | None = None,
    commit_key: str = COMMIT_KEY,
) -> None:
    """Complete an already initialized fixture through all durable phases."""

    upload_target = target or destination(request.staging_area_id)
    registry.append_chunk(
        upload_id,
        owner,
        expected_offset=0,
        upload_length=request.byte_length,
        chunk=b"abcd",
        destination=upload_target,
    )
    registry.append_chunk(
        upload_id,
        owner,
        expected_offset=4,
        upload_length=request.byte_length,
        chunk=b"efgh",
        destination=upload_target,
    )
    registry.request_commit(
        upload_id,
        owner,
        CommitUpload(
            request.client_asset_id,
            request.byte_length,
            request.checksum,
        ),
        upload_target,
        commit_key,
    )
    worker_id = "88888888-8888-4888-8888-888888888888"
    claim = registry.claim_next_processing(worker_id)
    assert claim is not None and claim.upload_id == upload_id
    claim = registry.record_checksum_verified(claim, request.checksum)
    claim = registry.record_derivatives_ready(claim)
    claim = registry.record_files_published(
        claim,
        {
            "ownerUploadId": upload_id,
            "assetId": request.client_asset_id,
            "byteLength": request.byte_length,
            "checksum": request.checksum,
            "derivativeNames": ["master.tif"],
            "storagePath": upload_target.storage_path,
        },
    )
    claim = registry.record_oldap_committed(
        claim,
        {
            "eventId": claim.event_id,
            "uploadId": upload_id,
            "clientAssetId": request.client_asset_id,
            "stagingAreaId": request.staging_area_id,
            "assetId": request.client_asset_id,
            "resourceIri": "urn:uuid:99999999-9999-4999-8999-999999999999",
            "checksum": request.checksum,
            "committedAt": "2026-08-22T12:00:00Z",
        },
    )
    registry.complete_commit(claim)


def lifecycle_event(
    upload_id: str,
    *,
    kind: str,
    event_id: str = LIFECYCLE_EVENT,
    request: InitializeUpload | None = None,
) -> MobileMediaLifecycleEvent:
    upload_request = request or initialize_request()
    return MobileMediaLifecycleEvent(
        event_id=event_id,
        claim_id=LIFECYCLE_CLAIM,
        worker_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3",
        kind=kind,
        upload_id=upload_id,
        client_asset_id=upload_request.client_asset_id,
        owner_user_iri=OWNER.user_iri,
        staging_area_id=upload_request.staging_area_id,
        resource_iri="urn:uuid:99999999-9999-4999-8999-999999999999",
        checksum=upload_request.checksum,
        occurred_at=NOW + timedelta(minutes=1),
        lease_expires_at=NOW + timedelta(minutes=6),
    )


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
    for whitespace_name in (" photo.jpg", "photo.jpg "):
        with pytest.raises(MobileUploadError):
            parse_initialize_upload(
                {**body, "originalName": whitespace_name}, max_original_bytes=100
            )
    assert (
        parse_initialize_upload(
            {**body, "comment": "  Kurze Notiz  "}, max_original_bytes=100
        ).comment
        == "Kurze Notiz"
    )
    assert (
        parse_initialize_upload(
            {**body, "comment": "   "}, max_original_bytes=100
        ).comment
        is None
    )
    assert unexpected.value.code == "invalid_request"

    with pytest.raises(MobileUploadError):
        parse_initialize_upload(
            body | {"clientAssetId": "00000000-0000-0000-0000-000000000000"},
            max_original_bytes=100,
        )
    for invalid_identifier in (
        "ftp://example.org/staging",
        "urn:",
        "urn:uuid:bad value",
    ):
        with pytest.raises(MobileUploadError):
            parse_initialize_upload(
                body | {"stagingAreaId": invalid_identifier},
                max_original_bytes=100,
            )
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


def test_committed_content_duplicate_is_distinct_permanent_and_location_independent(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    original_upload = commit_upload(registry)
    restarted = MobileUploadRegistry(registry.root, limits(), clock=clock)
    committed, committed_created = restarted.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa0",
    )
    assert committed_created is False
    assert not isinstance(committed, ContentDuplicateResult)
    assert committed.upload_id == original_upload
    assert committed.state == "committed"
    assert committed.asset_id == ASSET

    cleanup = registry.claim_next_cleanup("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    assert cleanup is not None and cleanup.upload_id == original_upload
    registry.remove_claimed_upload_directory(cleanup)
    registry.complete_cleanup(cleanup)
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            """
            UPDATE mobile_uploads
            SET mobile_folder_id = ?, resource_iri = ?
            WHERE upload_id = ?
            """,
            (
                "urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab",
                "urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac",
                original_upload,
            ),
        )

    duplicate_request = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaad"
    )
    first, created = registry.initialize(
        OWNER,
        duplicate_request,
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaae",
    )
    replay, replay_created = restarted.initialize(
        OWNER,
        duplicate_request,
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaf",
    )

    assert created is replay_created is False
    assert (
        first
        == replay
        == ContentDuplicateResult(
            duplicate_request.client_asset_id, AREA, duplicate_request.checksum
        )
    )
    assert first.to_dict() == {
        "clientAssetId": duplicate_request.client_asset_id,
        "stagingAreaId": AREA,
        "state": "content-duplicate",
        "checksum": duplicate_request.checksum,
    }
    assert original_upload not in str(first.to_dict())
    assert ASSET not in str(first.to_dict())
    with sqlite3.connect(registry.database_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM mobile_uploads").fetchone()[0] == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mobile_content_receipts"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mobile_content_duplicates"
            ).fetchone()[0]
            == 1
        )


def test_v2_registry_backfills_permanent_content_receipts(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    original_upload = commit_upload(registry)
    with sqlite3.connect(registry.database_path) as connection:
        connection.executescript(
            """
            DROP TABLE mobile_content_duplicate_idempotency;
            DROP TABLE mobile_content_duplicates;
            DROP TABLE mobile_content_reservations;
            DROP TABLE mobile_content_receipts;
            PRAGMA user_version = 2;
            """
        )

    migrated = MobileUploadRegistry(registry.root, limits(), clock=clock)
    duplicate_request = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab1"
    )
    result, created = migrated.initialize(
        OWNER,
        duplicate_request,
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab2",
    )

    assert created is False
    assert result == ContentDuplicateResult(
        duplicate_request.client_asset_id, AREA, duplicate_request.checksum
    )
    with sqlite3.connect(registry.database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        receipt = connection.execute(
            """
            SELECT committed_upload_id, client_asset_id, staging_area_id, checksum
            FROM mobile_content_receipts
            """
        ).fetchone()
    assert receipt == (original_upload, ASSET, AREA, duplicate_request.checksum)


def test_registry_startup_serializes_schema_migration(
    registry: MobileUploadRegistry,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    with sqlite3.connect(registry.database_path) as connection:
        connection.executescript(
            """
            DROP TABLE mobile_content_duplicate_idempotency;
            DROP TABLE mobile_content_duplicates;
            DROP TABLE mobile_content_reservations;
            DROP TABLE mobile_content_receipts;
            PRAGMA user_version = 2;
            """
        )

    original = MobileUploadRegistry._initialize_database
    guard = Lock()
    first_entered = Event()
    release_first = Event()
    calls = 0
    active = 0
    maximum_active = 0

    def observed_initialize_database(self: MobileUploadRegistry) -> None:
        nonlocal calls, active, maximum_active
        with guard:
            is_first = calls == 0
            calls += 1
            active += 1
            maximum_active = max(maximum_active, active)
        try:
            if is_first:
                first_entered.set()
                assert release_first.wait(timeout=5)
            original(self)
        finally:
            with guard:
                active -= 1

    monkeypatch.setattr(
        MobileUploadRegistry, "_initialize_database", observed_initialize_database
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            MobileUploadRegistry, registry.root, limits(), clock=clock
        )
        assert first_entered.wait(timeout=5)
        second = executor.submit(
            MobileUploadRegistry, registry.root, limits(), clock=clock
        )
        sleep(0.1)
        with guard:
            assert maximum_active == 1
        release_first.set()
        migrated = [first.result(timeout=5), second.result(timeout=5)]

    assert all(
        candidate.get_status(status.upload_id, OWNER).state == "initialized"
        for candidate in migrated
    )
    with sqlite3.connect(registry.database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mobile_content_reservations"
            ).fetchone()[0]
            == 1
        )


def test_registry_fails_closed_when_active_reservation_is_missing(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            "DELETE FROM mobile_content_reservations WHERE upload_id = ?",
            (status.upload_id,),
        )

    with pytest.raises(MobileUploadInvariantError, match="no durable content"):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_registry_fails_closed_when_committed_receipt_is_missing(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    upload_id = commit_upload(registry)
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            "DELETE FROM mobile_content_receipts WHERE committed_upload_id = ?",
            (upload_id,),
        )

    with pytest.raises(MobileUploadInvariantError, match="no permanent content"):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_registry_fails_closed_when_committed_result_identity_changes(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    commit_upload(registry)
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            """
            UPDATE mobile_assets
            SET committed_resource_iri = 'urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
            WHERE client_asset_id = ?
            """,
            (ASSET,),
        )

    with pytest.raises(MobileUploadInvariantError, match="receipt is contradictory"):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_registry_fails_closed_when_active_asset_ownership_changes(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            """
            UPDATE mobile_assets SET owner_user_iri = ?
            WHERE client_asset_id = ?
            """,
            (OTHER_OWNER.user_iri, ASSET),
        )

    with pytest.raises(
        MobileUploadInvariantError, match="reservation is contradictory"
    ):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_registry_fails_closed_when_committed_asset_scope_changes(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    commit_upload(registry)
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            """
            UPDATE mobile_assets SET staging_area_id = ?
            WHERE client_asset_id = ?
            """,
            (OTHER_AREA, ASSET),
        )

    with pytest.raises(MobileUploadInvariantError, match="ownership is contradictory"):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_registry_fails_closed_when_duplicate_history_owner_changes(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    first, _ = registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    assert not isinstance(first, ContentDuplicateResult)
    registry.cancel(first.upload_id, OWNER)
    commit_upload(
        registry,
        initialize_request(client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab3"),
        init_key="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab4",
        commit_key="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab5",
    )
    registry.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab6",
    )
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            """
            UPDATE mobile_content_duplicates SET owner_user_iri = ?
            WHERE client_asset_id = ?
            """,
            (OTHER_OWNER.user_iri, ASSET),
        )

    with pytest.raises(
        MobileUploadInvariantError, match="contradictory permanent outcomes"
    ):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_registry_fails_closed_when_idempotency_namespaces_overlap(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    original_upload = commit_upload(registry)
    duplicate_request = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab7"
    )
    duplicate_key = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaab8"
    registry.initialize(OWNER, duplicate_request, destination(), duplicate_key)
    with sqlite3.connect(registry.database_path) as connection:
        connection.execute(
            """
            INSERT INTO mobile_idempotency (
                owner_user_id, owner_user_iri, staging_area_id, idempotency_key,
                operation, request_hash, upload_id, created_at
            ) VALUES (?, ?, ?, ?, 'initialize', 'contradictory', ?, ?)
            """,
            (
                OWNER.user_id,
                OWNER.user_iri,
                AREA,
                duplicate_key,
                original_upload,
                "2026-08-22T12:00:00Z",
            ),
        )

    with pytest.raises(MobileUploadInvariantError, match="namespaces overlap"):
        MobileUploadRegistry(registry.root, limits(), clock=clock)


def test_same_checksum_in_another_staging_area_remains_independent(
    registry: MobileUploadRegistry,
) -> None:
    commit_upload(registry)
    request = initialize_request(
        client_asset_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        staging_area_id=OTHER_AREA,
    )

    result, created = registry.initialize(
        OTHER_OWNER,
        request,
        destination(OTHER_AREA),
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc",
    )

    assert created is True
    assert not isinstance(result, ContentDuplicateResult)
    assert result.staging_area_id == OTHER_AREA


def test_concurrent_new_client_assets_reserve_identical_content_once(
    registry: MobileUploadRegistry,
) -> None:
    requests = [
        initialize_request(client_asset_id="cccccccc-cccc-4ccc-8ccc-ccccccccccc1"),
        initialize_request(client_asset_id="cccccccc-cccc-4ccc-8ccc-ccccccccccc2"),
    ]
    keys = [
        "cccccccc-cccc-4ccc-8ccc-ccccccccccc3",
        "cccccccc-cccc-4ccc-8ccc-ccccccccccc4",
    ]

    def initialize_index(index: int) -> tuple[str, object]:
        try:
            result, created = registry.initialize(
                OWNER, requests[index], destination(), keys[index]
            )
            return "created" if created else "existing", result
        except MobileUploadError as error:
            return "error", error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(initialize_index, range(2)))

    assert sorted(kind for kind, _ in results) == ["created", "error"]
    created_result = next(value for kind, value in results if kind == "created")
    blocked = next(value for kind, value in results if kind == "error")
    assert not isinstance(created_result, ContentDuplicateResult)
    assert isinstance(blocked, MobileUploadError)
    assert blocked.code == "content_upload_in_progress"
    assert blocked.retryable is True
    winner = next(
        request
        for request in requests
        if request.client_asset_id == created_result.client_asset_id
    )
    loser = next(request for request in requests if request is not winner)
    complete_initialized_upload(registry, created_result.upload_id, winner)

    duplicate, created = registry.initialize(
        OWNER,
        loser,
        destination(),
        "cccccccc-cccc-4ccc-8ccc-ccccccccccc5",
    )

    assert created is False
    assert isinstance(duplicate, ContentDuplicateResult)
    assert duplicate.client_asset_id == loser.client_asset_id
    with sqlite3.connect(registry.database_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM mobile_uploads").fetchone()[0] == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mobile_content_receipts"
            ).fetchone()[0]
            == 1
        )


def test_concurrent_authorized_users_share_one_private_content_result(
    registry: MobileUploadRegistry,
) -> None:
    requests = [
        initialize_request(client_asset_id="dddddddd-dddd-4ddd-8ddd-ddddddddddd1"),
        initialize_request(client_asset_id="dddddddd-dddd-4ddd-8ddd-ddddddddddd2"),
    ]
    owners = [OWNER, OTHER_OWNER]
    keys = [
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd3",
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd4",
    ]

    def initialize_index(index: int) -> tuple[int, str, object]:
        try:
            result, created = registry.initialize(
                owners[index], requests[index], destination(), keys[index]
            )
            return index, "created" if created else "existing", result
        except MobileUploadError as error:
            return index, "error", error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(initialize_index, range(2)))

    assert sorted(kind for _, kind, _ in results) == ["created", "error"]
    winner_index, _, winner = next(row for row in results if row[1] == "created")
    loser_index, _, blocked = next(row for row in results if row[1] == "error")
    assert not isinstance(winner, ContentDuplicateResult)
    assert isinstance(blocked, MobileUploadError)
    assert blocked.code == "content_upload_in_progress"
    assert blocked.retryable is True
    assert requests[winner_index].client_asset_id not in str(blocked)

    complete_initialized_upload(
        registry,
        winner.upload_id,
        requests[winner_index],
        owner=owners[winner_index],
    )
    duplicate, created = registry.initialize(
        owners[loser_index],
        requests[loser_index],
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd5",
    )

    assert created is False
    assert isinstance(duplicate, ContentDuplicateResult)
    assert duplicate.client_asset_id == requests[loser_index].client_asset_id
    assert duplicate.staging_area_id == AREA
    assert set(duplicate.to_dict()) == {
        "clientAssetId",
        "stagingAreaId",
        "state",
        "checksum",
    }

    restarted = MobileUploadRegistry(registry.root, limits(), clock=Clock())
    replay, replay_created = restarted.initialize(
        owners[loser_index],
        requests[loser_index],
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd6",
    )
    assert replay_created is False
    assert replay == duplicate


def test_cancelled_and_expired_generations_release_content_reservations(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    first, _ = registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    assert not isinstance(first, ContentDuplicateResult)
    registry.cancel(first.upload_id, OWNER)
    second_request = initialize_request(
        client_asset_id="dddddddd-dddd-4ddd-8ddd-ddddddddddd1"
    )
    second, second_created = registry.initialize(
        OWNER,
        second_request,
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd2",
    )
    assert second_created is True and not isinstance(second, ContentDuplicateResult)

    clock.value += timedelta(seconds=61)
    assert registry.get_status(second.upload_id, OWNER).state == "expired"
    third, third_created = registry.initialize(
        OWNER,
        initialize_request(client_asset_id="dddddddd-dddd-4ddd-8ddd-ddddddddddd3"),
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd4",
    )

    assert third_created is True
    assert not isinstance(third, ContentDuplicateResult)


def test_terminal_generation_can_converge_to_a_later_duplicate_after_restart(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    first, _ = registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    assert not isinstance(first, ContentDuplicateResult)
    registry.cancel(first.upload_id, OWNER)

    committed_request = initialize_request(
        client_asset_id="dddddddd-dddd-4ddd-8ddd-ddddddddddd5"
    )
    commit_upload(
        registry,
        request=committed_request,
        init_key="dddddddd-dddd-4ddd-8ddd-ddddddddddd6",
        commit_key="dddddddd-dddd-4ddd-8ddd-ddddddddddd7",
    )

    duplicate, created = registry.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd8",
    )
    restarted = MobileUploadRegistry(registry.root, limits(), clock=clock)
    replay, replay_created = restarted.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd9",
    )

    assert created is replay_created is False
    assert (
        duplicate
        == replay
        == ContentDuplicateResult(ASSET, AREA, initialize_request().checksum)
    )
    assert restarted.get_status(first.upload_id, OWNER).state == "cancelled"


def test_restarted_client_asset_keeps_its_exact_original_bytes(
    registry: MobileUploadRegistry,
) -> None:
    first, _ = registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    registry.cancel(first.upload_id, OWNER)

    with pytest.raises(MobileUploadError) as changed_content:
        registry.initialize(
            OWNER,
            initialize_request(checksum="sha256:" + "f" * 64),
            destination(),
            "dddddddd-dddd-4ddd-8ddd-ddddddddddd5",
        )

    restarted, created = registry.initialize(
        OWNER,
        initialize_request(original_name="renamed.jpg", comment="Neue Notiz"),
        destination(),
        "dddddddd-dddd-4ddd-8ddd-ddddddddddd6",
    )

    assert changed_content.value.code == "client_asset_conflict"
    assert created is True
    assert not isinstance(restarted, ContentDuplicateResult)
    assert restarted.upload_id != first.upload_id


def test_duplicate_identity_and_idempotency_replays_fail_closed(
    registry: MobileUploadRegistry,
) -> None:
    commit_upload(registry)
    duplicate_request = initialize_request(
        client_asset_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1"
    )
    duplicate_key = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2"
    first, _ = registry.initialize(
        OWNER, duplicate_request, destination(), duplicate_key
    )
    replay, _ = registry.initialize(
        OWNER, duplicate_request, destination(), duplicate_key
    )

    with pytest.raises(MobileUploadError) as changed_payload:
        registry.initialize(
            OWNER,
            initialize_request(
                client_asset_id=duplicate_request.client_asset_id,
                original_name="changed.jpg",
            ),
            destination(),
            duplicate_key,
        )
    with pytest.raises(MobileUploadError) as foreign_owner:
        registry.initialize(
            OTHER_OWNER,
            duplicate_request,
            destination(),
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee3",
        )

    assert first == replay
    assert changed_payload.value.code == "idempotency_conflict"
    assert foreign_owner.value.code == "client_asset_conflict"
    assert ASSET not in str(foreign_owner.value)


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


def test_commit_key_follows_only_a_safely_cancelled_asset_generation(
    registry: MobileUploadRegistry,
) -> None:
    first, _ = registry.initialize(OWNER, initialize_request(), destination(), INIT_KEY)
    registry.append_chunk(
        first.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        first.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )
    commit = CommitUpload(ASSET, 8, "sha256:" + "a" * 64)
    registry.request_commit(first.upload_id, OWNER, commit, destination(), COMMIT_KEY)
    registry.cancel(first.upload_id, OWNER)

    second, created = registry.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "dddddddd-dddd-4ddd-8ddd-dddddddddda1",
    )
    assert created is True
    assert not isinstance(second, ContentDuplicateResult)
    registry.append_chunk(
        second.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=8,
        chunk=b"abcd",
        destination=destination(),
    )
    registry.append_chunk(
        second.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=8,
        chunk=b"efgh",
        destination=destination(),
    )

    accepted, committed = registry.request_commit(
        second.upload_id, OWNER, commit, destination(), COMMIT_KEY
    )

    assert accepted.state == "verifying"
    assert committed is False
    with sqlite3.connect(registry.database_path) as connection:
        rebound = connection.execute(
            "SELECT upload_id FROM mobile_idempotency WHERE idempotency_key = ?",
            (COMMIT_KEY,),
        ).fetchone()
    assert rebound == (second.upload_id,)


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
    assert path.exists()
    assert registry.get_status(status.upload_id, OWNER).state == "cancelled"
    cleanup = registry.claim_next_cleanup(str(UUID(int=9)))
    assert cleanup is not None
    registry.remove_claimed_upload_directory(cleanup)
    registry.complete_cleanup(cleanup)
    assert not path.exists()


def test_cancellation_is_durable_before_cleanup_and_keeps_its_reservation(
    registry: MobileUploadRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    status, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    path = registry.uploads_root / status.upload_id / "original.part"

    def fail_removal(_path: Path) -> None:
        raise OSError("simulated removal failure")

    monkeypatch.setattr(registry, "_remove_upload_directory", fail_removal)
    registry.cancel(status.upload_id, OWNER)

    assert registry.get_status(status.upload_id, OWNER).state == "cancelled"
    assert path.exists()
    with sqlite3.connect(registry.database_path) as connection:
        reserved, cleanup_pending = connection.execute(
            "SELECT reserved_bytes, cleanup_pending FROM mobile_uploads WHERE upload_id = ?",
            (status.upload_id,),
        ).fetchone()
    assert reserved == 8
    assert cleanup_pending == 1


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
    assert upload_directory.exists()
    cleanup = registry.claim_next_cleanup(str(UUID(int=10)))
    assert cleanup is not None
    registry.remove_claimed_upload_directory(cleanup)
    registry.complete_cleanup(cleanup)
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
    cleanup = registry.claim_next_cleanup(str(UUID(int=11)))
    assert cleanup is not None
    registry.remove_claimed_upload_directory(cleanup)
    registry.complete_cleanup(cleanup)
    assert target.read_bytes() == b"must-survive"


def test_orphan_reconciliation_removes_only_unregistered_uuid_directories(
    registry: MobileUploadRegistry,
) -> None:
    registered, _ = registry.initialize(
        OWNER, initialize_request(), destination(), INIT_KEY
    )
    orphan_id = str(UUID(int=12))
    orphan = registry.uploads_root / orphan_id
    orphan.mkdir()
    (orphan / "original.part").write_bytes(b"orphan")
    unrelated = registry.uploads_root / "operator-notes"
    unrelated.mkdir()

    assert registry.reconcile_orphan_upload_directories() == 1

    assert not orphan.exists()
    assert (registry.uploads_root / registered.upload_id).exists()
    assert unrelated.exists()


def test_orphan_reconciliation_waits_for_initialization_commit(
    registry: MobileUploadRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    insert_reached = Event()
    allow_commit = Event()
    original_insert = registry._insert_idempotency

    def delayed_insert(*args, **kwargs) -> None:
        original_insert(*args, **kwargs)
        insert_reached.set()
        assert allow_commit.wait(timeout=2)

    monkeypatch.setattr(registry, "_insert_idempotency", delayed_insert)
    with ThreadPoolExecutor(max_workers=2) as executor:
        initialization = executor.submit(
            registry.initialize,
            OWNER,
            initialize_request(),
            destination(),
            INIT_KEY,
        )
        assert insert_reached.wait(timeout=2)
        reconciliation = executor.submit(registry.reconcile_orphan_upload_directories)
        with pytest.raises(FutureTimeoutError):
            reconciliation.result(timeout=0.05)
        allow_commit.set()
        status, created = initialization.result(timeout=2)
        assert reconciliation.result(timeout=2) == 0

    assert created is True
    assert (registry.uploads_root / status.upload_id).exists()


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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        migrated = connection.execute(
            "SELECT * FROM mobile_uploads WHERE upload_id = ?", (legacy_upload,)
        ).fetchone()
        reservation = connection.execute(
            "SELECT upload_id FROM mobile_content_reservations"
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
    assert reservation["upload_id"] == legacy_upload

    migrated_checksum = "sha256:" + "b" * 64
    current, _ = registry.initialize(
        OWNER,
        initialize_request(checksum=migrated_checksum),
        destination(),
        INIT_KEY,
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
        CommitUpload(ASSET, 8, migrated_checksum),
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
            initialize_request(
                client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                checksum="sha256:" + "b" * 64,
            ),
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


def test_staging_delete_releases_checksum_but_preserves_original_identity(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    event = lifecycle_event(upload_id, kind="staging_deleted")

    action = registry.begin_lifecycle_event(event)
    assert action.requires_file_deletion is True
    registry.complete_staging_deletion(event)
    assert registry.begin_lifecycle_event(event).requires_file_deletion is False

    replay, created = registry.initialize(
        OWNER,
        initialize_request(),
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
    )
    assert created is False
    assert replay.state == "committed"

    replacement = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5"
    )
    replacement_status, replacement_created = registry.initialize(
        OWNER,
        replacement,
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6",
    )
    assert replacement_created is True
    assert replacement_status.client_asset_id == replacement.client_asset_id


def test_two_devices_racing_after_release_create_exactly_one_new_generation(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    event = lifecycle_event(upload_id, kind="staging_deleted")
    registry.begin_lifecycle_event(event)
    registry.complete_staging_deletion(event)
    requests = [
        initialize_request(client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa21"),
        initialize_request(client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa22"),
    ]
    keys = [
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa23",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa24",
    ]

    def initialize_index(index: int) -> tuple[str, object]:
        try:
            result, created = registry.initialize(
                OWNER, requests[index], destination(), keys[index]
            )
            return "created" if created else "existing", result
        except MobileUploadError as error:
            return "error", error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(initialize_index, range(2)))

    assert sorted(kind for kind, _ in results) == ["created", "error"]
    winner = next(value for kind, value in results if kind == "created")
    blocked = next(value for kind, value in results if kind == "error")
    assert winner.client_asset_id in {request.client_asset_id for request in requests}
    assert isinstance(blocked, MobileUploadError)
    assert blocked.code == "content_upload_in_progress"


def test_legacy_delete_lookup_requires_exact_committed_mobile_facts(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    exact = registry.committed_asset_for_legacy_delete(
        ASSET,
        "urn:uuid:99999999-9999-4999-8999-999999999999",
        "fasnacht/image/bmg",
    )

    assert exact is not None
    assert exact.upload_id == upload_id
    assert exact.client_asset_id == ASSET
    assert (
        registry.committed_asset_for_legacy_delete(
            ASSET,
            "urn:uuid:99999999-9999-4999-8999-999999999998",
            "fasnacht/image/bmg",
        )
        is None
    )
    assert (
        registry.committed_asset_for_legacy_delete(
            "legacy-id",
            "urn:uuid:99999999-9999-4999-8999-999999999999",
            "fasnacht/image/bmg",
        )
        is None
    )


@pytest.mark.parametrize("kind", ["moved", "archived"])
def test_move_and_archive_keep_same_area_checksum_blocked(
    registry: MobileUploadRegistry, kind: str
) -> None:
    upload_id = commit_upload(registry)
    event = lifecycle_event(upload_id, kind=kind)

    assert registry.begin_lifecycle_event(event).requires_file_deletion is False
    duplicate = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7"
    )
    result, created = registry.initialize(
        OWNER, duplicate, destination(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8"
    )

    assert created is False
    assert result == ContentDuplicateResult(
        duplicate.client_asset_id, AREA, duplicate.checksum
    )


def test_move_then_confirmed_staging_delete_allows_one_new_identity(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    moved = lifecycle_event(upload_id, kind="moved")
    deleted = lifecycle_event(
        upload_id,
        kind="staging_deleted",
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa25",
    )

    assert registry.begin_lifecycle_event(moved).requires_file_deletion is False
    assert registry.begin_lifecycle_event(deleted).requires_file_deletion is True
    registry.complete_staging_deletion(deleted)

    replacement = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa26"
    )
    replacement_status, created = registry.initialize(
        OWNER,
        replacement,
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa27",
    )

    assert created is True
    assert replacement_status.client_asset_id == replacement.client_asset_id


def test_archive_wins_over_a_late_staging_delete_event(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    archived = lifecycle_event(upload_id, kind="archived")
    deleted = lifecycle_event(
        upload_id,
        kind="staging_deleted",
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9",
    )

    registry.begin_lifecycle_event(archived)
    assert registry.begin_lifecycle_event(deleted).requires_file_deletion is False
    with sqlite3.connect(registry.database_path) as connection:
        state = connection.execute(
            "SELECT lifecycle_state FROM mobile_content_receipts WHERE committed_upload_id = ?",
            (upload_id,),
        ).fetchone()[0]
    assert state == "archived"


def test_archive_evidence_restores_permanent_block_after_delayed_delete_delivery(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    deleted = lifecycle_event(upload_id, kind="staging_deleted")
    archived = lifecycle_event(
        upload_id,
        kind="archived",
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa12",
    )

    registry.begin_lifecycle_event(deleted)
    registry.complete_staging_deletion(deleted)
    registry.begin_lifecycle_event(archived)

    with sqlite3.connect(registry.database_path) as connection:
        receipt = connection.execute(
            "SELECT lifecycle_state, released_at, release_reason "
            "FROM mobile_content_receipts WHERE committed_upload_id = ?",
            (upload_id,),
        ).fetchone()
    assert receipt == ("archived", None, None)

    duplicate = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa13"
    )
    result, created = registry.initialize(
        OWNER, duplicate, destination(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa14"
    )
    assert created is False
    assert isinstance(result, ContentDuplicateResult)


def test_released_receipt_does_not_change_existing_duplicate_tombstone(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    duplicate = initialize_request(
        client_asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa10"
    )
    first, created = registry.initialize(
        OWNER, duplicate, destination(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa11"
    )
    assert created is False and isinstance(first, ContentDuplicateResult)
    event = lifecycle_event(upload_id, kind="staging_deleted")
    registry.begin_lifecycle_event(event)
    registry.complete_staging_deletion(event)

    replay, replay_created = registry.initialize(
        OWNER, duplicate, destination(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa12"
    )
    assert replay_created is False
    assert replay == first


def test_lifecycle_event_cannot_be_reused_with_different_facts(
    registry: MobileUploadRegistry,
) -> None:
    upload_id = commit_upload(registry)
    event = lifecycle_event(upload_id, kind="moved")
    registry.begin_lifecycle_event(event)

    with pytest.raises(MobileUploadInvariantError):
        registry.begin_lifecycle_event(
            lifecycle_event(upload_id, kind="archived", event_id=event.event_id)
        )
