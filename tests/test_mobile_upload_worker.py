"""Crash, race, ambiguity, failure, and cleanup matrix for mobile commit work."""

from __future__ import annotations

import hashlib
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from config import MobileUploadLimits  # noqa: E402
from mobile_media_assets import MobileMediaAssetError, MobilePublication  # noqa: E402
from mobile_media_commit import MobileMediaCommitFailure  # noqa: E402
from mobile_media_lifecycle import (  # noqa: E402
    MobileMediaLifecycleEvent,
    MobileMediaLifecycleTransportError,
)
from mobile_upload_domain import (  # noqa: E402
    CommitUpload,
    InitializeUpload,
    MobileAccessIdentity,
    MobileUploadError,
    MobileUploadInvariantError,
    ResolvedMobileInbox,
)
from mobile_upload_registry import MobileUploadRegistry  # noqa: E402
from mobile_upload_worker import (  # noqa: E402
    MOBILE_PROCESSING_PEAK_FACTOR,
    MobileUploadWorker,
)
from storage_capacity import (  # noqa: E402
    DiskUsage,
    StorageCapacityGuard,
)


OWNER = MobileAccessIdentity("alice", "https://oldap.org/users/alice")
AREA = "urn:uuid:11111111-1111-4111-8111-111111111111"
ASSET = "22222222-2222-4222-8222-222222222222"
INIT_KEY = "33333333-3333-4333-8333-333333333333"
COMMIT_KEY = "44444444-4444-4444-8444-444444444444"
WORKER = "55555555-5555-4555-8555-555555555555"
CONTENT = b"\xff\xd8\xffabcde"
CHECKSUM = f"sha256:{hashlib.sha256(CONTENT).hexdigest()}"
NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


class MonotonicClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Assets:
    def __init__(self, *, fail_at: str | None = None) -> None:
        self.fail_at = fail_at
        self.media_root = Path("/media")
        self.calls: list[str] = []
        self.compensated = False

    def verify_original(self, spec) -> str:
        self.calls.append("verify")
        if self.fail_at == "verify":
            raise MobileMediaAssetError("invalid")
        return spec.checksum

    def prepare(self, spec) -> None:
        self.calls.append("prepare")
        if self.fail_at == "prepare":
            raise MobileMediaAssetError("rendition")

    def publish(self, spec) -> MobilePublication:
        self.calls.append("publish")
        return MobilePublication(
            spec.upload_id,
            spec.client_asset_id,
            spec.byte_length,
            spec.checksum,
            ("master.tif",),
            spec.storage_path,
        )

    def compensate(self, spec) -> None:
        self.calls.append("compensate")
        self.compensated = True

    def delete_committed(self, spec) -> None:
        self.calls.append("delete-committed")
        if self.fail_at == "delete-committed":
            raise MobileMediaAssetError("deletion failed")


class Oldap:
    def __init__(self, failure: MobileMediaCommitFailure | None = None) -> None:
        self.failure = failure
        self.calls = 0

    def commit(self, upload_id: str, request_id: str, payload: dict[str, object]):
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return {
            "eventId": payload["eventId"],
            "uploadId": upload_id,
            "clientAssetId": payload["clientAssetId"],
            "stagingAreaId": payload["stagingAreaId"],
            "assetId": payload["clientAssetId"],
            "resourceIri": "urn:uuid:66666666-6666-4666-8666-666666666666",
            "checksum": payload["checksum"],
            "committedAt": "2026-08-23T12:00:00Z",
        }


class Lifecycle:
    def __init__(self) -> None:
        self.event: MobileMediaLifecycleEvent | None = None
        self.completed: list[str] = []
        self.claims = 0

    def claim(self, worker_id: str) -> MobileMediaLifecycleEvent | None:
        self.claims += 1
        event, self.event = self.event, None
        return event

    def complete(self, event: MobileMediaLifecycleEvent) -> None:
        self.completed.append(event.event_id)


class Capacity:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[Path, int]] = []

    def require(self, path: Path, *, additional_bytes: int):
        self.calls.append((path, additional_bytes))
        if self.fail:
            guard = StorageCapacityGuard(
                disk_usage=lambda unused: DiskUsage(total=100, used=100, free=0)
            )
            guard.require(path, additional_bytes=additional_bytes)


def limits(**changes: int) -> MobileUploadLimits:
    values = {
        "max_original_bytes": 100,
        "chunk_bytes": 4,
        "inactivity_seconds": 60,
        "lease_seconds": 30,
        "max_active_per_user": 20,
        "max_active_per_staging_area": 100,
        "max_reserved_bytes_per_user": 1000,
        "max_reserved_bytes_per_staging_area": 1000,
        "max_processing_jobs": 2,
    }
    values.update(changes)
    return MobileUploadLimits(**values)


def destination() -> ResolvedMobileInbox:
    return ResolvedMobileInbox(
        AREA,
        "urn:uuid:77777777-7777-4777-8777-777777777777",
        "urn:uuid:88888888-8888-4888-8888-888888888888",
        "fasnacht/image/bmg",
    )


def queued(
    registry: MobileUploadRegistry,
    *,
    asset: str = ASSET,
    init_key: str = INIT_KEY,
    commit_key: str = COMMIT_KEY,
):
    checksum = (
        CHECKSUM
        if asset == ASSET
        else f"sha256:{hashlib.sha256(asset.encode('ascii')).hexdigest()}"
    )
    request = InitializeUpload(
        asset, AREA, "photo.jpg", "image/jpeg", len(CONTENT), checksum, "Keller"
    )
    status, _ = registry.initialize(OWNER, request, destination(), init_key)
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=0,
        upload_length=len(CONTENT),
        chunk=CONTENT[:4],
        destination=destination(),
    )
    registry.append_chunk(
        status.upload_id,
        OWNER,
        expected_offset=4,
        upload_length=len(CONTENT),
        chunk=CONTENT[4:],
        destination=destination(),
    )
    registry.request_commit(
        status.upload_id,
        OWNER,
        CommitUpload(asset, len(CONTENT), checksum),
        destination(),
        commit_key,
    )
    return status


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def registry(tmp_path: Path, clock: Clock) -> MobileUploadRegistry:
    return MobileUploadRegistry(tmp_path / "mobile", limits(), clock=clock)


def worker(
    registry,
    assets=None,
    oldap=None,
    capacity=None,
    worker_id=WORKER,
    **options,
):
    return MobileUploadWorker(
        registry,
        assets or Assets(),
        oldap or Oldap(),
        capacity or Capacity(),
        worker_id=worker_id,
        **options,
    )


def test_remote_lifecycle_polling_is_throttled_without_delaying_local_work(
    registry: MobileUploadRegistry,
) -> None:
    lifecycle = Lifecycle()
    clock = MonotonicClock()
    oldap = Oldap()
    runner = worker(
        registry,
        oldap=oldap,
        lifecycle=lifecycle,
        lifecycle_poll_seconds=20,
        monotonic_clock=clock,
    )

    assert runner.run_once() is False
    assert lifecycle.claims == 1
    assert runner.run_once() is False
    assert lifecycle.claims == 1

    queued(registry)
    assert runner.run_once() is True
    assert lifecycle.claims == 1
    assert oldap.calls == 1

    clock.advance(19.9)
    runner.run_once()  # Local cleanup may still be available.
    assert lifecycle.claims == 1
    clock.advance(0.1)
    assert runner.run_once() is False
    assert lifecycle.claims == 2


def test_unavailable_lifecycle_endpoint_obeys_the_same_poll_interval(
    registry: MobileUploadRegistry,
) -> None:
    class UnavailableLifecycle:
        def __init__(self) -> None:
            self.claims = 0

        def claim(self, worker_id: str):
            self.claims += 1
            raise MobileMediaLifecycleTransportError("offline")

        def complete(self, event):
            raise AssertionError("No unavailable claim can be completed.")

    lifecycle = UnavailableLifecycle()
    clock = MonotonicClock()
    runner = worker(
        registry,
        lifecycle=lifecycle,
        lifecycle_poll_seconds=20,
        monotonic_clock=clock,
    )

    assert runner.run_once() is False
    assert runner.run_once() is False
    assert lifecycle.claims == 1
    clock.advance(20)
    assert runner.run_once() is False
    assert lifecycle.claims == 2


def test_lifecycle_backlog_alternates_with_ready_local_upload_work(
    registry: MobileUploadRegistry,
) -> None:
    committed = queued(registry)
    assert worker(registry).run_once() is True
    queued(
        registry,
        asset="99999999-9999-4999-8999-999999999981",
        init_key="99999999-9999-4999-8999-999999999982",
        commit_key="99999999-9999-4999-8999-999999999983",
    )

    class LifecycleBacklog:
        def __init__(self) -> None:
            self.events = [
                MobileMediaLifecycleEvent(
                    event_id=f"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa{index}",
                    claim_id=f"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb{index}",
                    worker_id=WORKER,
                    kind="moved",
                    upload_id=committed.upload_id,
                    client_asset_id=ASSET,
                    owner_user_iri=OWNER.user_iri,
                    staging_area_id=AREA,
                    resource_iri="urn:uuid:66666666-6666-4666-8666-666666666666",
                    checksum=CHECKSUM,
                    occurred_at=NOW + timedelta(minutes=index),
                    lease_expires_at=NOW + timedelta(minutes=index + 5),
                )
                for index in (1, 2)
            ]
            self.completed: list[str] = []

        def claim(self, worker_id: str) -> MobileMediaLifecycleEvent | None:
            assert worker_id == WORKER
            return self.events.pop(0) if self.events else None

        def complete(self, event: MobileMediaLifecycleEvent) -> None:
            self.completed.append(event.event_id)

    lifecycle = LifecycleBacklog()
    oldap = Oldap()
    runner = worker(registry, lifecycle=lifecycle, oldap=oldap)

    assert runner.run_once() is True
    assert oldap.calls == 0
    assert len(lifecycle.completed) == 1
    assert runner.run_once() is True
    assert oldap.calls == 1
    assert len(lifecycle.completed) == 1
    assert runner.run_once() is True
    assert len(lifecycle.completed) == 2


def test_lifecycle_poll_interval_must_be_positive(
    registry: MobileUploadRegistry,
) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        worker(registry, lifecycle_poll_seconds=0)


def test_happy_commit_is_atomic_and_cleanup_never_removes_final_asset(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    runner = worker(registry)

    assert runner.run_once() is True
    committed = registry.get_status(status.upload_id, OWNER)
    assert committed.state == "committed"
    assert committed.asset_id == ASSET
    with registry._connect() as connection:
        receipt_count = connection.execute(
            "SELECT COUNT(*) FROM mobile_content_receipts"
        ).fetchone()[0]
        reservation_count = connection.execute(
            "SELECT COUNT(*) FROM mobile_content_reservations"
        ).fetchone()[0]
    assert receipt_count == 1
    assert reservation_count == 0
    assert (registry.uploads_root / status.upload_id).exists()
    assert runner.run_once() is True
    assert not (registry.uploads_root / status.upload_id).exists()
    assert registry.get_status(status.upload_id, OWNER).state == "committed"
    assert runner.run_once() is False


def test_cleanup_is_not_starved_by_a_continuous_processing_queue(
    registry: MobileUploadRegistry,
) -> None:
    queued(registry)
    queued(
        registry,
        asset="99999999-9999-4999-8999-999999999991",
        init_key="99999999-9999-4999-8999-999999999992",
        commit_key="99999999-9999-4999-8999-999999999993",
    )
    runner = worker(registry)

    assert runner.run_once() is True
    assert runner.run_once() is True

    with registry._connect() as connection:
        states = [
            row[0]
            for row in connection.execute(
                "SELECT state FROM mobile_uploads ORDER BY upload_id"
            )
        ]
        pending_cleanup = connection.execute(
            "SELECT COUNT(*) FROM mobile_uploads WHERE cleanup_pending = 1"
        ).fetchone()[0]
    assert states.count("committed") == 1
    assert states.count("verifying") == 1
    assert pending_cleanup == 0


def test_worker_startup_recovers_an_orphaned_initialization_directory(
    registry: MobileUploadRegistry,
) -> None:
    registered, _ = registry.initialize(
        OWNER,
        InitializeUpload(
            ASSET, AREA, "photo.jpg", "image/jpeg", len(CONTENT), CHECKSUM, None
        ),
        destination(),
        INIT_KEY,
    )
    orphan = registry.uploads_root / "99999999-9999-4999-8999-999999999994"
    orphan.mkdir()
    (orphan / "original.part").write_bytes(b"orphan")

    worker(registry)

    assert not orphan.exists()
    assert (registry.uploads_root / registered.upload_id).exists()


def test_running_worker_periodically_reconciles_later_orphans(
    registry: MobileUploadRegistry,
) -> None:
    runner = worker(registry)
    orphan = registry.uploads_root / "99999999-9999-4999-8999-999999999995"
    orphan.mkdir()
    (orphan / "original.part").write_bytes(b"orphan")
    runner._next_orphan_reconciliation = 0

    assert runner.run_once() is False
    assert not orphan.exists()


def test_processing_reserves_cross_mount_publication_peak(
    registry: MobileUploadRegistry,
) -> None:
    queued(registry)
    capacity = Capacity()

    worker(registry, capacity=capacity).run_once()

    assert len(capacity.calls) == 2
    assert {additional for _, additional in capacity.calls} == {
        len(CONTENT) * MOBILE_PROCESSING_PEAK_FACTOR
    }


def test_every_durable_phase_can_be_reclaimed_after_a_worker_crash(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    queued(registry)
    claim = registry.claim_next_processing(WORKER)
    assert claim is not None and claim.commit_phase == "requested"
    claim = registry.record_checksum_verified(claim, CHECKSUM)
    clock.value += timedelta(seconds=31)
    claim = registry.claim_next_processing("99999999-9999-4999-8999-999999999999")
    assert claim is not None and claim.commit_phase == "checksum_verified"
    claim = registry.record_derivatives_ready(claim)
    clock.value += timedelta(seconds=31)
    claim = registry.claim_next_processing("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    assert claim is not None and claim.commit_phase == "derivatives_ready"
    publication = MobilePublication(
        claim.upload_id,
        ASSET,
        len(CONTENT),
        CHECKSUM,
        ("master.tif",),
        claim.storage_path,
    )
    claim = registry.record_files_published(claim, publication.to_dict())
    clock.value += timedelta(seconds=31)
    recovered = registry.claim_next_processing("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    assert recovered is not None and recovered.commit_phase == "files_published"
    result = Oldap().commit(
        recovered.upload_id,
        recovered.event_id,
        MobileUploadWorker._commit_payload(recovered),
    )
    recovered = registry.record_oldap_committed(recovered, result)
    clock.value += timedelta(seconds=31)
    final_claim = registry.claim_next_processing("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    assert final_claim is not None and final_claim.commit_phase == "oldap_committed"
    registry.complete_commit(final_claim)
    assert registry.get_status(final_claim.upload_id, OWNER).state == "committed"


def test_durable_processing_progress_renews_inactivity_expiry(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    original_expiry = registry.get_status(status.upload_id, OWNER).expires_at
    clock.value += timedelta(seconds=30)
    claim = registry.claim_next_processing(WORKER)
    assert claim is not None

    registry.record_checksum_verified(claim, CHECKSUM)

    refreshed = registry.get_status(status.upload_id, OWNER)
    assert refreshed.expires_at == clock.value + timedelta(seconds=60)
    assert refreshed.expires_at > original_expiry


def test_stale_processing_claim_is_rejected_before_file_access(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    queued(registry)
    stale = registry.claim_next_processing(WORKER)
    assert stale is not None
    clock.value += timedelta(seconds=31)
    current = registry.claim_next_processing("99999999-9999-4999-8999-999999999999")
    assert current is not None
    assets = Assets()

    with pytest.raises(MobileUploadInvariantError, match="lease was lost"):
        worker(registry, assets=assets)._process(stale)

    assert assets.calls == []


def test_file_operation_detects_lease_reclaim_before_persisting_its_phase(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    stale = registry.claim_next_processing(WORKER)
    assert stale is not None
    replacement = None

    class ReclaimingAssets(Assets):
        def verify_original(self, spec) -> str:
            nonlocal replacement
            self.calls.append("verify")
            clock.value += timedelta(seconds=31)
            replacement = registry.claim_next_processing(
                "99999999-9999-4999-8999-999999999999"
            )
            return spec.checksum

    assets = ReclaimingAssets()
    with pytest.raises(MobileUploadInvariantError, match="lease was lost"):
        worker(registry, assets=assets)._process(stale)

    with registry._connect() as connection:  # type: ignore[attr-defined]
        phase = connection.execute(
            "SELECT commit_phase FROM mobile_uploads WHERE upload_id = ?",
            (status.upload_id,),
        ).fetchone()[0]
    assert phase == "requested"
    assert replacement is not None
    worker(
        registry,
        assets=Assets(),
        worker_id="99999999-9999-4999-8999-999999999999",
    )._process(replacement)
    assert registry.get_status(status.upload_id, OWNER).state == "committed"


def test_same_upload_is_claimed_once_and_global_processing_cap_is_enforced(
    registry: MobileUploadRegistry,
) -> None:
    queued(registry)
    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(
            executor.map(
                registry.claim_next_processing,
                (WORKER, "99999999-9999-4999-8999-999999999999"),
            )
        )
    assert sum(claim is not None for claim in claims) == 1


def test_global_processing_cap_blocks_a_third_distinct_job(
    tmp_path: Path, clock: Clock
) -> None:
    registry = MobileUploadRegistry(
        tmp_path / "mobile", limits(max_processing_jobs=2), clock=clock
    )
    for _ in range(3):
        queued(
            registry,
            asset=str(uuid4()),
            init_key=str(uuid4()),
            commit_key=str(uuid4()),
        )
    assert registry.claim_next_processing(str(uuid4())) is not None
    assert registry.claim_next_processing(str(uuid4())) is not None
    assert registry.claim_next_processing(str(uuid4())) is None


def test_lost_oldap_response_retries_same_publication_and_converges(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    assets = Assets()
    oldap = Oldap(MobileMediaCommitFailure("upstream_unavailable", retryable=True))
    runner = worker(registry, assets, oldap)
    runner.run_once()
    failed = registry.get_status(status.upload_id, OWNER)
    assert failed.state == "failed" and failed.error["retryable"] is True  # type: ignore[index]
    assert assets.compensated is False
    with registry._connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mobile_content_reservations"
            ).fetchone()[0]
            == 1
        )

    registry.request_commit(
        status.upload_id,
        OWNER,
        CommitUpload(ASSET, len(CONTENT), CHECKSUM),
        destination(),
        COMMIT_KEY,
    )
    oldap.failure = None
    runner.run_once()
    assert registry.get_status(status.upload_id, OWNER).state == "committed"
    assert oldap.calls == 2
    assert assets.calls.count("publish") == 1


def test_definite_oldap_rejection_compensates_but_ambiguous_failure_does_not(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    assets = Assets()
    runner = worker(
        registry,
        assets,
        Oldap(MobileMediaCommitFailure("client_asset_conflict", retryable=False)),
    )
    runner.run_once()
    failed = registry.get_status(status.upload_id, OWNER)
    assert failed.state == "failed" and failed.error["retryable"] is False  # type: ignore[index]
    assert assets.compensated is True
    with registry._connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mobile_content_reservations"
            ).fetchone()[0]
            == 0
        )
    registry.cancel(status.upload_id, OWNER)
    cleanup = registry.claim_next_cleanup(str(uuid4()))
    assert cleanup is not None
    registry.remove_claimed_upload_directory(cleanup)
    registry.complete_cleanup(cleanup)
    restarted, created = registry.initialize(
        OWNER,
        InitializeUpload(
            ASSET,
            AREA,
            "photo.jpg",
            "image/jpeg",
            len(CONTENT),
            CHECKSUM,
            "Keller",
        ),
        destination(),
        str(uuid4()),
    )
    assert created is True
    assert restarted.upload_id != status.upload_id


def test_crash_during_definitive_compensation_never_retries_oldap(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    claim = registry.claim_next_processing(WORKER)
    assert claim is not None
    claim = registry.record_checksum_verified(claim, CHECKSUM)
    claim = registry.record_derivatives_ready(claim)
    publication = MobilePublication(
        claim.upload_id,
        ASSET,
        len(CONTENT),
        CHECKSUM,
        ("master.tif",),
        claim.storage_path,
    )
    claim = registry.record_files_published(claim, publication.to_dict())
    registry.record_compensation_required(claim, "client_asset_conflict")
    clock.value += timedelta(seconds=31)
    assets = Assets()
    oldap = Oldap()

    worker(
        registry,
        assets=assets,
        oldap=oldap,
        worker_id="99999999-9999-4999-8999-999999999999",
    ).run_once()

    failed = registry.get_status(status.upload_id, OWNER)
    assert failed.state == "failed"
    assert assets.compensated is True
    assert oldap.calls == 0


@pytest.mark.parametrize("phase", ["verify", "prepare"])
def test_checksum_or_rendition_failure_is_stable_and_cleanup_is_repeatable(
    registry: MobileUploadRegistry, phase: str
) -> None:
    status = queued(registry)
    runner = worker(registry, Assets(fail_at=phase))
    runner.run_once()
    failed = registry.get_status(status.upload_id, OWNER)
    assert failed.state == "failed" and failed.error["retryable"] is False  # type: ignore[index]
    assert runner.run_once() is True
    assert not (registry.uploads_root / status.upload_id).exists()
    assert runner.run_once() is False


def test_disk_full_is_retryable_and_keeps_uploaded_original(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    runner = worker(registry, capacity=Capacity(fail=True))
    runner.run_once()
    failed = registry.get_status(status.upload_id, OWNER)
    assert failed.error["code"] == "physical_capacity_insufficient"  # type: ignore[index]
    assert failed.error["retryable"] is True  # type: ignore[index]
    assert (registry.uploads_root / status.upload_id / "original.part").exists()


def test_retryable_prepublication_failure_expires_and_releases_private_storage(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    runner = worker(registry, capacity=Capacity(fail=True))
    runner.run_once()
    clock.value += timedelta(seconds=61)

    assert runner.run_once() is True
    assert registry.get_status(status.upload_id, OWNER).state == "expired"
    assert not (registry.uploads_root / status.upload_id).exists()


def test_retryable_postpublication_failure_never_expires_ambiguously(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    runner = worker(
        registry,
        oldap=Oldap(MobileMediaCommitFailure("upstream_unavailable", retryable=True)),
    )
    runner.run_once()
    clock.value += timedelta(seconds=61)

    assert runner.run_once() is False
    assert registry.get_status(status.upload_id, OWNER).state == "failed"
    assert (registry.uploads_root / status.upload_id).exists()


def test_published_ambiguous_upload_cannot_be_cancelled(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    worker(
        registry,
        oldap=Oldap(MobileMediaCommitFailure("upstream_unavailable", retryable=True)),
    ).run_once()
    with pytest.raises(MobileUploadError) as caught:
        registry.cancel(status.upload_id, OWNER)
    assert caught.value.code == "upload_commit_uncertain"


def test_cleanup_recovers_after_directory_deletion_and_lost_acknowledgement(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    runner = worker(registry, assets=Assets(fail_at="verify"))
    runner.run_once()
    cleanup = registry.claim_next_cleanup(WORKER)
    assert cleanup is not None
    registry.remove_claimed_upload_directory(cleanup)

    clock.value += timedelta(seconds=31)
    replay = registry.claim_next_cleanup("99999999-9999-4999-8999-999999999999")
    assert replay is not None
    registry.remove_claimed_upload_directory(replay)
    registry.complete_cleanup(replay)
    assert registry.get_status(status.upload_id, OWNER).state == "failed"
    assert registry.claim_next_cleanup(str(uuid4())) is None


def test_stale_cleanup_claim_cannot_remove_private_storage(
    registry: MobileUploadRegistry, clock: Clock
) -> None:
    status = queued(registry)
    worker(registry, assets=Assets(fail_at="verify")).run_once()
    stale = registry.claim_next_cleanup(WORKER)
    assert stale is not None
    clock.value += timedelta(seconds=31)
    current = registry.claim_next_cleanup("99999999-9999-4999-8999-999999999999")
    assert current is not None

    with pytest.raises(MobileUploadInvariantError, match="lease was lost"):
        worker(registry)._cleanup(stale)

    assert (registry.uploads_root / status.upload_id).exists()


def test_authoritative_staging_delete_is_applied_once_before_acknowledgement(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    commit_runner = worker(registry)
    assert commit_runner.run_once() is True

    lifecycle = Lifecycle()
    lifecycle.event = MobileMediaLifecycleEvent(
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
        claim_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
        worker_id=WORKER,
        kind="staging_deleted",
        upload_id=status.upload_id,
        client_asset_id=ASSET,
        owner_user_iri=OWNER.user_iri,
        staging_area_id=AREA,
        resource_iri="urn:uuid:66666666-6666-4666-8666-666666666666",
        checksum=CHECKSUM,
        occurred_at=NOW + timedelta(minutes=1),
        lease_expires_at=NOW + timedelta(minutes=6),
    )
    assets = Assets()
    lifecycle_runner = worker(registry, assets=assets)
    lifecycle_runner.lifecycle = lifecycle

    assert lifecycle_runner.run_once() is True
    assert assets.calls == ["delete-committed"]
    assert lifecycle.completed == ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"]
    with registry._connect() as connection:
        receipt = connection.execute(
            "SELECT lifecycle_state, release_reason FROM mobile_content_receipts"
        ).fetchone()
    assert tuple(receipt) == ("released", "staging_deleted")

    replacement = InitializeUpload(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3",
        AREA,
        "photo-again.jpg",
        "image/jpeg",
        len(CONTENT),
        CHECKSUM,
        None,
    )
    replacement_status, created = registry.initialize(
        OWNER,
        replacement,
        destination(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
    )
    assert created is True
    assert replacement_status.client_asset_id == replacement.client_asset_id


def test_failed_staging_file_deletion_keeps_receipt_active_and_event_unacknowledged(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    assert worker(registry).run_once() is True
    lifecycle = Lifecycle()
    lifecycle.event = MobileMediaLifecycleEvent(
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5",
        claim_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6",
        worker_id=WORKER,
        kind="staging_deleted",
        upload_id=status.upload_id,
        client_asset_id=ASSET,
        owner_user_iri=OWNER.user_iri,
        staging_area_id=AREA,
        resource_iri="urn:uuid:66666666-6666-4666-8666-666666666666",
        checksum=CHECKSUM,
        occurred_at=NOW + timedelta(minutes=1),
        lease_expires_at=NOW + timedelta(minutes=6),
    )
    runner = worker(registry, assets=Assets(fail_at="delete-committed"))
    runner.lifecycle = lifecycle

    with pytest.raises(MobileMediaAssetError, match="deletion failed"):
        runner.run_once()

    assert lifecycle.completed == []
    with registry._connect() as connection:
        receipt = connection.execute(
            "SELECT lifecycle_state, released_at FROM mobile_content_receipts"
        ).fetchone()
        event_state = connection.execute(
            "SELECT state FROM mobile_lifecycle_events"
        ).fetchone()[0]
    assert tuple(receipt) == ("active", None)
    assert event_state == "received"


def test_restart_after_lost_lifecycle_ack_replays_without_second_file_deletion(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    assert worker(registry).run_once() is True
    event = MobileMediaLifecycleEvent(
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7",
        claim_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8",
        worker_id=WORKER,
        kind="staging_deleted",
        upload_id=status.upload_id,
        client_asset_id=ASSET,
        owner_user_iri=OWNER.user_iri,
        staging_area_id=AREA,
        resource_iri="urn:uuid:66666666-6666-4666-8666-666666666666",
        checksum=CHECKSUM,
        occurred_at=NOW + timedelta(minutes=1),
        lease_expires_at=NOW + timedelta(minutes=6),
    )

    class LostAcknowledgementLifecycle:
        def __init__(self) -> None:
            self.fail = True
            self.completed = 0

        def claim(self, worker_id: str):
            return event

        def complete(self, claimed: MobileMediaLifecycleEvent) -> None:
            assert claimed == event
            self.completed += 1
            if self.fail:
                self.fail = False
                raise RuntimeError("response lost")

    lifecycle = LostAcknowledgementLifecycle()
    first_assets = Assets()
    first = worker(registry, assets=first_assets)
    first.lifecycle = lifecycle
    with pytest.raises(RuntimeError, match="response lost"):
        first.run_once()
    assert first_assets.calls == ["delete-committed"]

    restarted_assets = Assets()
    restarted = worker(registry, assets=restarted_assets)
    restarted.lifecycle = lifecycle
    assert restarted.run_once() is True
    assert restarted_assets.calls == []
    assert lifecycle.completed == 2
    with registry._connect() as connection:
        assert (
            connection.execute(
                "SELECT lifecycle_state FROM mobile_content_receipts"
            ).fetchone()[0]
            == "released"
        )
