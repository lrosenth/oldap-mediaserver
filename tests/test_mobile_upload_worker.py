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
from mobile_upload_domain import (  # noqa: E402
    CommitUpload,
    InitializeUpload,
    MobileAccessIdentity,
    MobileUploadError,
    MobileUploadInvariantError,
    ResolvedMobileInbox,
)
from mobile_upload_registry import MobileUploadRegistry  # noqa: E402
from mobile_upload_worker import MobileUploadWorker  # noqa: E402
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


class Capacity:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def require(self, path: Path, *, additional_bytes: int):
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
    request = InitializeUpload(
        asset, AREA, "photo.jpg", "image/jpeg", len(CONTENT), CHECKSUM, "Keller"
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
        CommitUpload(asset, len(CONTENT), CHECKSUM),
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


def worker(registry, assets=None, oldap=None, capacity=None, worker_id=WORKER):
    return MobileUploadWorker(
        registry,
        assets or Assets(),
        oldap or Oldap(),
        capacity or Capacity(),
        worker_id=worker_id,
    )


def test_happy_commit_is_atomic_and_cleanup_never_removes_final_asset(
    registry: MobileUploadRegistry,
) -> None:
    status = queued(registry)
    runner = worker(registry)

    assert runner.run_once() is True
    committed = registry.get_status(status.upload_id, OWNER)
    assert committed.state == "committed"
    assert committed.asset_id == ASSET
    assert (registry.uploads_root / status.upload_id).exists()
    assert runner.run_once() is True
    assert not (registry.uploads_root / status.upload_id).exists()
    assert registry.get_status(status.upload_id, OWNER).state == "committed"
    assert runner.run_once() is False


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
    registry.cancel(status.upload_id, OWNER)
    assert registry.claim_next_cleanup(str(uuid4())) is None
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
