"""Leased, phase-durable orchestration for asynchronous mobile media commits."""

from __future__ import annotations

import errno
import logging
import threading
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from time import sleep
from typing import Iterator, Protocol
from uuid import uuid4

from config import MediahelperSettings
from mobile_media_assets import (
    MobileAssetSpec,
    MobileMediaAssetError,
    MobileMediaAssetStore,
)
from mobile_media_commit import (
    MobileMediaCommitFailure,
    OldapMobileMediaCommitClient,
)
from mobile_upload_domain import MobileUploadInvariantError
from mobile_upload_registry import (
    MobileCleanupClaim,
    MobileProcessingClaim,
    MobileUploadRegistry,
)
from storage_capacity import PhysicalCapacityInsufficient, StorageCapacityGuard


LOGGER = logging.getLogger(__name__)
MOBILE_PROCESSING_PEAK_FACTOR = 8


class CommitClient(Protocol):
    """OLDAP commit surface injected into the worker."""

    def commit(
        self, upload_id: str, request_id: str, payload: dict[str, object]
    ) -> dict[str, object]: ...


class ProcessingLeaseHeartbeat(AbstractContextManager["ProcessingLeaseHeartbeat"]):
    """Renew one processing lease and transfer renewal failure to its owner."""

    def __init__(
        self, registry: MobileUploadRegistry, claim: MobileProcessingClaim
    ) -> None:
        self.registry = registry
        self.claim = claim
        self.interval = max(1.0, registry.limits.lease_seconds / 3)
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "ProcessingLeaseHeartbeat":
        self.renew_now()
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval + 1)

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            raise MobileUploadInvariantError(
                "Mobile processing lease heartbeat failed."
            ) from self._failure

    def renew_now(self) -> None:
        """Synchronously fence work before and after one file operation."""

        self.raise_if_failed()
        self.registry.renew_processing_lease(
            self.claim.upload_id, self.claim.lease_owner
        )

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.registry.renew_processing_lease(
                    self.claim.upload_id, self.claim.lease_owner
                )
            except BaseException as error:
                self._failure = error
                return


class CleanupLeaseHeartbeat(AbstractContextManager["CleanupLeaseHeartbeat"]):
    """Renew a cleanup lease while its private directory is being removed."""

    def __init__(
        self, registry: MobileUploadRegistry, claim: MobileCleanupClaim
    ) -> None:
        self.registry = registry
        self.claim = claim
        self.interval = max(1.0, registry.limits.lease_seconds / 3)
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "CleanupLeaseHeartbeat":
        self.renew_now()
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval + 1)

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            raise MobileUploadInvariantError(
                "Mobile cleanup lease heartbeat failed."
            ) from self._failure

    def renew_now(self) -> None:
        """Synchronously fence cleanup before and after directory removal."""

        self.raise_if_failed()
        self.registry.renew_cleanup_lease(self.claim.upload_id, self.claim.lease_owner)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.registry.renew_cleanup_lease(
                    self.claim.upload_id, self.claim.lease_owner
                )
            except BaseException as error:
                self._failure = error
                return


class MobileUploadWorker:
    """Recover and advance one mobile commit or cleanup task per iteration."""

    def __init__(
        self,
        registry: MobileUploadRegistry,
        assets: MobileMediaAssetStore,
        oldap: CommitClient,
        capacity: StorageCapacityGuard,
        *,
        worker_id: str | None = None,
        logger: logging.Logger = LOGGER,
    ) -> None:
        self.registry = registry
        self.assets = assets
        self.oldap = oldap
        self.capacity = capacity
        self.worker_id = worker_id or str(uuid4())
        self.logger = logger

    @classmethod
    def from_environment(cls) -> "MobileUploadWorker":
        """Build the separately deployed mobile processing worker."""

        settings = MediahelperSettings.from_environment()
        capacity = StorageCapacityGuard(settings.storage_absolute_reserve_bytes)
        registry = MobileUploadRegistry(
            settings.mobile_upload_root,
            settings.mobile_upload_limits,
            capacity_guard=capacity,
        )
        return cls(
            registry,
            MobileMediaAssetStore(settings.media_root),
            OldapMobileMediaCommitClient.from_environment(),
            capacity,
        )

    def run_once(self) -> bool:
        """Advance one processing task, otherwise one cleanup task."""

        claim = self.registry.claim_next_processing(self.worker_id)
        if claim is not None:
            self._process(claim)
            return True
        cleanup = self.registry.claim_next_cleanup(self.worker_id)
        if cleanup is None:
            return False
        self._cleanup(cleanup)
        return True

    def run_forever(self, *, idle_seconds: float = 2.0) -> None:
        """Poll durable work indefinitely without coupling to Flask workers."""

        while True:
            try:
                worked = self.run_once()
            except Exception:
                self.logger.exception("mobile_upload_worker_iteration_failed")
                worked = False
            if not worked:
                sleep(idle_seconds)

    def _process(self, claim: MobileProcessingClaim) -> None:
        spec = self._asset_spec(claim)
        try:
            with ProcessingLeaseHeartbeat(self.registry, claim) as heartbeat:
                if claim.commit_phase == "compensating":
                    with self._file_operation(claim, heartbeat):
                        self.assets.compensate(spec)
                    self.registry.complete_compensation(claim)
                    return
                if claim.commit_phase == "requested":
                    with self._file_operation(claim, heartbeat):
                        checksum = self.assets.verify_original(spec)
                    claim = self.registry.record_checksum_verified(claim, checksum)
                if claim.commit_phase == "checksum_verified":
                    # Preparation and cross-mount-safe publication can
                    # temporarily retain both a work tree and a final-filesystem
                    # staging copy. Apply the full peak estimate to both paths;
                    # this is intentionally conservative when they use separate
                    # physical filesystems.
                    self.capacity.require(
                        claim.upload_directory,
                        additional_bytes=(
                            claim.byte_length * MOBILE_PROCESSING_PEAK_FACTOR
                        ),
                    )
                    self.capacity.require(
                        self.assets.media_root,
                        additional_bytes=(
                            claim.byte_length * MOBILE_PROCESSING_PEAK_FACTOR
                        ),
                    )
                    with self._file_operation(claim, heartbeat):
                        self.assets.prepare(spec)
                    claim = self.registry.record_derivatives_ready(claim)
                if claim.commit_phase == "derivatives_ready":
                    with self._file_operation(claim, heartbeat):
                        publication = self.assets.publish(spec)
                    claim = self.registry.record_files_published(
                        claim, publication.to_dict()
                    )
                if claim.commit_phase == "files_published":
                    result = self.oldap.commit(
                        claim.upload_id,
                        claim.event_id,
                        self._commit_payload(claim),
                    )
                    heartbeat.raise_if_failed()
                    claim = self.registry.record_oldap_committed(claim, result)
                if claim.commit_phase == "oldap_committed":
                    heartbeat.raise_if_failed()
                    self.registry.complete_commit(claim)
        except MobileMediaCommitFailure as error:
            if error.retryable:
                self.registry.fail_processing(claim, error.code, retryable=True)
                return
            claim = self.registry.record_compensation_required(claim, error.code)
            with ProcessingLeaseHeartbeat(self.registry, claim) as heartbeat:
                with self._file_operation(claim, heartbeat):
                    self.assets.compensate(spec)
                self.registry.complete_compensation(claim)
        except (MobileMediaAssetError, ValueError) as error:
            self.logger.info(
                "mobile_media_rejected uploadId=%s error=%s",
                claim.upload_id,
                type(error).__name__,
            )
            self.registry.fail_processing(
                claim,
                "media_validation_failed",
                retryable=False,
                cleanup_pending=True,
            )
        except PhysicalCapacityInsufficient:
            self.registry.fail_processing(
                claim, "physical_capacity_insufficient", retryable=True
            )
        except OSError as error:
            self.registry.fail_processing(
                claim,
                (
                    "physical_capacity_insufficient"
                    if error.errno == errno.ENOSPC
                    else "media_processing_unavailable"
                ),
                retryable=True,
            )

    def _cleanup(self, claim: MobileCleanupClaim) -> None:
        with CleanupLeaseHeartbeat(self.registry, claim) as heartbeat:
            with self.registry.upload_operation_lock(claim.upload_id):
                heartbeat.renew_now()
                self.registry.remove_claimed_upload_directory(claim)
                heartbeat.renew_now()
            self.registry.complete_cleanup(claim)

    @contextmanager
    def _file_operation(
        self,
        claim: MobileProcessingClaim,
        heartbeat: ProcessingLeaseHeartbeat,
    ) -> Iterator[None]:
        """Fence one upload-owned filesystem effect against stale workers."""

        with self.registry.upload_operation_lock(claim.upload_id):
            heartbeat.renew_now()
            yield
            heartbeat.renew_now()

    @staticmethod
    def _asset_spec(claim: MobileProcessingClaim) -> MobileAssetSpec:
        return MobileAssetSpec(
            upload_id=claim.upload_id,
            client_asset_id=claim.client_asset_id,
            original_name=claim.original_name,
            original_mime_type=claim.original_mime_type,
            byte_length=claim.byte_length,
            checksum=claim.checksum,
            storage_path=claim.storage_path,
            upload_directory=claim.upload_directory,
        )

    @staticmethod
    def _commit_payload(claim: MobileProcessingClaim) -> dict[str, object]:
        if claim.publication is None:
            raise MobileUploadInvariantError("Published file evidence is missing.")
        value: dict[str, object] = {
            "eventId": claim.event_id,
            "uploadId": claim.upload_id,
            "clientAssetId": claim.client_asset_id,
            "ownerUserIri": claim.owner_user_iri,
            "stagingAreaId": claim.staging_area_id,
            "originalName": claim.original_name,
            "originalMimeType": claim.original_mime_type,
            "byteLength": claim.byte_length,
            "checksum": claim.checksum,
            "publication": claim.publication,
        }
        if claim.comment is not None:
            value["comment"] = claim.comment
        return value


def main() -> None:
    """Run the standalone mobile-media worker entry point."""

    logging.basicConfig(level=logging.INFO)
    MobileUploadWorker.from_environment().run_forever()


if __name__ == "__main__":
    main()
