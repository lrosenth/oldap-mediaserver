"""Sequential, lease-aware project-neutral ZIP export worker."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Protocol
from uuid import UUID, uuid5

from config import MediahelperSettings
from export_artifacts import (
    ExportArchiveTooLarge,
    ExportArtifactError,
    ExportArtifactStore,
    ExportManifestRejected,
    ExportSourceChanged,
)
from export_service import (
    BuildClaim,
    CleanupClaim,
    ExportClaim,
    ExportServiceClient,
    ExportServiceError,
)
from storage_capacity import PhysicalCapacityInsufficient, StorageCapacityGuard

LOGGER = logging.getLogger("oldap.export-worker")


class ExportWorkerLogger(Protocol):
    """Privacy-preserving logger interface used by the worker loop."""

    def info(self, message: str, *args: object) -> None: ...

    def warning(self, message: str, *args: object) -> None: ...


class ExportHeartbeatFailed(RuntimeError):
    """Raised when the worker can no longer prove ownership of its lease."""


@dataclass(frozen=True, slots=True)
class ExportWorkerSettings:
    """Private paths and bounded polling/heartbeat timings."""

    media_root: Path
    export_root: Path
    poll_seconds: float = 10.0
    heartbeat_seconds: float = 60.0
    storage_absolute_reserve_bytes: int = 0

    @classmethod
    def from_environment(cls) -> "ExportWorkerSettings":
        """Load the worker filesystem and timing contract from environment."""

        media = MediahelperSettings.from_environment()
        return cls(
            media_root=media.media_root,
            export_root=media.export_root,
            poll_seconds=float(os.getenv("OLDAP_EXPORT_POLL_SECONDS", "10")),
            heartbeat_seconds=float(os.getenv("OLDAP_EXPORT_HEARTBEAT_SECONDS", "60")),
            storage_absolute_reserve_bytes=media.storage_absolute_reserve_bytes,
        )

    def validate(self, *, lease_seconds: int) -> None:
        """Reject unsafe path overlap and timings before the worker starts."""

        if self.poll_seconds <= 0 or self.heartbeat_seconds <= 0:
            raise ValueError("Export worker intervals must be positive.")
        if self.heartbeat_seconds >= lease_seconds / 2:
            raise ValueError("Export heartbeat must be shorter than half the lease.")
        media = self.media_root.resolve()
        exports = self.export_root.resolve()
        if media == exports or media in exports.parents or exports in media.parents:
            raise ValueError("Export storage must be separate from media originals.")


class ClaimHeartbeat:
    """Renew one claim in the background and surface any lease loss."""

    def __init__(
        self,
        client: ExportServiceClient,
        claim: ExportClaim,
        *,
        interval_seconds: float,
        logger: ExportWorkerLogger,
    ) -> None:
        self._client = client
        self._claim = claim
        self._interval = interval_seconds
        self._logger = logger
        self._stopped = threading.Event()
        self._failed: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="export-claim-heartbeat",
            daemon=True,
        )

    def __enter__(self) -> "ClaimHeartbeat":
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self._stopped.set()
        self._thread.join(timeout=max(1.0, self._interval + 1.0))

    def raise_if_failed(self) -> None:
        """Stop work when the active lease can no longer be renewed."""

        if self._failed is not None:
            raise ExportHeartbeatFailed(
                "Export worker claim heartbeat failed."
            ) from self._failed

    def _run(self) -> None:
        while not self._stopped.wait(self._interval):
            try:
                self._client.heartbeat(self._claim)
            except BaseException as error:
                self._failed = error
                self._logger.warning(
                    "export_heartbeat_failed exportId=%s error=%s",
                    self._claim.export_id,
                    type(error).__name__,
                )
                return


class SequentialExportWorker:
    """Process at most one API-owned BUILD or CLEANUP task at a time."""

    def __init__(
        self,
        client: ExportServiceClient,
        settings: ExportWorkerSettings,
        *,
        store: ExportArtifactStore | None = None,
        logger: ExportWorkerLogger = LOGGER,
    ) -> None:
        client.validate_configuration()
        settings.validate(lease_seconds=client.lease_seconds)
        self.client = client
        self.settings = settings
        self.store = store or ExportArtifactStore(
            settings.export_root,
            settings.media_root,
            capacity_guard=StorageCapacityGuard(
                settings.storage_absolute_reserve_bytes
            ),
        )
        self.logger = logger

    def run_once(self) -> bool:
        """Claim and finish one task, returning false for an empty queue."""

        claim = self.client.claim_next()
        if claim is None:
            return False
        self.logger.info(
            "export_task_claimed exportId=%s task=%s",
            claim.export_id,
            "BUILD" if isinstance(claim, BuildClaim) else "CLEANUP",
        )
        with ClaimHeartbeat(
            self.client,
            claim,
            interval_seconds=self.settings.heartbeat_seconds,
            logger=self.logger,
        ) as heartbeat:
            if isinstance(claim, BuildClaim):
                outcome = self._build(claim, heartbeat)
            else:
                outcome = self._cleanup(claim, heartbeat)
        self.logger.info(
            "export_task_completed exportId=%s outcome=%s",
            claim.export_id,
            outcome,
        )
        return True

    def _build(self, claim: BuildClaim, heartbeat: ClaimHeartbeat) -> str:
        try:
            manifest = self.client.get_manifest(claim)
            heartbeat.raise_if_failed()
            evidence = self.store.build(
                manifest,
                claim.manifest_sha256,
                checkpoint=heartbeat.raise_if_failed,
            )
            heartbeat.raise_if_failed()
        except ExportServiceError:
            raise
        except ExportHeartbeatFailed:
            raise
        except Exception as error:
            heartbeat.raise_if_failed()
            failure_code = _failure_code(error)
            completed = datetime.now(UTC)
            result = {
                "eventId": _event_id(claim, f"BUILD:{failure_code}"),
                "claimId": claim.claim_id,
                "expectedStateVersion": claim.state_version,
                "manifestSha256": claim.manifest_sha256,
                "outcome": "FAILED",
                "completedAt": _timestamp(completed),
                "failureCode": failure_code,
                "partialArtifactsDeleted": True,
            }
            self.client.publish_build_result(claim, result)
            return "FAILED"
        result = {
            "eventId": _event_id(claim, "BUILD:READY"),
            "claimId": claim.claim_id,
            "expectedStateVersion": claim.state_version,
            "manifestSha256": claim.manifest_sha256,
            "outcome": "READY",
            "completedAt": _timestamp(evidence.completed_at),
            "archiveSizeBytes": evidence.archive_size_bytes,
            "archiveSha256": evidence.archive_sha256,
            "artifactFinalized": True,
            "partialArtifactsDeleted": True,
        }
        self.client.publish_build_result(claim, result)
        return "READY"

    def _cleanup(self, claim: CleanupClaim, heartbeat: ClaimHeartbeat) -> str:
        self.store.cleanup(claim.export_id)
        heartbeat.raise_if_failed()
        completed = datetime.now(UTC)
        result = {
            "eventId": _event_id(claim, "CLEANUP"),
            "claimId": claim.claim_id,
            "expectedStateVersion": claim.state_version,
            "completedAt": _timestamp(completed),
            "artifactDeleted": True,
        }
        self.client.publish_cleanup_result(claim, result)
        return "DELETED"


def run_forever(worker: SequentialExportWorker, stop: threading.Event) -> None:
    """Poll sequentially and delay boundedly after empty/error attempts."""

    while not stop.is_set():
        try:
            processed = worker.run_once()
        except Exception as error:
            worker.logger.warning(
                "export_worker_attempt_failed error=%s", type(error).__name__
            )
            stop.wait(worker.settings.poll_seconds)
        else:
            if not processed:
                stop.wait(worker.settings.poll_seconds)


def main() -> int:
    """Validate configuration and run the private sequential export worker."""

    logging.basicConfig(
        level=os.getenv("OLDAP_EXPORT_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    stop = threading.Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        worker = SequentialExportWorker(
            ExportServiceClient.from_environment(),
            ExportWorkerSettings.from_environment(),
        )
    except Exception as error:
        LOGGER.error(
            "export_worker_configuration_failed error=%s", type(error).__name__
        )
        return 2
    run_forever(worker, stop)
    return 0


def _failure_code(error: Exception) -> str:
    if isinstance(error, ExportSourceChanged):
        return "SOURCE_CHANGED"
    if isinstance(error, ExportArchiveTooLarge):
        return "ARCHIVE_TOO_LARGE"
    if isinstance(error, ExportManifestRejected):
        return "MANIFEST_INVALID"
    if isinstance(error, PhysicalCapacityInsufficient):
        return "STORAGE_CAPACITY"
    if isinstance(error, ExportArtifactError):
        return "ARTIFACT_FAILURE"
    return "BUILD_FAILURE"


def _event_id(claim: ExportClaim, purpose: str) -> str:
    return str(uuid5(UUID(claim.export_id), f"{claim.claim_id}:{purpose}"))


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    sys.exit(main())
