"""Behaviour tests for the sequential export worker."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mediaserver"))

from export_artifacts import ExportBuildEvidence, ExportSourceChanged  # noqa: E402
from export_service import BuildClaim, CleanupClaim  # noqa: E402
from export_worker import ExportWorkerSettings, SequentialExportWorker  # noqa: E402

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
EXPORT_ID = "11111111-1111-4111-8111-111111111111"
CLAIM_ID = "22222222-2222-4222-8222-222222222222"


class Client:
    """In-memory control-plane fake."""

    lease_seconds = 300

    def __init__(self, claim: object):
        self.claim = claim
        self.build_results: list[dict[str, object]] = []
        self.cleanup_results: list[dict[str, object]] = []

    def validate_configuration(self) -> None:
        return None

    def claim_next(self) -> object:
        return self.claim

    def heartbeat(self, claim: object) -> datetime:
        return NOW + timedelta(minutes=5)

    def get_manifest(self, claim: object) -> dict[str, object]:
        return {"exportId": EXPORT_ID}

    def publish_build_result(self, claim: object, result: dict[str, object]) -> None:
        self.build_results.append(result)

    def publish_cleanup_result(self, claim: object, result: dict[str, object]) -> None:
        self.cleanup_results.append(result)


class Store:
    """In-memory artifact-store fake."""

    def __init__(self, error: Exception | None = None):
        self.error = error
        self.cleaned: list[str] = []

    def build(
        self, manifest: object, digest: str, *, checkpoint=None
    ) -> ExportBuildEvidence:
        if checkpoint is not None:
            checkpoint()
        if self.error:
            raise self.error
        return ExportBuildEvidence(EXPORT_ID, digest, 123, "b" * 64, NOW)

    def cleanup(self, export_id: str) -> None:
        self.cleaned.append(export_id)


def settings(tmp_path: Path) -> ExportWorkerSettings:
    return ExportWorkerSettings(tmp_path / "media", tmp_path / "exports", 1, 60)


def test_build_reports_closed_ready_evidence(tmp_path: Path) -> None:
    claim = BuildClaim(
        CLAIM_ID, EXPORT_ID, 4, NOW, NOW + timedelta(minutes=5), "a" * 64
    )
    client = Client(claim)
    worker = SequentialExportWorker(client, settings(tmp_path), store=Store())

    assert worker.run_once() is True
    result = client.build_results[0]
    assert result["outcome"] == "READY"
    assert result["archiveSizeBytes"] == 123
    assert result["artifactFinalized"] is True


def test_source_change_reports_failed_without_ready_artifact(tmp_path: Path) -> None:
    claim = BuildClaim(
        CLAIM_ID, EXPORT_ID, 4, NOW, NOW + timedelta(minutes=5), "a" * 64
    )
    client = Client(claim)
    worker = SequentialExportWorker(
        client,
        settings(tmp_path),
        store=Store(ExportSourceChanged("changed")),
    )

    assert worker.run_once() is True
    assert client.build_results[0]["failureCode"] == "SOURCE_CHANGED"
    assert client.build_results[0]["partialArtifactsDeleted"] is True


def test_cleanup_is_claim_bound_and_idempotent(tmp_path: Path) -> None:
    claim = CleanupClaim(
        CLAIM_ID, EXPORT_ID, 8, NOW, NOW + timedelta(minutes=5), "EXPIRED"
    )
    client = Client(claim)
    store = Store()
    worker = SequentialExportWorker(client, settings(tmp_path), store=store)

    assert worker.run_once() is True
    assert store.cleaned == [EXPORT_ID]
    assert client.cleanup_results[0]["artifactDeleted"] is True
