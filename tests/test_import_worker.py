"""Confirmed IMPORT worker orchestration and recovery-boundary tests."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from import_records import ImportRecordStore  # noqa: E402
from ingest_service import (  # noqa: E402
    ImportClaim,
    IngestServiceRejected,
    IngestServiceUnavailable,
)
from ingest_worker import (  # noqa: E402
    SequentialValidationWorker,
    WorkerSettings,
    _folder_commit_items,
)
from storage_capacity import (  # noqa: E402
    DiskUsage,
    PhysicalCapacityInsufficient,
    StorageCapacityGuard,
)

IMPORT_ID = "11111111-1111-4111-8111-111111111111"


class CommitItem:
    def to_commit_item(self):
        return {
            "entryIndex": 4,
            "relativePath": "A/B/note.txt",
            "parentRelativePath": "A/B",
            "assetId": "33333333-3333-4333-8333-333333333333",
            "checksumSha256": "b" * 64,
            "originalName": "note.txt",
            "originalMimeType": "text/plain",
            "dctermsType": "dcmitype:Text",
            "protocol": "http",
            "derivativeName": "document.txt",
            "storagePath": "fasnacht/document",
        }


class Assets:
    def __init__(self):
        self.prepared = self.promoted = self.compensated = 0
        self.result = SimpleNamespace(media=(CommitItem(),))

    def prepare(self, import_id, digest, manifest, extraction_root):
        self.prepared += 1
        assert import_id == IMPORT_ID
        assert manifest["validationOutcome"] == "READY"
        assert extraction_root.name == "extracted"
        return self.result

    def promote(self, prepared):
        self.promoted += 1
        assert prepared is self.result
        return self.result

    def compensate(self, promoted):
        self.compensated += 1
        assert promoted is self.result


class Client:
    lease_seconds = 300
    timeout_seconds = 10.0

    def __init__(self, claim, failure=None):
        self.claim = claim
        self.failure = failure
        self.commits = []
        self.failures = []

    def validate_configuration(self):
        return None

    def claim_next(self):
        return self.claim

    def heartbeat(self, claim):
        return datetime.now(UTC) + timedelta(minutes=5)

    def commit_import(self, claim, *, folders, media):
        self.commits.append((folders, media))
        if self.failure:
            raise self.failure("injected")
        return {"job": {"state": "IMPORTED"}}

    def publish_import_failure(self, claim, receipt):
        self.failures.append(receipt)
        return {"importId": claim.import_id, "state": "FAILED"}


class Logger:
    def info(self, *args):
        pass

    def warning(self, *args):
        pass

    def error(self, *args):
        pass


def _manifest() -> dict:
    return {
        "documentType": "oldap.zip-import.manifest",
        "schemaVersion": "1.0.0",
        "importId": IMPORT_ID,
        "validationOutcome": "READY",
        "summary": {"extractedBytes": 1},
        "entries": [
            {
                "entryIndex": 2,
                "normalizedPath": "Leer/Unterordner",
                "entryType": "directory",
                "disposition": "IMPORT",
            },
            {
                "entryIndex": 4,
                "normalizedPath": "A/B/note.txt",
                "entryType": "file",
                "disposition": "IMPORT",
            },
        ],
    }


def _worker(tmp_path: Path, failure=None):
    ingest = tmp_path / "ingest"
    (ingest / IMPORT_ID / "extracted").mkdir(parents=True)
    records = ImportRecordStore(tmp_path / "records")
    stored = records.publish(
        IMPORT_ID,
        manifest=_manifest(),
        report={
            "importId": IMPORT_ID,
            "status": "READY",
            "summary": {"compressedBytes": 1, "extractedBytes": 1},
        },
        temporary_payload_deleted=False,
    )
    claim = ImportClaim(
        claim_id="22222222-2222-4222-8222-222222222222",
        import_id=IMPORT_ID,
        state_version=4,
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        manifest_sha256=stored.manifest_sha256,
        target={
            "projectShortName": "fasnacht",
            "stagingAreaIri": "https://example.org/staging",
            "stagingAreaName": "Staging",
            "targetRootFolderIri": "https://example.org/root",
            "targetRootFolderName": "Root",
        },
    )
    client = Client(claim, failure)
    assets = Assets()
    worker = SequentialValidationWorker(
        client,
        WorkerSettings(
            ingest_root=ingest,
            records_root=records.root,
            media_root=tmp_path / "media",
            poll_seconds=1,
            heartbeat_seconds=10,
        ),
        record_store=records,
        asset_preparer=assets,
        logger=Logger(),
    )
    return worker, client, assets


def test_folder_plan_preserves_empty_and_synthesizes_omitted_parents() -> None:
    assert _folder_commit_items(_manifest()) == (
        {
            "entryIndex": 4,
            "relativePath": "A",
            "parentRelativePath": "",
            "name": "A",
        },
        {
            "entryIndex": 2,
            "relativePath": "Leer",
            "parentRelativePath": "",
            "name": "Leer",
        },
        {
            "entryIndex": 4,
            "relativePath": "A/B",
            "parentRelativePath": "A",
            "name": "B",
        },
        {
            "entryIndex": 2,
            "relativePath": "Leer/Unterordner",
            "parentRelativePath": "Leer",
            "name": "Unterordner",
        },
    )


def test_import_worker_prepares_promotes_and_commits_complete_plan(tmp_path: Path):
    worker, client, assets = _worker(tmp_path)

    assert worker.run_once() is True

    assert assets.prepared == assets.promoted == 1
    assert assets.compensated == 0
    folders, media = client.commits[0]
    assert len(folders) == 4
    assert media[0]["relativePath"] == "A/B/note.txt"


def test_import_worker_compensates_and_publishes_definitive_rejection(tmp_path: Path):
    worker, client, assets = _worker(tmp_path, IngestServiceRejected)

    assert worker.run_once() is True

    assert assets.compensated == 1
    assert client.failures[0]["failureCode"] == "IMPORT_COMMIT_REJECTED"
    assert not (worker.settings.ingest_root / IMPORT_ID).exists()


def test_import_worker_keeps_assets_after_ambiguous_api_failure(tmp_path: Path):
    worker, _, assets = _worker(tmp_path, IngestServiceUnavailable)

    with pytest.raises(IngestServiceUnavailable):
        worker.run_once()

    assert assets.compensated == 0


def test_import_worker_retries_ambiguous_commit_without_compensation(
    tmp_path: Path,
):
    """Lease replay reaches success while preserving potentially committed assets."""

    worker, client, assets = _worker(tmp_path, IngestServiceUnavailable)
    with pytest.raises(IngestServiceUnavailable):
        worker.run_once()
    client.failure = None

    assert worker.run_once() is True
    assert assets.prepared == assets.promoted == 2
    assert assets.compensated == 0
    assert len(client.commits) == 2


def test_import_worker_blocks_before_asset_writes_under_disk_pressure(
    tmp_path: Path,
):
    """A retryable physical-capacity block creates no final or work assets."""

    worker, client, assets = _worker(tmp_path)
    worker.capacity = StorageCapacityGuard(
        disk_usage=lambda path: DiskUsage(total=100, used=80, free=20)
    )

    with pytest.raises(PhysicalCapacityInsufficient):
        worker.run_once()

    assert assets.prepared == assets.promoted == assets.compensated == 0
    assert client.commits == []


def test_retained_failure_receipt_republishes_without_assets_or_payload(tmp_path: Path):
    worker, client, assets = _worker(tmp_path)
    worker.records.publish_import_failure(IMPORT_ID, "IMPORT_COMMIT_REJECTED")
    worker._delete_temporary_payload(IMPORT_ID)

    assert worker.run_once() is True

    assert len(client.failures) == 1
    assert assets.prepared == assets.promoted == assets.compensated == 0
