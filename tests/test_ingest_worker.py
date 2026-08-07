"""Sequential worker, cleanup ordering, and crash-replay tests."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from import_records import ImportRecordStore  # noqa: E402
from ingest_service import (
    CleanupClaim,
    TargetPreflightFinding,
    ValidationClaim,
)  # noqa: E402
from ingest_worker import (  # noqa: E402
    SequentialValidationWorker,
    WorkerSettings,
    _terminate_analysis_process,
)
from storage_capacity import (  # noqa: E402
    DiskUsage,
    PhysicalCapacityInsufficient,
    StorageCapacityGuard,
)
from zip_validation import ZipStructureValidator  # noqa: E402

IMPORT_ID = "11111111-1111-4111-8111-111111111111"


def _validate_records(manifest: dict, report: dict) -> None:
    schema_root = Path(__file__).resolve().parents[1] / "docs" / "zip-import" / "v1"
    schemas = [
        json.loads((schema_root / name).read_text(encoding="utf-8"))
        for name in ("common.schema.json", "manifest.schema.json", "report.schema.json")
    ]
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
    )
    Draft202012Validator(
        schemas[1], registry=registry, format_checker=FormatChecker()
    ).validate(manifest)
    Draft202012Validator(
        schemas[2], registry=registry, format_checker=FormatChecker()
    ).validate(report)


def _validate_report(report: dict) -> None:
    schema_root = Path(__file__).resolve().parents[1] / "docs" / "zip-import" / "v1"
    schemas = [
        json.loads((schema_root / name).read_text(encoding="utf-8"))
        for name in ("common.schema.json", "report.schema.json")
    ]
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
    )
    Draft202012Validator(
        schemas[1], registry=registry, format_checker=FormatChecker()
    ).validate(report)


class FakeClient:
    lease_seconds = 300
    timeout_seconds = 10.0

    def __init__(self, claim: ValidationClaim):
        self.claim = claim
        self.published = []
        self.preflight_entries = []
        self.preflight_findings = ()
        self.fail_publish_once = False
        self.fail_cleanup_publish_once = False
        self.cleanup_results = []

    def validate_configuration(self):
        return None

    def claim_validation(self):
        return self.claim

    def claim_next(self):
        return self.claim

    def heartbeat(self, claim):
        return datetime.now(UTC)

    def preflight_target(self, claim, top_level_entries, *, timeout_seconds=None):
        assert timeout_seconds is not None and 0 < timeout_seconds <= 10
        self.preflight_entries.append(top_level_entries)
        return self.preflight_findings

    def __getstate__(self):
        raise AssertionError("The API client must never enter the parser process.")

    def publish_validation_result(self, claim, **kwargs):
        if self.fail_publish_once:
            self.fail_publish_once = False
            raise RuntimeError("lost API connection")
        assert (self.ingest_root / claim.import_id).exists() is (
            not kwargs["temporary_payload_deleted"]
        )
        self.published.append(kwargs)
        return {"importId": claim.import_id, "state": kwargs["outcome"]}

    def publish_cleanup_result(self, claim):
        assert not (self.ingest_root / claim.import_id).exists()
        if self.fail_cleanup_publish_once:
            self.fail_cleanup_publish_once = False
            raise RuntimeError("lost cleanup acknowledgement")
        self.cleanup_results.append(claim.cleanup_reason)
        return {
            "importId": claim.import_id,
            "state": claim.cleanup_reason,
            "cleanupPending": False,
        }


class Logger:
    def __init__(self):
        self.warnings = []

    def info(self, *args):
        pass

    def warning(self, *args):
        self.warnings.append(args)

    def error(self, *args):
        pass


def _fixture(tmp_path: Path, *, entries=None, validation_timeout_seconds=21_600.0):
    ingest_root = tmp_path / "ingest"
    job = ingest_root / IMPORT_ID
    job.mkdir(parents=True)
    sip = job / "sip.zip"
    with zipfile.ZipFile(sip, "w") as archive:
        for name, content in entries or [("../escape.jpg", b"unsafe")]:
            archive.writestr(name, content)
    content = sip.read_bytes()
    claim = ValidationClaim(
        claim_id="22222222-2222-4222-8222-222222222222",
        import_id=IMPORT_ID,
        state_version=2,
        lease_expires_at=datetime(2026, 8, 5, 0, 5, tzinfo=UTC),
        job_created_at="2026-08-04T23:00:00Z",
        requested_by_iri="https://example.org/users/alice",
        original_file_name="unsafe.zip",
        compressed_size_bytes=len(content),
        sip_sha256=hashlib.sha256(content).hexdigest(),
        target={
            "projectShortName": "fasnacht",
            "stagingAreaIri": "https://example.org/staging",
            "stagingAreaName": "Staging",
            "targetRootFolderIri": "https://example.org/root",
            "targetRootFolderName": "Root",
        },
    )
    client = FakeClient(claim)
    client.ingest_root = ingest_root
    settings = WorkerSettings(
        ingest_root=ingest_root,
        records_root=tmp_path / "records",
        media_root=tmp_path / "media",
        poll_seconds=1,
        heartbeat_seconds=10,
        validation_timeout_seconds=validation_timeout_seconds,
    )
    worker = SequentialValidationWorker(client, settings, logger=Logger())
    return worker, client, job


def test_validation_timeout_cannot_broaden_frozen_policy(tmp_path: Path) -> None:
    settings = WorkerSettings(
        ingest_root=tmp_path / "ingest",
        records_root=tmp_path / "records",
        media_root=tmp_path / "media",
        heartbeat_seconds=10,
        validation_timeout_seconds=21_601,
    )

    try:
        settings.validate(lease_seconds=300)
    except ValueError as error:
        assert "frozen policy" in str(error)
    else:
        raise AssertionError("A deployment must not broaden the reviewed deadline.")


def test_invalid_payload_is_deleted_before_api_publication(tmp_path: Path) -> None:
    worker, client, job = _fixture(tmp_path)

    assert worker.run_once()

    assert not job.exists()
    assert client.published[0]["outcome"] == "INVALID"
    assert client.published[0]["temporary_payload_deleted"] is True
    assert ImportRecordStore(worker.settings.records_root).load_result(IMPORT_ID)


def test_validation_capacity_pressure_is_retryable_before_extraction(
    tmp_path: Path,
) -> None:
    """Disk pressure retains the SIP and emits privacy-safe operator facts."""

    worker, client, job = _fixture(tmp_path)
    worker.capacity = StorageCapacityGuard(
        disk_usage=lambda path: DiskUsage(total=100, used=80, free=20)
    )

    with pytest.raises(PhysicalCapacityInsufficient):
        worker.run_once()

    assert job.exists()
    assert not (job / "extracted").exists()
    assert client.published == []
    message, *facts = worker.logger.warnings[0]
    assert message.startswith("ingest_capacity_blocked importId=%s phase=%s")
    assert facts[0:2] == [IMPORT_ID, "VALIDATE"]


def test_api_claimed_cleanup_deletes_payload_but_retains_records(
    tmp_path: Path,
) -> None:
    worker, client, job = _fixture(tmp_path)
    retained = worker.settings.records_root / IMPORT_ID
    retained.mkdir(parents=True)
    (retained / "report.json").write_text('{"retained":true}', encoding="utf-8")
    client.claim = CleanupClaim(
        claim_id="22222222-2222-4222-8222-222222222222",
        import_id=IMPORT_ID,
        state_version=4,
        lease_expires_at=datetime(2026, 8, 5, 0, 5, tzinfo=UTC),
        cleanup_reason="EXPIRED",
    )

    assert worker.run_once()

    assert not job.exists()
    assert (retained / "report.json").is_file()
    assert client.cleanup_results == ["EXPIRED"]


def test_cleanup_recovers_after_deletion_when_api_acknowledgement_is_lost(
    tmp_path: Path,
) -> None:
    """A reclaimed cleanup succeeds even when its payload is already absent."""

    worker, client, job = _fixture(tmp_path)
    retained = worker.settings.records_root / IMPORT_ID
    retained.mkdir(parents=True)
    (retained / "manifest.json").write_text('{"retained":true}', encoding="utf-8")
    client.claim = CleanupClaim(
        claim_id="22222222-2222-4222-8222-222222222222",
        import_id=IMPORT_ID,
        state_version=4,
        lease_expires_at=datetime(2026, 8, 5, 0, 5, tzinfo=UTC),
        cleanup_reason="IMPORTED",
    )
    client.fail_cleanup_publish_once = True

    with pytest.raises(RuntimeError, match="acknowledgement"):
        worker.run_once()

    assert not job.exists()
    assert (retained / "manifest.json").is_file()
    assert client.cleanup_results == []

    # Represents the API reclaiming the same idempotent task after lease expiry.
    client.claim = CleanupClaim(
        claim_id="33333333-3333-4333-8333-333333333333",
        import_id=IMPORT_ID,
        state_version=5,
        lease_expires_at=datetime(2026, 8, 5, 0, 10, tzinfo=UTC),
        cleanup_reason="IMPORTED",
    )
    assert worker.run_once()
    assert client.cleanup_results == ["IMPORTED"]


def test_retained_result_recovers_after_api_failure_without_sip(tmp_path: Path) -> None:
    worker, client, job = _fixture(tmp_path)
    client.fail_publish_once = True

    try:
        worker.run_once()
    except RuntimeError:
        pass
    else:
        raise AssertionError("The injected API failure must escape the attempt.")
    assert not job.exists()
    assert ImportRecordStore(worker.settings.records_root).load_result(IMPORT_ID)

    assert worker.run_once()
    assert client.published[0]["outcome"] == "INVALID"


def test_content_valid_text_is_ready_and_payload_is_retained(tmp_path: Path) -> None:
    worker, client, job = _fixture(
        tmp_path, entries=[("folder/notes.txt", "Basler Fasnacht\n".encode())]
    )

    assert worker.run_once()

    assert job.exists()
    assert (job / "sip.zip").exists()
    assert (job / "extracted" / "folder" / "notes.txt").exists()
    assert client.published[0]["outcome"] == "READY"
    assert client.published[0]["temporary_payload_deleted"] is False
    manifest = json.loads(
        (worker.settings.records_root / IMPORT_ID / "manifest.json").read_text()
    )
    report = json.loads(
        (worker.settings.records_root / IMPORT_ID / "report.json").read_text()
    )
    assert manifest["validationOutcome"] == "READY"
    assert client.preflight_entries == [
        ({"entryIndex": 0, "name": "folder", "entryType": "directory"},)
    ]
    assert "expiresAt" in report
    _validate_records(manifest, report)


def test_target_folder_collision_is_invalid_and_deletes_payload(tmp_path: Path) -> None:
    worker, client, job = _fixture(
        tmp_path, entries=[("folder/notes.txt", b"Basler Fasnacht\n")]
    )
    client.preflight_findings = (
        TargetPreflightFinding(
            code="TARGET_FOLDER_COLLISION",
            blocking=True,
            entry_index=0,
            existing_kind="folder",
            existing_name="Folder",
        ),
    )

    assert worker.run_once()

    assert not job.exists()
    assert client.published[0]["outcome"] == "INVALID"
    report = json.loads(
        (worker.settings.records_root / IMPORT_ID / "report.json").read_text()
    )
    assert report["entries"][0]["issues"][0]["code"] == "TARGET_FOLDER_COLLISION"
    _validate_records(
        json.loads(
            (worker.settings.records_root / IMPORT_ID / "manifest.json").read_text()
        ),
        report,
    )


def test_existing_media_name_is_a_ready_warning(tmp_path: Path) -> None:
    worker, client, job = _fixture(
        tmp_path, entries=[("notes.txt", b"Basler Fasnacht\n")]
    )
    client.preflight_findings = (
        TargetPreflightFinding(
            code="TARGET_MEDIA_NAME_COLLISION",
            blocking=False,
            entry_index=0,
            existing_kind="media",
            existing_name="Notes.txt",
        ),
    )

    assert worker.run_once()

    assert job.exists()
    assert client.published[0]["outcome"] == "READY"
    report = json.loads(
        (worker.settings.records_root / IMPORT_ID / "report.json").read_text()
    )
    assert report["summary"]["warningCount"] == 1
    assert report["entries"][0]["issues"][0]["blocking"] is False


class SlowValidator:
    """Block long enough for the hard process deadline to interrupt it."""

    def validate_and_extract(self, sip_path, work_root):
        del sip_path, work_root
        time.sleep(1)
        raise AssertionError("The process deadline did not interrupt validation.")


class EnvironmentAssertingValidator:
    """Prove the child sees only the closed non-secret environment."""

    def validate_and_extract(self, sip_path, work_root):
        assert set(os.environ) == {"PATH", "LANG", "LC_ALL", "HOME"}
        assert "OLDAP_IMPORT_SERVICE_JWT_SECRET" not in os.environ
        return ZipStructureValidator().validate_and_extract(sip_path, work_root)


def test_parser_child_receives_no_client_or_secret_environment(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("OLDAP_IMPORT_SERVICE_JWT_SECRET", "s" * 64)
    monkeypatch.setenv("UNRELATED_PARENT_SECRET", "must-not-cross")
    worker, client, job = _fixture(
        tmp_path, entries=[("notes.txt", b"Basler Fasnacht\n")]
    )
    worker.validator = EnvironmentAssertingValidator()

    assert worker.run_once()

    assert job.exists()
    assert client.published[0]["outcome"] == "READY"


def _process_group_with_descendant(started, descendant_marker: str) -> None:
    """Create a process group containing a child that would outlive its leader."""

    os.setsid()
    subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import pathlib,sys,time; time.sleep(0.5); "
                "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
            ),
            descendant_marker,
        ],
        close_fds=True,
    )
    started.set()
    time.sleep(10)


def test_timeout_termination_kills_decoder_descendants(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    started = context.Event()
    marker = tmp_path / "descendant-survived"
    process = context.Process(
        target=_process_group_with_descendant,
        args=(started, str(marker)),
    )
    process.start()
    try:
        assert started.wait(5)
        _terminate_analysis_process(process, process_group_ready=True)
        time.sleep(0.75)
        assert not marker.exists()
    finally:
        if process.is_alive():
            process.kill()
            process.join()
        process.close()


def test_validation_timeout_deletes_payload_and_replays_failed_result(
    tmp_path: Path,
) -> None:
    worker, client, job = _fixture(
        tmp_path,
        entries=[("notes.txt", b"Basler Fasnacht\n")],
        validation_timeout_seconds=0.01,
    )
    worker.validator = SlowValidator()
    client.fail_publish_once = True

    try:
        worker.run_once()
    except RuntimeError:
        pass
    else:
        raise AssertionError("The injected API failure must escape the attempt.")

    assert not job.exists()
    result = ImportRecordStore(worker.settings.records_root).load_result(IMPORT_ID)
    assert result.outcome == "FAILED"
    assert result.manifest_sha256 is None
    assert result.failure_code == "VALIDATION_TIMEOUT"
    report = json.loads(
        (worker.settings.records_root / IMPORT_ID / "report.json").read_text()
    )
    assert report["status"] == "FAILED"
    assert report["issues"][0]["code"] == "VALIDATION_TIMEOUT"
    _validate_report(report)
    assert not (worker.settings.records_root / IMPORT_ID / "manifest.json").exists()

    assert worker.run_once()
    assert client.published[0]["outcome"] == "FAILED"
    assert client.published[0]["manifest_sha256"] is None
    assert client.published[0]["failure_code"] == "VALIDATION_TIMEOUT"
