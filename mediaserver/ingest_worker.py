"""Sequential, lease-aware ZIP validation worker entry point."""

from __future__ import annotations

import hashlib
import logging
import multiprocessing
import os
import shutil
import signal
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Protocol

from config import MediahelperSettings, ZipImportLimits
from content_validation import (
    ContentEntryResult,
    ContentIssue,
    ContentValidationResult,
    ContentValidator,
)
from import_assets import ImportAssetPreparer
from import_records import ImportRecordStore, StoredValidationRecords
from ingest_service import (
    CleanupClaim,
    ImportClaim,
    ImportServiceClient,
    IngestServiceError,
    IngestServiceRejected,
    TargetPreflightFinding,
    ValidationClaim,
    WorkerClaim,
)
from parser_sandbox import ParserSandbox
from storage_capacity import (
    PhysicalCapacityInsufficient,
    StorageCapacityGuard,
    import_asset_bytes,
    potential_extracted_bytes,
)
from validation_documents import (
    build_content_documents,
    build_structural_invalid_documents,
    build_validation_timeout_report,
    component_version,
)
from zip_validation import ZipStructureValidator, ZipValidationResult


LOGGER = logging.getLogger("oldap.ingest-worker")
VALIDATION_TIMEOUT_FAILURE_CODE = "VALIDATION_TIMEOUT"


class ValidationAnalysisError(RuntimeError):
    """Raised when the isolated analysis process fails without a user outcome."""


class WorkerLogger(Protocol):
    """Privacy-preserving logging interface used by the worker loop."""

    def info(self, message: str, *args: object) -> None: ...

    def warning(self, message: str, *args: object) -> None: ...

    def error(self, message: str, *args: object) -> None: ...


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    """Runtime paths and bounded polling/lease timing for one worker process."""

    ingest_root: Path
    records_root: Path
    media_root: Path
    poll_seconds: float = 10.0
    heartbeat_seconds: float = 60.0
    validation_timeout_seconds: float = 21_600.0
    parser_sandbox: ParserSandbox = field(default_factory=ParserSandbox)
    storage_absolute_reserve_bytes: int = 0

    @classmethod
    def from_environment(cls) -> "WorkerSettings":
        media = MediahelperSettings.from_environment()
        return cls(
            ingest_root=media.ingest_root,
            records_root=media.import_records_root,
            media_root=media.media_root,
            poll_seconds=float(os.getenv("OLDAP_INGEST_POLL_SECONDS", "10")),
            heartbeat_seconds=float(os.getenv("OLDAP_INGEST_HEARTBEAT_SECONDS", "60")),
            parser_sandbox=ParserSandbox.production(),
            storage_absolute_reserve_bytes=media.storage_absolute_reserve_bytes,
        )

    def validate(self, *, lease_seconds: int) -> None:
        if self.poll_seconds <= 0 or self.heartbeat_seconds <= 0:
            raise ValueError("Worker intervals must be positive.")
        if self.storage_absolute_reserve_bytes < 0:
            raise ValueError("Storage absolute reserve must not be negative.")
        if (
            not 0
            < self.validation_timeout_seconds
            <= ZipImportLimits().max_validation_seconds
        ):
            raise ValueError("Validation timeout exceeds the frozen policy limit.")
        if self.heartbeat_seconds >= lease_seconds / 2:
            raise ValueError("Heartbeat interval must be below half the lease.")
        if self.records_root == self.ingest_root or self.records_root.is_relative_to(
            self.ingest_root
        ):
            raise ValueError(
                "Retained records must be outside temporary ingest storage."
            )
        if self.media_root in {self.ingest_root, self.records_root}:
            raise ValueError("Final media storage must have a distinct root.")
        self.parser_sandbox.validate_runtime()


class ClaimHeartbeat:
    """Renew a claim on a dedicated thread while validation blocks."""

    def __init__(
        self,
        client: ImportServiceClient,
        claim: WorkerClaim,
        *,
        interval_seconds: float,
        logger: WorkerLogger,
    ) -> None:
        self._client = client
        self._claim = claim
        self._interval = interval_seconds
        self._logger = logger
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="ingest-claim-heartbeat",
            daemon=True,
        )

    def __enter__(self) -> "ClaimHeartbeat":
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self._interval + 1.0))

    def raise_if_failed(self) -> None:
        """Prevent result publication after lease renewal became uncertain."""

        if self._failure is not None:
            raise IngestServiceError(
                "Import worker claim heartbeat failed."
            ) from self._failure

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._client.heartbeat(self._claim)
            except BaseException as error:  # thread transfers failure to owner
                self._failure = error
                self._logger.warning(
                    "ingest_heartbeat_failed importId=%s error=%s",
                    self._claim.import_id,
                    type(error).__name__,
                )
                return


class SequentialValidationWorker:
    """Claim and execute one validation, import, or cleanup task at a time."""

    def __init__(
        self,
        client: ImportServiceClient,
        settings: WorkerSettings,
        *,
        record_store: ImportRecordStore | None = None,
        validator: ZipStructureValidator | None = None,
        content_validator: ContentValidator | None = None,
        asset_preparer: ImportAssetPreparer | None = None,
        capacity_guard: StorageCapacityGuard | None = None,
        logger: WorkerLogger = LOGGER,
    ) -> None:
        client.validate_configuration()
        settings.validate(lease_seconds=client.lease_seconds)
        self.client = client
        self.settings = settings
        self.records = record_store or ImportRecordStore(settings.records_root)
        self.validator = validator or ZipStructureValidator()
        self.content_validator = content_validator or ContentValidator()
        self.assets = asset_preparer or ImportAssetPreparer(settings.media_root)
        self.capacity = capacity_guard or StorageCapacityGuard(
            settings.storage_absolute_reserve_bytes
        )
        self.logger = logger

    def run_once(self) -> bool:
        """Claim and process one task, returning false when the queue is empty."""

        claim = self.client.claim_next()
        if claim is None:
            return False
        self.logger.info("ingest_claimed importId=%s", claim.import_id)
        with ClaimHeartbeat(
            self.client,
            claim,
            interval_seconds=self.settings.heartbeat_seconds,
            logger=self.logger,
        ) as heartbeat:
            if isinstance(claim, CleanupClaim):
                outcome = self._cleanup(claim, heartbeat)
            elif isinstance(claim, ImportClaim):
                outcome = self._import(claim, heartbeat)
            else:
                outcome = self._run_validation(claim, heartbeat)
        self.logger.info(
            "ingest_task_published importId=%s outcome=%s",
            claim.import_id,
            outcome,
        )
        return True

    def _run_validation(self, claim: ValidationClaim, heartbeat: ClaimHeartbeat) -> str:
        """Execute and publish one leased validation task."""

        retained = self.records.load_result(claim.import_id)
        if retained is None:
            retained = self._validate(claim)
        if retained.temporary_payload_deleted:
            self._delete_temporary_payload(claim.import_id)
        heartbeat.raise_if_failed()
        self.client.publish_validation_result(
            claim,
            outcome=retained.outcome,
            manifest_sha256=retained.manifest_sha256,
            report_sha256=retained.report_sha256,
            summary=retained.summary,
            temporary_payload_deleted=retained.temporary_payload_deleted,
            failure_code=retained.failure_code,
        )
        heartbeat.raise_if_failed()
        return retained.outcome

    def _import(self, claim: ImportClaim, heartbeat: ClaimHeartbeat) -> str:
        """Promote verified assets and submit the atomic staging batch commit.

        A definite API rejection compensates the exact promoted asset set. A
        transport/5xx/receipt ambiguity deliberately leaves owner-marked assets
        in place so a later deterministic replay can establish commit outcome.
        """

        failure = self.records.load_import_failure(claim.import_id)
        if failure is not None:
            self.client.publish_import_failure(claim, failure)
            return "FAILED"
        manifest = self.records.read_manifest(claim.import_id, claim.manifest_sha256)
        extraction_root = self.settings.ingest_root / claim.import_id / "extracted"
        extracted_bytes = _manifest_extracted_bytes(manifest)
        self._require_capacity(
            claim.import_id,
            "IMPORT",
            self.settings.media_root,
            import_asset_bytes(extracted_bytes),
        )
        prepared = self.assets.prepare(
            claim.import_id,
            claim.manifest_sha256,
            manifest,
            extraction_root,
        )
        heartbeat.raise_if_failed()
        promoted = self.assets.promote(prepared)
        heartbeat.raise_if_failed()
        try:
            self.client.commit_import(
                claim,
                folders=_folder_commit_items(manifest),
                media=tuple(item.to_commit_item() for item in promoted.media),
            )
        except IngestServiceRejected:
            self.assets.compensate(promoted)
            self._delete_temporary_payload(claim.import_id)
            failure = self.records.publish_import_failure(
                claim.import_id, "IMPORT_COMMIT_REJECTED"
            )
            self.client.publish_import_failure(claim, failure)
            return "FAILED"
        return "IMPORTED"

    def _cleanup(self, claim: CleanupClaim, heartbeat: ClaimHeartbeat) -> str:
        """Delete only API-claimed temporary payload and publish exact proof.

        Immutable report/manifest records live under ``records_root`` and are
        intentionally outside this deletion boundary.
        """

        self._delete_temporary_payload(claim.import_id)
        heartbeat.raise_if_failed()
        self.client.publish_cleanup_result(claim)
        return claim.cleanup_reason

    def _validate(self, claim: ValidationClaim) -> StoredValidationRecords:
        quarantine = self.settings.ingest_root / claim.import_id
        sip_path = quarantine / "sip.zip"
        deadline = time.monotonic() + self.settings.validation_timeout_seconds
        try:
            self._require_capacity(
                claim.import_id,
                "VALIDATE",
                self.settings.ingest_root,
                potential_extracted_bytes(
                    claim.compressed_size_bytes,
                    maximum_bytes=ZipImportLimits().max_extracted_bytes,
                ),
            )
            self.settings.parser_sandbox.validate_paths(
                self.settings.ingest_root, quarantine, sip_path
            )
            self._verify_sip(claim, sip_path)
            workspace = self.settings.parser_sandbox.prepare(
                self.settings.ingest_root, quarantine, sip_path
            )
            try:
                analysis = _run_analysis_process(
                    validator=self.validator,
                    content_validator=self.content_validator,
                    sandbox=self.settings.parser_sandbox,
                    sip_path=sip_path,
                    work_root=workspace.extraction_root,
                    timeout_seconds=_remaining_seconds(deadline),
                )
            finally:
                self.settings.parser_sandbox.seal_input(quarantine, sip_path)
            if isinstance(analysis, ContentValidationResult):
                content = analysis
                if content.accepted:
                    top_level_entries = _top_level_entries(content)
                    try:
                        findings = self.client.preflight_target(
                            claim,
                            top_level_entries,
                            timeout_seconds=min(
                                self.client.timeout_seconds,
                                _remaining_seconds(deadline),
                            ),
                        )
                    except IngestServiceError as error:
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "Validation analysis exceeded its deadline."
                            ) from error
                        raise
                    content = _apply_target_findings(
                        content, findings, top_level_entries
                    )
                if content.accepted:
                    extraction_root = self.settings.parser_sandbox.promote(workspace)
                    content = replace(
                        content,
                        structural=replace(
                            content.structural,
                            extraction_root=extraction_root,
                        ),
                    )
                documents = build_content_documents(
                    claim,
                    content,
                    component_version=component_version(),
                    limits=ZipImportLimits(),
                )
                temporary_payload_deleted = not content.accepted
            else:
                documents = build_structural_invalid_documents(
                    claim,
                    analysis,
                    component_version=component_version(),
                    limits=ZipImportLimits(),
                )
                temporary_payload_deleted = True
            _remaining_seconds(deadline)
        except TimeoutError:
            retained = self.records.publish_failure(
                claim.import_id,
                report=build_validation_timeout_report(claim),
                failure_code=VALIDATION_TIMEOUT_FAILURE_CODE,
            )
            self._delete_temporary_payload(claim.import_id)
            return retained
        retained = self.records.publish(
            claim.import_id,
            manifest=documents.manifest,
            report=documents.report,
            temporary_payload_deleted=temporary_payload_deleted,
        )
        if temporary_payload_deleted:
            self._delete_temporary_payload(claim.import_id)
        return retained

    def _require_capacity(
        self,
        import_id: str,
        phase: str,
        path: Path,
        additional_bytes: int,
    ) -> None:
        """Reject one phase safely and log only non-sensitive capacity facts."""

        path.mkdir(parents=True, exist_ok=True)
        try:
            self.capacity.require(path, additional_bytes=additional_bytes)
        except PhysicalCapacityInsufficient as error:
            facts = error.snapshot
            self.logger.warning(
                "ingest_capacity_blocked importId=%s phase=%s "
                "requiredBytes=%d freeBytes=%d reserveBytes=%d",
                import_id,
                phase,
                facts.required_bytes,
                facts.free_bytes,
                facts.reserve_bytes,
            )
            raise

    def _delete_temporary_payload(self, import_id: str) -> None:
        """Delete only the canonical job-owned quarantine directory."""

        quarantine = self.settings.ingest_root / import_id
        if not quarantine.exists() and not quarantine.is_symlink():
            return
        if quarantine.is_symlink() or not quarantine.is_dir():
            raise OSError("Temporary payload path is not a safe directory.")
        resolved_root = self.settings.ingest_root.resolve()
        if quarantine.resolve().parent != resolved_root:
            raise OSError("Temporary payload path escapes ingest root.")
        shutil.rmtree(quarantine)
        if quarantine.exists():
            raise OSError("Temporary payload could not be deleted.")

    @staticmethod
    def _verify_sip(claim: ValidationClaim, sip_path: Path) -> None:
        if not sip_path.is_file() or sip_path.is_symlink():
            raise OSError("Claimed SIP is unavailable.")
        digest = hashlib.sha256()
        size = 0
        with sip_path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
        if (
            size != claim.compressed_size_bytes
            or digest.hexdigest() != claim.sip_sha256
        ):
            raise OSError("Claimed SIP does not match API receipt.")


def _run_analysis_process(
    *,
    validator: ZipStructureValidator,
    content_validator: ContentValidator,
    sandbox: ParserSandbox,
    sip_path: Path,
    work_root: Path,
    timeout_seconds: float,
) -> ContentValidationResult | ZipValidationResult:
    """Run parser-heavy analysis under a parent-enforced wall-clock deadline."""

    context = multiprocessing.get_context("spawn")
    receive_connection, send_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_analysis_process_main,
        args=(
            send_connection,
            validator,
            content_validator,
            sandbox,
            sip_path,
            work_root,
        ),
        name=f"ingest-analysis-{sip_path.parent.name}",
    )
    deadline = time.monotonic() + timeout_seconds
    process_group_ready = False
    try:
        process.start()
    except BaseException:
        receive_connection.close()
        send_connection.close()
        process.close()
        raise
    send_connection.close()
    try:
        ready = _receive_analysis_message(receive_connection, process, deadline)
        if ready != ("READY",):
            raise ValidationAnalysisError("Analysis process handshake is invalid.")
        process_group_ready = True
        message = _receive_analysis_message(receive_connection, process, deadline)
        if not isinstance(message, tuple) or not message:
            raise ValidationAnalysisError("Analysis process response is invalid.")
        if message[0] == "ERROR":
            error_name = message[1] if len(message) == 2 else "UnknownError"
            raise ValidationAnalysisError(f"Analysis process failed with {error_name}.")
        if (
            len(message) != 2
            or message[0] != "RESULT"
            or not isinstance(
                message[1], (ContentValidationResult, ZipValidationResult)
            )
        ):
            raise ValidationAnalysisError("Analysis process result is invalid.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Validation analysis exceeded its deadline.")
        process.join(timeout=remaining)
        if process.is_alive():
            raise TimeoutError("Validation analysis exceeded its deadline.")
        if process.exitcode != 0:
            raise ValidationAnalysisError("Analysis process did not exit cleanly.")
        return message[1]
    except TimeoutError:
        _terminate_analysis_process(process, process_group_ready=process_group_ready)
        raise
    finally:
        receive_connection.close()
        if process.is_alive():
            _terminate_analysis_process(
                process, process_group_ready=process_group_ready
            )
        process.close()


def _receive_analysis_message(
    connection: Connection,
    process: multiprocessing.Process,
    deadline: float,
) -> object:
    """Receive one child message while enforcing a monotonic deadline."""

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Validation analysis exceeded its deadline.")
        if connection.poll(min(remaining, 0.1)):
            try:
                return connection.recv()
            except EOFError as error:
                raise ValidationAnalysisError(
                    "Analysis process closed its result channel."
                ) from error
        if not process.is_alive():
            process.join()
            raise ValidationAnalysisError("Analysis process exited unexpectedly.")


def _terminate_analysis_process(
    process: multiprocessing.Process,
    *,
    process_group_ready: bool,
) -> None:
    """Terminate the analysis process and any decoder children it started."""

    if process.is_alive():
        if process_group_ready and process.pid is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
    if process.is_alive():
        raise ValidationAnalysisError("Analysis process could not be terminated.")


def _analysis_process_main(
    connection: Connection,
    validator: ZipStructureValidator,
    content_validator: ContentValidator,
    sandbox: ParserSandbox,
    sip_path: Path,
    work_root: Path,
) -> None:
    """Perform one complete analysis in an isolated process group."""

    try:
        os.setsid()
        sandbox.enter_child()
        connection.send(("READY",))
        result = validator.validate_and_extract(sip_path, work_root)
        if result.accepted:
            result = content_validator.validate(result)
        connection.send(("RESULT", result))
    except BaseException as error:
        try:
            connection.send(("ERROR", type(error).__name__))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()


def _remaining_seconds(deadline: float) -> float:
    """Return positive remaining wall time or raise the terminal timeout."""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Validation analysis exceeded its deadline.")
    return remaining


def _top_level_entries(
    result: ContentValidationResult,
) -> tuple[dict[str, object], ...]:
    """Derive explicit and implicit ZIP-root children from importable evidence."""

    content_by_index = {entry.entry_index: entry for entry in result.entries}
    selected: dict[str, dict[str, object]] = {}
    for entry in result.structural.entries:
        content = content_by_index[entry.index]
        if content.disposition == "IGNORE":
            continue
        parts = entry.normalized_path.split("/")
        name = parts[0]
        entry_type = (
            "directory" if len(parts) > 1 or entry.entry_type == "directory" else "file"
        )
        current = selected.get(name)
        candidate = {
            "entryIndex": entry.index,
            "name": name,
            "entryType": entry_type,
        }
        if current is None or (
            len(parts) == 1
            and entry.entry_type == "directory"
            and current["entryType"] == "directory"
        ):
            selected[name] = candidate
    return tuple(selected.values())


def _apply_target_findings(
    result: ContentValidationResult,
    findings: tuple[TargetPreflightFinding, ...],
    top_level_entries: tuple[dict[str, object], ...],
) -> ContentValidationResult:
    """Attach API-owned collision evidence without mutating parser evidence."""

    paths = {
        int(entry["entryIndex"]): str(entry["name"]) for entry in top_level_entries
    }
    aggregate: list[ContentIssue] = list(result.issues)
    by_index: dict[int, list[TargetPreflightFinding]] = {}
    for finding in findings:
        if finding.entry_index is None:
            aggregate.append(ContentIssue(finding.code, blocking=finding.blocking))
        else:
            by_index.setdefault(finding.entry_index, []).append(finding)
    entries: list[ContentEntryResult] = []
    for entry in result.entries:
        item_findings = by_index.get(entry.entry_index, [])
        if not item_findings:
            entries.append(entry)
            continue
        issues = tuple(
            ContentIssue(
                finding.code,
                blocking=finding.blocking,
                entry_index=entry.entry_index,
                path=paths[entry.entry_index],
                details=(
                    ("existingKind", finding.existing_kind or "unknown"),
                    ("existingName", finding.existing_name or "unknown"),
                ),
            )
            for finding in item_findings
        )
        blocking = any(issue.blocking for issue in issues)
        entries.append(
            replace(
                entry,
                disposition="REJECT" if blocking else entry.disposition,
                planned_resource=None if blocking else entry.planned_resource,
                issues=entry.issues + issues,
            )
        )
    return ContentValidationResult(
        structural=result.structural,
        entries=tuple(entries),
        issues=tuple(aggregate),
    )


def _manifest_extracted_bytes(manifest: dict[str, object]) -> int:
    """Return the immutable READY summary size used for physical admission."""

    summary = manifest.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("READY manifest summary is unavailable.")
    value = summary.get("extractedBytes")
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= ZipImportLimits().max_extracted_bytes
    ):
        raise ValueError("READY manifest extracted byte count is invalid.")
    return value


def _folder_commit_items(manifest: dict[str, object]) -> tuple[dict[str, object], ...]:
    """Create explicit and omitted parent folders from immutable manifest paths.

    Synthetic folders reuse the first descendant source entry index. The commit
    response is path-addressed, so this preserves traceability without inventing
    indexes outside the frozen 0..9999 ZIP inventory range.
    """

    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("READY manifest entries are unavailable.")
    selected: dict[str, tuple[int, str]] = {}
    imported = [
        entry
        for entry in raw_entries
        if isinstance(entry, dict) and entry.get("disposition") == "IMPORT"
    ]
    for entry in imported:
        if entry.get("entryType") != "directory":
            continue
        path = str(entry.get("normalizedPath", ""))
        index = entry.get("entryIndex")
        if not path or isinstance(index, bool) or not isinstance(index, int):
            raise ValueError("Manifest directory evidence is invalid.")
        selected[path] = (index, path.rsplit("/", 1)[-1])
    for entry in imported:
        path = str(entry.get("normalizedPath", ""))
        index = entry.get("entryIndex")
        if not path or isinstance(index, bool) or not isinstance(index, int):
            raise ValueError("Manifest path evidence is invalid.")
        parts = path.split("/")
        if entry.get("entryType") != "directory":
            parts = parts[:-1]
        for depth in range(1, len(parts) + 1):
            folder = "/".join(parts[:depth])
            selected.setdefault(folder, (index, parts[depth - 1]))
    result = []
    for path, (index, name) in sorted(
        selected.items(), key=lambda item: (item[0].count("/"), item[0])
    ):
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        result.append(
            {
                "entryIndex": index,
                "relativePath": path,
                "parentRelativePath": parent,
                "name": name,
            }
        )
    return tuple(result)


def run_forever(worker: SequentialValidationWorker, stop: threading.Event) -> None:
    """Poll sequentially and apply bounded retry delay after ordinary failures."""

    while not stop.is_set():
        try:
            processed = worker.run_once()
        except Exception as error:
            worker.logger.warning(
                "ingest_worker_attempt_failed error=%s", type(error).__name__
            )
            stop.wait(worker.settings.poll_seconds)
        else:
            if not processed:
                stop.wait(worker.settings.poll_seconds)


def main() -> int:
    """Validate configuration and run the private sequential worker."""

    logging.basicConfig(
        level=os.getenv("OLDAP_INGEST_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    stop = threading.Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        worker = SequentialValidationWorker(
            ImportServiceClient.from_environment(), WorkerSettings.from_environment()
        )
        worker.content_validator.validate_runtime()
    except Exception as error:
        LOGGER.error(
            "ingest_worker_configuration_failed error=%s", type(error).__name__
        )
        return 2
    run_forever(worker, stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
