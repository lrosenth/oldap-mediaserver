"""Projection of structural validation evidence into the frozen v1 contracts."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from config import ZipImportLimits
from content_validation import (
    ContentEntryResult,
    ContentIssue,
    ContentValidationResult,
)
from ingest_service import ValidationClaim
from zip_validation import ZipEntry, ZipIssue, ZipValidationResult


@dataclass(frozen=True, slots=True)
class ValidationDocuments:
    """One matching manifest/report pair ready for immutable publication."""

    manifest: dict[str, Any]
    report: dict[str, Any]


def build_validation_timeout_report(
    claim: ValidationClaim,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the bounded FAILED report used after the hard wall-clock limit."""

    current = (generated_at or datetime.now(UTC)).astimezone(UTC)
    issue = ContentIssue("VALIDATION_TIMEOUT")
    return {
        "documentType": "oldap.zip-import.report",
        "schemaVersion": "1.0.0",
        "importId": claim.import_id,
        "generatedAt": current.isoformat().replace("+00:00", "Z"),
        "status": "FAILED",
        "canConfirm": False,
        "target": claim.target,
        "sip": _sip(claim),
        "summary": {
            "entriesObserved": 0,
            "inventoryComplete": False,
            "files": 0,
            "directories": 0,
            "importableFiles": 0,
            "importableDirectories": 0,
            "ignoredEntries": 0,
            "rejectedEntries": 0,
            "warningCount": 0,
            "errorCount": 1,
            "compressedBytes": claim.compressed_size_bytes,
            "extractedBytes": 0,
            "maxDepth": 0,
        },
        "issues": [_issue(issue)],
        "entries": [],
    }


def build_content_documents(
    claim: ValidationClaim,
    result: ContentValidationResult,
    *,
    component_version: str,
    generated_at: datetime | None = None,
    limits: ZipImportLimits | None = None,
) -> ValidationDocuments:
    """Build complete READY or content-driven INVALID v1 records."""

    structural = result.structural
    if not structural.accepted or structural.extraction_root is None:
        raise ValueError("Content documents require successful extraction.")
    current = (generated_at or datetime.now(UTC)).astimezone(UTC)
    timestamp = current.isoformat().replace("+00:00", "Z")
    outcome = "READY" if result.accepted else "INVALID"
    content_by_index = {entry.entry_index: entry for entry in result.entries}
    if set(content_by_index) != {entry.index for entry in structural.entries}:
        raise ValueError("Content inventory must cover every structural entry once.")
    manifest_entries = [
        _content_manifest_entry(
            entry,
            content_by_index[entry.index],
            structural.issues,
        )
        for entry in structural.entries
    ]
    report_entries = [
        _content_report_entry(
            entry,
            content_by_index[entry.index],
            structural.issues,
        )
        for entry in structural.entries
    ]
    all_issues = _unique_findings(
        list(structural.issues)
        + list(result.issues)
        + [issue for entry in result.entries for issue in entry.issues]
    )
    summary = {
        "entriesObserved": len(structural.entries),
        "entriesDeclared": structural.entries_declared,
        "inventoryComplete": structural.inventory_complete,
        "files": sum(entry.entry_type == "file" for entry in structural.entries),
        "directories": sum(
            entry.entry_type == "directory" for entry in structural.entries
        ),
        "importableFiles": sum(
            entry.entry_type == "file"
            and content_by_index[entry.index].disposition == "IMPORT"
            for entry in structural.entries
        ),
        "importableDirectories": sum(
            entry.entry_type == "directory"
            and content_by_index[entry.index].disposition == "IMPORT"
            for entry in structural.entries
        ),
        "ignoredEntries": sum(item.disposition == "IGNORE" for item in result.entries),
        "rejectedEntries": sum(item.disposition == "REJECT" for item in result.entries),
        "warningCount": sum(not issue.blocking for issue in all_issues),
        "errorCount": sum(issue.blocking for issue in all_issues),
        "compressedBytes": claim.compressed_size_bytes,
        "extractedBytes": structural.actual_extracted_bytes,
        "maxDepth": structural.max_depth,
    }
    sip = _sip(claim)
    aggregate_issues = [
        _issue(issue)
        for issue in tuple(structural.issues) + tuple(result.issues)
        if issue.entry_index is None
    ]
    manifest = _manifest_base(
        claim,
        structural,
        timestamp=timestamp,
        component_version=component_version,
        limits=limits or ZipImportLimits(),
        outcome=outcome,
        summary=summary,
        issues=aggregate_issues,
        entries=manifest_entries,
    )
    report: dict[str, Any] = {
        "documentType": "oldap.zip-import.report",
        "schemaVersion": "1.0.0",
        "importId": claim.import_id,
        "generatedAt": timestamp,
        "status": outcome,
        "canConfirm": outcome == "READY",
        "target": claim.target,
        "sip": sip,
        "summary": summary,
        "issues": aggregate_issues,
        "entries": report_entries,
    }
    if outcome == "READY":
        report["expiresAt"] = (
            (current + timedelta(days=7)).isoformat().replace("+00:00", "Z")
        )
    return ValidationDocuments(manifest=manifest, report=report)


def build_structural_invalid_documents(
    claim: ValidationClaim,
    result: ZipValidationResult,
    *,
    component_version: str,
    generated_at: datetime | None = None,
    limits: ZipImportLimits | None = None,
) -> ValidationDocuments:
    """Build complete INVALID records from bounded structural evidence.

    This function deliberately cannot emit READY. Content and target checks
    must enrich a structurally accepted inventory before READY is possible.
    """

    if result.accepted:
        raise ValueError("Structural evidence alone cannot produce READY records.")
    current = generated_at or datetime.now(UTC)
    timestamp = current.astimezone(UTC).isoformat().replace("+00:00", "Z")
    policy = limits or ZipImportLimits()
    entries = [_manifest_entry(entry, result.issues) for entry in result.entries]
    report_entries = [_report_entry(entry, result.issues) for entry in result.entries]
    aggregate_issues = [
        _issue(issue) for issue in result.issues if issue.entry_index is None
    ]
    all_issues = _unique_issues(
        list(result.issues)
        + [issue for entry in result.entries for issue in entry.issues]
    )
    summary = {
        "entriesObserved": len(result.entries),
        "entriesDeclared": result.entries_declared,
        "inventoryComplete": result.inventory_complete,
        "files": sum(entry.entry_type == "file" for entry in result.entries),
        "directories": sum(entry.entry_type == "directory" for entry in result.entries),
        "importableFiles": 0,
        "importableDirectories": 0,
        "ignoredEntries": 0,
        "rejectedEntries": len(result.entries),
        "warningCount": sum(not issue.blocking for issue in all_issues),
        "errorCount": sum(issue.blocking for issue in all_issues),
        "compressedBytes": claim.compressed_size_bytes,
        "extractedBytes": result.actual_extracted_bytes,
        "maxDepth": result.max_depth,
    }
    sip = {
        "originalFileName": claim.original_file_name,
        "sizeBytes": claim.compressed_size_bytes,
        "sha256": claim.sip_sha256,
    }
    manifest = _manifest_base(
        claim,
        result,
        timestamp=timestamp,
        component_version=component_version,
        limits=policy,
        outcome="INVALID",
        summary=summary,
        issues=aggregate_issues,
        entries=entries,
    )
    report = {
        "documentType": "oldap.zip-import.report",
        "schemaVersion": "1.0.0",
        "importId": claim.import_id,
        "generatedAt": timestamp,
        "status": "INVALID",
        "canConfirm": False,
        "target": claim.target,
        "sip": sip,
        "summary": summary,
        "issues": aggregate_issues,
        "entries": report_entries,
    }
    return ValidationDocuments(manifest=manifest, report=report)


def _manifest_base(
    claim: ValidationClaim,
    structural: ZipValidationResult,
    *,
    timestamp: str,
    component_version: str,
    limits: ZipImportLimits,
    outcome: str,
    summary: dict[str, Any],
    issues: list[dict[str, Any]],
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "documentType": "oldap.zip-import.manifest",
        "schemaVersion": "1.0.0",
        "importId": claim.import_id,
        "generatedAt": timestamp,
        "validator": {
            "component": "oldap-mediahelper",
            "version": component_version,
            "policyVersion": "zip-import-mvp-1",
        },
        "validationOutcome": outcome,
        "job": {
            "createdAt": claim.job_created_at,
            "requestedByIri": claim.requested_by_iri,
            "target": claim.target,
        },
        "sip": _sip(claim)
        | {
            "zip": {
                "singleDisk": not _has_issue(structural, "MULTI_DISK_NOT_ALLOWED"),
                "zip64": _has_issue(structural, "ZIP64_NOT_ALLOWED"),
                "encrypted": _has_issue(structural, "ENCRYPTED_ENTRY"),
                "selfExtractingPreamble": _has_issue(
                    structural, "SELF_EXTRACTING_ZIP_NOT_ALLOWED"
                ),
                "archiveCommentPresent": structural.archive_comment_present,
                "compressionMethodsObserved": list(
                    structural.compression_methods_observed
                ),
            }
        },
        "limits": limits.to_contract_snapshot(),
        "summary": summary,
        "issues": issues,
        "entries": entries,
    }


def _sip(claim: ValidationClaim) -> dict[str, Any]:
    return {
        "originalFileName": claim.original_file_name,
        "sizeBytes": claim.compressed_size_bytes,
        "sha256": claim.sip_sha256,
    }


def _manifest_entry(
    entry: ZipEntry, result_issues: tuple[ZipIssue, ...]
) -> dict[str, Any]:
    issues = _entry_issues(entry, result_issues)
    archive: dict[str, Any] = {
        "compressionMethodCode": entry.compression_method_code,
        "compressionMethod": entry.compression_method,
        "generalPurposeBitFlags": entry.flags,
        "externalAttributes": entry.external_attributes,
        "compressedSizeBytes": entry.compressed_size_bytes,
        "declaredUncompressedSizeBytes": entry.declared_uncompressed_size_bytes,
        "actualUncompressedSizeBytes": (
            entry.actual_uncompressed_size_bytes
            if entry.actual_uncompressed_size_bytes is not None
            else entry.declared_uncompressed_size_bytes
        ),
        "crc32Declared": entry.crc32_declared,
    }
    if entry.crc32_actual is not None:
        archive["crc32Actual"] = entry.crc32_actual
    return {
        "entryIndex": entry.index,
        "sourcePath": _bounded_text(entry.source_name, 1_024, entry.index),
        "sourcePathBytesBase64": base64.b64encode(entry.source_name_bytes).decode(
            "ascii"
        ),
        "normalizedPath": _bounded_text(entry.normalized_path, 1_024, entry.index),
        "parentNormalizedPath": _bounded_text(
            entry.parent_normalized_path, 1_024, entry.index, allow_empty=True
        ),
        "normalizedName": _bounded_text(entry.normalized_name, 255, entry.index),
        "entryType": entry.entry_type,
        "disposition": "REJECT",
        "depth": entry.depth,
        "archive": archive,
        "issues": [_issue(issue) for issue in issues],
    }


def _content_manifest_entry(
    entry: ZipEntry,
    content: ContentEntryResult,
    structural_issues: tuple[ZipIssue, ...],
) -> dict[str, Any]:
    value = _manifest_entry(entry, structural_issues)
    value["disposition"] = content.disposition
    value["issues"] = [
        _issue(issue)
        for issue in _unique_findings(
            list(_entry_issues(entry, structural_issues)) + list(content.issues)
        )
    ]
    if entry.sha256 is not None:
        value["sha256"] = entry.sha256
    if content.detected_content is not None:
        value["detectedContent"] = content.detected_content
    if content.planned_resource is not None:
        value["plannedResource"] = content.planned_resource
    return value


def _content_report_entry(
    entry: ZipEntry,
    content: ContentEntryResult,
    structural_issues: tuple[ZipIssue, ...],
) -> dict[str, Any]:
    value = _report_entry(entry, structural_issues)
    value["disposition"] = content.disposition
    value["issues"] = [
        _issue(issue)
        for issue in _unique_findings(
            list(_entry_issues(entry, structural_issues)) + list(content.issues)
        )
    ]
    if content.detected_content is not None:
        value["detectedCategory"] = content.detected_content["category"]
        value["detectedMimeType"] = content.detected_content["mimeType"]
    return value


def _report_entry(
    entry: ZipEntry, result_issues: tuple[ZipIssue, ...]
) -> dict[str, Any]:
    return {
        "entryIndex": entry.index,
        "sourcePath": _bounded_text(entry.source_name, 1_024, entry.index),
        "normalizedPath": _bounded_text(entry.normalized_path, 1_024, entry.index),
        "entryType": entry.entry_type,
        "disposition": "REJECT",
        "sizeBytes": (
            entry.actual_uncompressed_size_bytes
            if entry.actual_uncompressed_size_bytes is not None
            else entry.declared_uncompressed_size_bytes
        ),
        "issues": [_issue(issue) for issue in _entry_issues(entry, result_issues)],
    }


def _entry_issues(
    entry: ZipEntry, result_issues: tuple[ZipIssue, ...]
) -> tuple[ZipIssue, ...]:
    return _unique_issues(
        list(entry.issues)
        + [issue for issue in result_issues if issue.entry_index == entry.index]
    )


def _issue(issue: ZipIssue | ContentIssue) -> dict[str, Any]:
    value: dict[str, Any] = {
        "code": issue.code,
        "severity": issue.severity,
        "blocking": issue.blocking,
        "messageKey": issue.message_key,
    }
    if issue.entry_index is not None:
        value["entryIndex"] = issue.entry_index
    if issue.path is not None:
        value["path"] = _bounded_text(issue.path, 1_024, issue.entry_index or 0)
    if issue.details:
        value["details"] = dict(issue.details)
    return value


def _unique_issues(issues: list[ZipIssue]) -> tuple[ZipIssue, ...]:
    return tuple(dict.fromkeys(issues))


def _unique_findings(
    issues: list[ZipIssue | ContentIssue],
) -> tuple[ZipIssue | ContentIssue, ...]:
    return tuple(dict.fromkeys(issues))


def _has_issue(result: ZipValidationResult, code: str) -> bool:
    return any(issue.code == code for issue in result.issues)


def _bounded_text(
    value: str,
    max_bytes: int,
    entry_index: int,
    *,
    allow_empty: bool = False,
) -> str:
    if not value and allow_empty:
        return ""
    if not value:
        return f"invalid-entry-{entry_index}"
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value
    suffix = "…"
    available = max_bytes - len(suffix.encode("utf-8"))
    shortened = encoded[:available]
    while shortened:
        try:
            return shortened.decode("utf-8") + suffix
        except UnicodeDecodeError:
            shortened = shortened[:-1]
    return f"invalid-entry-{entry_index}"


def component_version(version_file: Path | None = None) -> str:
    """Resolve the bounded worker component version without importing Flask."""

    value = os.environ.get("MEDIAHELPER_VERSION", "").strip()
    if value:
        return value[:64]
    path = version_file or Path(__file__).resolve().parent / "VERSION"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    return value[:64] or "unknown"
