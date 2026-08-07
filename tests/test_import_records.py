"""Immutable import-record storage and read-authorization tests."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from import_records import (  # noqa: E402
    ImportRecordError,
    ImportRecordConflict,
    ImportRecordStore,
    authorize_record_token,
)

IMPORT_ID = "11111111-1111-4111-8111-111111111111"
RECORD_SECRET = "record-read-test-secret-at-least-thirty-two-bytes"


def _documents() -> tuple[dict, dict]:
    summary = {"compressedBytes": 100, "extractedBytes": 0}
    manifest = {
        "documentType": "oldap.zip-import.manifest",
        "schemaVersion": "1.0.0",
        "importId": IMPORT_ID,
        "validationOutcome": "INVALID",
        "summary": summary,
    }
    report = {
        "documentType": "oldap.zip-import.report",
        "schemaVersion": "1.0.0",
        "importId": IMPORT_ID,
        "status": "INVALID",
        "summary": summary,
    }
    return manifest, report


def _token(import_id: str = IMPORT_ID, **overrides: object) -> str:
    current = datetime.now(UTC)
    claims: dict[str, object] = {
        "typ": "import-records",
        "sub": "oldap-api",
        "importId": import_id,
        "iat": current,
        "exp": current + timedelta(minutes=5),
        "iss": "https://oldap.org",
        "aud": "oldap-media-import-records",
    }
    claims.update(overrides)
    return jwt.encode(claims, RECORD_SECRET, algorithm="HS256")


def test_record_pair_is_create_only_checksum_bound_and_exactly_replayable(
    tmp_path: Path,
) -> None:
    store = ImportRecordStore(tmp_path / "records")
    manifest, report = _documents()

    first = store.publish(
        IMPORT_ID,
        manifest=manifest,
        report=report,
        temporary_payload_deleted=True,
    )
    replay = store.publish(
        IMPORT_ID,
        manifest=manifest,
        report=report,
        temporary_payload_deleted=True,
    )

    assert replay == first
    manifest_bytes, manifest_digest = store.read(IMPORT_ID, "manifest")
    report_bytes, report_digest = store.read(IMPORT_ID, "report")
    assert hashlib.sha256(manifest_bytes).hexdigest() == manifest_digest
    assert hashlib.sha256(report_bytes).hexdigest() == report_digest
    assert json.loads(report_bytes)["manifestSha256"] == manifest_digest
    assert store.read_manifest(IMPORT_ID, manifest_digest) == manifest
    try:
        store.read_manifest(IMPORT_ID, "0" * 64)
    except ImportRecordError:
        pass
    else:
        raise AssertionError("A stale IMPORT claim digest must be rejected.")
    assert not any(path.name.startswith(".part-") for path in store.root.iterdir())

    changed = report | {"status": "READY"}
    try:
        store.publish(
            IMPORT_ID,
            manifest=manifest,
            report=changed,
            temporary_payload_deleted=True,
        )
    except (ImportRecordConflict, ValueError):
        pass
    else:
        raise AssertionError("Different retained records must not overwrite originals.")


def test_record_token_is_bound_to_purpose_subject_and_import() -> None:
    claims = authorize_record_token(
        f"Bearer {_token()}", IMPORT_ID, secret=RECORD_SECRET
    )
    assert claims["importId"] == IMPORT_ID

    for token in (
        _token("22222222-2222-4222-8222-222222222222"),
        _token(typ="access"),
        _token(sub="browser-user"),
    ):
        try:
            authorize_record_token(f"Bearer {token}", IMPORT_ID, secret=RECORD_SECRET)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Mis-scoped token was accepted.")


def test_failed_report_is_create_only_without_a_manifest(tmp_path: Path) -> None:
    store = ImportRecordStore(tmp_path / "records")
    report = {
        "documentType": "oldap.zip-import.report",
        "schemaVersion": "1.0.0",
        "importId": IMPORT_ID,
        "status": "FAILED",
        "summary": {"compressedBytes": 100, "extractedBytes": 0},
    }

    first = store.publish_failure(
        IMPORT_ID, report=report, failure_code="VALIDATION_TIMEOUT"
    )
    replay = store.publish_failure(
        IMPORT_ID, report=report, failure_code="VALIDATION_TIMEOUT"
    )

    assert replay == first
    assert first.manifest_sha256 is None
    assert first.failure_code == "VALIDATION_TIMEOUT"
    assert not (store.root / IMPORT_ID / "manifest.json").exists()
    report_bytes, digest = store.read(IMPORT_ID, "report")
    assert hashlib.sha256(report_bytes).hexdigest() == digest
    try:
        store.read(IMPORT_ID, "manifest")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FAILED must not expose a fabricated manifest.")


def test_flask_internal_record_route_returns_exact_hashed_bytes(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path / "images"))
    monkeypatch.setenv("OLDAP_INGEST_ROOT", str(tmp_path / "ingest"))
    monkeypatch.setenv("OLDAP_IMPORT_RECORDS_ROOT", str(tmp_path / "records"))
    monkeypatch.setenv("OLDAP_IMPORT_RECORDS_JWT_SECRET", RECORD_SECRET)
    monkeypatch.setitem(
        sys.modules, "pyvips", types.SimpleNamespace(Image=types.SimpleNamespace())
    )
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    manifest, report = _documents()
    stored = module.IMPORT_RECORD_STORE.publish(
        IMPORT_ID,
        manifest=manifest,
        report=report,
        temporary_payload_deleted=True,
    )

    response = module.app.test_client().get(
        f"/internal/imports/{IMPORT_ID}/records/report",
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert hashlib.sha256(response.data).hexdigest() == stored.report_sha256
    assert response.json["manifestSha256"] == stored.manifest_sha256
