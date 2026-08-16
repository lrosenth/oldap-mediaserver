"""Private ZIP export artifact, integrity, and capability tests."""

import csv
import hashlib
import importlib
import io
import json
import sys
import types
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
import rfc8785

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from export_artifacts import (
    DOWNLOAD_TOKEN_AUDIENCE,
    DOWNLOAD_TOKEN_TYPE,
    ExportArtifactStore,
    ExportArchiveTooLarge,
    ExportDownloadAuthorizationError,
    ExportManifestRejected,
    ExportSourceChanged,
    authorize_export_download,
    digest_header,
)
from storage_capacity import DiskUsage, StorageCapacityGuard

EXPORT_ID = "11111111-1111-4111-8111-111111111111"
NOW = datetime(2026, 8, 14, 15, 0, tzinfo=UTC)


def _manifest(content: bytes) -> tuple[dict, str]:
    source_sha = hashlib.sha256(content).hexdigest()
    value = {
        "documentType": "oldap.zip-export.manifest",
        "schemaVersion": "1.0.0",
        "exportId": EXPORT_ID,
        "generatedAt": "2026-08-14T14:59:00Z",
        "kind": "STAGING_FOLDER",
        "projectShortName": "museum",
        "requestedByIri": "https://example.org/users/alice",
        "profile": {
            "profileId": "museum-v1",
            "profileVersion": "1.0.0",
            "profileSha256": "a" * 64,
            "metadataSchemaVersion": "1.0.0",
        },
        "selection": {
            "iri": "urn:uuid:22222222-2222-4222-8222-222222222222",
            "displayName": "Posters",
            "displayPath": "Museum/Posters",
        },
        "limits": {"maxArchiveBytes": 50_000_000_000},
        "directories": [
            {
                "relativePath": "Posters",
                "containerIri": "urn:uuid:22222222-2222-4222-8222-222222222222",
            },
            {
                "relativePath": "Posters/Empty",
                "containerIri": "urn:uuid:33333333-3333-4333-8333-333333333333",
            },
        ],
        "media": [
            {
                "entryIndex": 0,
                "relativePath": "Posters/one.txt",
                "mediaIri": "urn:uuid:44444444-4444-4444-8444-444444444444",
                "containerIri": "urn:uuid:22222222-2222-4222-8222-222222222222",
                "included": True,
                "binarySource": {
                    "assetId": "asset-one",
                    "storagePath": "museum/text/asset-one/original/one.txt",
                    "originalName": "one.txt",
                    "originalMimeType": "text/plain",
                    "expectedSizeBytes": len(content),
                    "recordedChecksum": source_sha,
                },
                "metadata": {
                    "title": {"en": "One"},
                    "formula_note": "=unsafe",
                },
            },
            {
                "entryIndex": 1,
                "relativePath": "Posters/external.jpg",
                "mediaIri": "urn:uuid:55555555-5555-4555-8555-555555555555",
                "containerIri": "urn:uuid:22222222-2222-4222-8222-222222222222",
                "included": False,
                "exclusionReason": "EXTERNAL_ORIGINAL_UNAVAILABLE",
                "externalSourceUrl": "https://example.org/external.jpg",
                "metadata": {},
            },
        ],
    }
    return value, hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _store(tmp_path, content=b"hello export"):
    media = tmp_path / "media"
    source = media / "museum/text/asset-one/original/one.txt"
    source.parent.mkdir(parents=True)
    source.write_bytes(content)
    exports = tmp_path / "exports"
    exports.mkdir()
    capacity = StorageCapacityGuard(
        disk_usage=lambda path: DiskUsage(10**12, 0, 10**12)
    )
    return ExportArtifactStore(exports, media, capacity_guard=capacity), exports


def test_builds_expected_zip_atomically_and_cleanup_is_idempotent(tmp_path) -> None:
    content = b"hello export"
    store, exports = _store(tmp_path, content)
    manifest, digest = _manifest(content)

    evidence = store.build(
        manifest, digest, started_at=NOW, completed_at=NOW + timedelta(minutes=1)
    )
    replay = store.build(manifest, digest, started_at=NOW)

    assert replay == evidence
    assert not list(exports.glob(".part-*"))
    archive_path = exports / EXPORT_ID / "archive.zip"
    assert archive_path.stat().st_size == evidence.archive_size_bytes
    assert (
        hashlib.sha256(archive_path.read_bytes()).hexdigest() == evidence.archive_sha256
    )
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.read("Posters/one.txt") == content
        assert "Posters/Empty/" in archive.namelist()
        assert {"README.txt", "export.csv", "metadata.csv"} <= set(archive.namelist())
        metadata_raw = archive.read("metadata.csv")
        assert metadata_raw.startswith(b"\xef\xbb\xbf")
        rows = list(
            csv.DictReader(io.StringIO(metadata_raw[3:].decode("utf-8"), newline=""))
        )
        assert rows[0]["sha256"] == hashlib.sha256(content).hexdigest()
        assert rows[0]["formula_note"] == "'=unsafe"
        assert rows[1]["included"] == "false"
        export_rows = list(
            csv.DictReader(io.StringIO(archive.read("export.csv")[3:].decode("utf-8")))
        )
        assert export_rows[0]["requested_by_iri"] == "https://example.org/users/alice"

    store.cleanup(EXPORT_ID)
    store.cleanup(EXPORT_ID)
    assert not (exports / EXPORT_ID).exists()


def test_manifest_limit_is_enforced_below_the_v1_hard_ceiling(tmp_path) -> None:
    content = b"hello export"
    store, exports = _store(tmp_path, content)
    manifest, _ = _manifest(content)
    manifest["limits"] = {"maxArchiveBytes": 100}
    digest = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()

    with pytest.raises(ExportArchiveTooLarge, match="configured export limit"):
        store.build(manifest, digest, started_at=NOW)

    assert not (exports / EXPORT_ID).exists()
    assert not list(exports.glob(".part-*"))


def test_successful_retry_removes_hard_interruption_workspace(tmp_path) -> None:
    content = b"restart-safe export"
    store, exports = _store(tmp_path, content)
    orphan = exports / f".part-{EXPORT_ID}-interrupted"
    orphan.mkdir()
    (orphan / "archive.zip").write_bytes(b"incomplete")
    manifest, digest = _manifest(content)

    evidence = store.build(manifest, digest, started_at=NOW)

    assert evidence.archive_size_bytes > 0
    assert (exports / EXPORT_ID / "archive.zip").is_file()
    assert not orphan.exists()

    replay_orphan = exports / f".part-{EXPORT_ID}-replayed"
    replay_orphan.mkdir()
    assert store.build(manifest, digest, started_at=NOW) == evidence
    assert not replay_orphan.exists()


def test_lease_loss_checkpoint_aborts_stream_and_removes_partial(tmp_path) -> None:
    content = b"x" * (3 * 1024 * 1024)
    store, exports = _store(tmp_path, content)
    manifest, digest = _manifest(content)
    checks = 0

    def checkpoint() -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise RuntimeError("lease lost")

    with pytest.raises(RuntimeError, match="lease lost"):
        store.build(manifest, digest, started_at=NOW, checkpoint=checkpoint)

    assert checks == 3
    assert not (exports / EXPORT_ID).exists()
    assert not list(exports.glob(".part-*"))


def test_source_change_and_manifest_path_or_digest_mismatch_fail_closed(
    tmp_path,
) -> None:
    content = b"hello export"
    store, exports = _store(tmp_path, b"changed")
    manifest, digest = _manifest(content)
    with pytest.raises(ExportSourceChanged):
        store.build(manifest, digest, started_at=NOW)
    assert not (exports / EXPORT_ID).exists()
    assert not list(exports.glob(".part-*"))

    store, _ = _store(tmp_path / "other", content)
    unsafe, _ = _manifest(content)
    unsafe["media"][0]["relativePath"] = "../escape.txt"
    unsafe_digest = hashlib.sha256(rfc8785.dumps(unsafe)).hexdigest()
    with pytest.raises(ExportManifestRejected):
        store.build(unsafe, unsafe_digest)
    with pytest.raises(ExportManifestRejected, match="digest"):
        store.build(manifest, "f" * 64)


def test_archive_manifest_writes_archive_units_csv_and_keeps_shared_media_once(
    tmp_path,
) -> None:
    """Archive support metadata is generic and does not duplicate bitstreams."""

    content = b"hello export"
    store, exports = _store(tmp_path, content)
    manifest, _ = _manifest(content)
    manifest["kind"] = "ARCHIVE_UNIT"
    manifest["directories"] = manifest["directories"][:1]
    manifest["archiveUnits"] = [
        {
            "relativePath": "Posters",
            "unitIri": "urn:uuid:22222222-2222-4222-8222-222222222222",
            "archiveLevelIri": "shared:Fonds",
            "title": {"en": "Posters", "de": "Plakate"},
            "identifier": "MUS-P",
            "description": {"en": "Poster collection"},
            "temporal": "1900 - 1999",
            "materialExtent": {"en": "12 items"},
            "creatorIris": ["https://example.org/agents/curator"],
            "provenance": {},
            "conditionsOfAccess": {},
            "metadata": {"catalogue_note": "Reviewed"},
        }
    ]
    digest = hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()

    store.build(manifest, digest, started_at=NOW)

    with zipfile.ZipFile(exports / EXPORT_ID / "archive.zip") as archive:
        assert archive.namelist().count("Posters/one.txt") == 1
        raw = archive.read("archive-units.csv")
        assert raw.startswith(b"\xef\xbb\xbf")
        rows = list(csv.DictReader(io.StringIO(raw[3:].decode("utf-8"))))
        assert rows == [
            {
                "relative_path": "Posters",
                "unit_iri": "urn:uuid:22222222-2222-4222-8222-222222222222",
                "parent_unit_iri": "",
                "archive_level_iri": "shared:Fonds",
                "identifier": "MUS-P",
                "title": '{"en":"Posters","de":"Plakate"}',
                "description": '{"en":"Poster collection"}',
                "temporal": "1900 - 1999",
                "material_extent": '{"en":"12 items"}',
                "creator_iris": '["https://example.org/agents/curator"]',
                "provenance": "{}",
                "conditions_of_access": "{}",
                "catalogue_note": "Reviewed",
            }
        ]


def test_download_capability_is_exact_export_and_purpose(monkeypatch) -> None:
    secret = "export-download-secret-at-least-32-bytes"
    token_now = datetime.now(UTC)
    token = jwt.encode(
        {
            "typ": DOWNLOAD_TOKEN_TYPE,
            "sub": "https://example.org/users/alice",
            "exportId": EXPORT_ID,
            "jti": "event-1",
            "iat": token_now,
            "exp": token_now + timedelta(minutes=5),
            "iss": "https://oldap.example.org",
            "aud": DOWNLOAD_TOKEN_AUDIENCE,
        },
        secret,
        algorithm="HS256",
    )
    claims = authorize_export_download(
        token,
        EXPORT_ID,
        secret=secret,
        issuer="https://oldap.example.org",
    )
    assert claims["exportId"] == EXPORT_ID
    with pytest.raises(ExportDownloadAuthorizationError):
        authorize_export_download(
            token,
            "22222222-2222-4222-8222-222222222222",
            secret=secret,
            issuer="https://oldap.example.org",
        )


def test_flask_export_auth_returns_only_fixed_finalized_archive(monkeypatch, tmp_path):
    """Forward auth must bind capability, artifact, and Caddy path exactly."""
    content = b"hello export"
    store, exports = _store(tmp_path, content)
    manifest, digest = _manifest(content)
    evidence = store.build(manifest, digest)
    secret = "route-download-secret-at-least-32-bytes"
    token_now = datetime.now(UTC)
    token = jwt.encode(
        {
            "typ": DOWNLOAD_TOKEN_TYPE,
            "sub": "https://example.org/users/alice",
            "exportId": EXPORT_ID,
            "jti": "route-event",
            "iat": token_now,
            "exp": token_now + timedelta(minutes=5),
            "iss": "https://oldap.example.org",
            "aud": DOWNLOAD_TOKEN_AUDIENCE,
        },
        secret,
        algorithm="HS256",
    )
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path / "media"))
    monkeypatch.setenv("OLDAP_INGEST_ROOT", str(tmp_path / "ingest"))
    monkeypatch.setenv("OLDAP_IMPORT_RECORDS_ROOT", str(tmp_path / "records"))
    monkeypatch.setenv("OLDAP_EXPORT_ROOT", str(exports))
    monkeypatch.setenv("OLDAP_EXPORT_DOWNLOAD_JWT_SECRET", secret)
    monkeypatch.setenv("OLDAP_ACCESS_JWT_SECRET", "a" * 32)
    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", "b" * 32)
    monkeypatch.setenv("OLDAP_JWT_ISSUER", "https://oldap.example.org")
    monkeypatch.setenv("CORS_ORIGINS", "https://frontend.example")
    monkeypatch.setitem(
        sys.modules,
        "pyvips",
        types.SimpleNamespace(Image=types.SimpleNamespace()),
    )
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    client = module.app.test_client()

    denied = client.get(f"/auth/exports/{EXPORT_ID}/archive")
    assert denied.status_code == 401
    response = client.get(
        f"/auth/exports/{EXPORT_ID}/archive?token={token}",
        headers={"Origin": "https://frontend.example"},
    )
    assert response.status_code == 200
    assert response.headers["X-Oldap-Internal-Path"] == str(
        (exports / EXPORT_ID / "archive.zip").resolve()
    )
    assert response.headers["X-Oldap-Content-Type"] == "application/zip"
    assert response.headers["X-Oldap-Digest"] == digest_header(evidence.archive_sha256)
    assert response.headers["X-Oldap-Cors-Allow-Origin"] == ("https://frontend.example")
