"""Direct SIP capability and atomic quarantine tests."""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from quarantine import (  # noqa: E402
    InvalidZipContent,
    QuarantineStore,
    UploadLengthMismatch,
    UploadTooLarge,
)
from ingest_callback import (  # noqa: E402
    CallbackUnavailable,
    ImportApiNotifier,
    reconcile_pending_receipts,
)
from storage_capacity import DiskUsage, StorageCapacityGuard  # noqa: E402

UPLOAD_SECRET = "zip-upload-test-secret-at-least-thirty-two-bytes"
ACCESS_SECRET = "zip-access-test-secret-at-least-thirty-two-bytes"
MEDIA_SECRET = "zip-media-test-secret-at-least-thirty-two-bytes"
SERVICE_SECRET = "zip-service-test-secret-at-least-thirty-two-bytes"
IMPORT_ID = "11111111-1111-4111-8111-111111111111"
REQUEST_ID = "22222222-2222-4222-8222-222222222222"
ZIP_BYTES = b"PK\x03\x04" + (b"OLDAP ZIP SIP" * 100)


def _token(import_id: str = IMPORT_ID, **overrides: object) -> str:
    current = datetime.now(UTC)
    claims: dict[str, object] = {
        "typ": "ingest-upload",
        "sub": "https://example.org/users/alice",
        "importId": import_id,
        "jti": "33333333-3333-4333-8333-333333333333",
        "iat": current,
        "exp": current + timedelta(minutes=10),
        "iss": "https://oldap.org",
        "aud": "oldap-media-ingest",
        "maxBytes": 500_000_000,
    }
    claims.update(overrides)
    return jwt.encode(claims, UPLOAD_SECRET, algorithm="HS256")


@pytest.fixture()
def ingest_app(monkeypatch, tmp_path: Path):
    """Load mediahelper against isolated delivery and ingest roots."""
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path / "images"))
    monkeypatch.setenv("OLDAP_INGEST_ROOT", str(tmp_path / "ingest"))
    monkeypatch.setenv("OLDAP_IMPORT_UPLOAD_JWT_SECRET", UPLOAD_SECRET)
    monkeypatch.setenv("OLDAP_ACCESS_JWT_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", MEDIA_SECRET)
    monkeypatch.setitem(
        sys.modules, "pyvips", types.SimpleNamespace(Image=types.SimpleNamespace())
    )
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    return module, module.app.test_client(), tmp_path


def _headers(token: str | None = None, request_id: str = REQUEST_ID) -> dict[str, str]:
    headers = {
        "Content-Type": "application/zip",
        "X-Upload-Request-Id": request_id,
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def test_streaming_put_finalizes_once_outside_delivery_tree(ingest_app):
    module, client, root = ingest_app

    created = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )

    assert created.status_code == 201
    assert created.headers["Location"] == f"/imports/{IMPORT_ID}/sip"
    assert created.json["stateNotification"] == "PENDING"
    assert created.json["sizeBytes"] == len(ZIP_BYTES)
    assert created.json["sha256"] == hashlib.sha256(ZIP_BYTES).hexdigest()
    sip = root / "ingest" / IMPORT_ID / "sip.zip"
    assert sip.read_bytes() == ZIP_BYTES
    assert not (root / "images" / IMPORT_ID).exists()
    assert not list((root / "ingest").glob(".part-*"))
    assert module.INGEST_ROOT != module.IMAGE_ROOT

    replay = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    assert replay.status_code == 200
    assert replay.json == created.json
    assert sip.read_bytes() == ZIP_BYTES


def test_endpoint_rejects_missing_expired_and_mismatched_capabilities(ingest_app):
    _, client, _ = ingest_app
    missing = client.put(
        f"/imports/{IMPORT_ID}/sip", data=ZIP_BYTES, headers=_headers()
    )
    expired = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token(exp=datetime.now(UTC) - timedelta(seconds=1))),
    )
    other_import = "44444444-4444-4444-8444-444444444444"
    mismatch = client.put(
        f"/imports/{other_import}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )

    assert missing.status_code == 401
    assert expired.status_code == 401
    assert mismatch.status_code == 403


def test_endpoint_rejects_non_zip_and_conflicting_replay(ingest_app):
    _, client, root = ingest_app
    invalid = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=b"not a zip",
        headers=_headers(_token()),
    )
    assert invalid.status_code == 415
    assert not (root / "ingest" / IMPORT_ID).exists()

    created = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    conflict = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token(), "55555555-5555-4555-8555-555555555555"),
    )
    assert created.status_code == 201
    assert conflict.status_code == 409


def test_endpoint_rejects_capacity_pressure_but_allows_exact_replay(
    ingest_app, monkeypatch
):
    """HTTP 507 is stable, while a replay needs no new physical allocation."""

    module, client, root = ingest_app
    rejecting = StorageCapacityGuard(
        disk_usage=lambda path: DiskUsage(total=100_000, used=75_000, free=25_000)
    )
    monkeypatch.setattr(module.QUARANTINE_STORE, "capacity_guard", rejecting)
    rejected = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    assert rejected.status_code == 507
    assert rejected.json["code"] == "IMPORT_PHYSICAL_CAPACITY_INSUFFICIENT"
    assert not (root / "ingest" / IMPORT_ID).exists()

    monkeypatch.setattr(module.QUARANTINE_STORE, "capacity_guard", None)
    created = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    monkeypatch.setattr(module.QUARANTINE_STORE, "capacity_guard", rejecting)
    replay = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    assert created.status_code == 201
    assert replay.status_code == 200


def test_successful_callback_atomically_updates_receipt(ingest_app, monkeypatch):
    module, client, root = ingest_app
    observed_event_ids: list[str] = []

    def deliver(receipt):
        observed_event_ids.append(receipt.event_id)
        return module.QUARANTINE_STORE.mark_notification_delivered(
            receipt.import_id, receipt.event_id
        )

    monkeypatch.setattr(module, "deliver_import_receipt", deliver)
    response = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )

    persisted = (root / "ingest" / IMPORT_ID / "receipt.json").read_text(
        encoding="utf-8"
    )
    assert response.status_code == 201
    assert response.json["stateNotification"] == "DELIVERED"
    assert observed_event_ids == [json.loads(persisted)["eventId"]]


def test_pending_callback_retries_same_event_on_exact_put_replay(
    ingest_app, monkeypatch
):
    module, client, root = ingest_app
    first = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    retained_before = json.loads(
        (root / "ingest" / IMPORT_ID / "receipt.json").read_text(encoding="utf-8")
    )

    monkeypatch.setattr(
        module,
        "deliver_import_receipt",
        lambda receipt: module.QUARANTINE_STORE.mark_notification_delivered(
            receipt.import_id, receipt.event_id
        ),
    )
    replay = client.put(
        f"/imports/{IMPORT_ID}/sip",
        data=ZIP_BYTES,
        headers=_headers(_token()),
    )
    retained_after = json.loads(
        (root / "ingest" / IMPORT_ID / "receipt.json").read_text(encoding="utf-8")
    )

    assert first.json["stateNotification"] == "PENDING"
    assert replay.status_code == 200
    assert replay.json["stateNotification"] == "DELIVERED"
    assert retained_after["eventId"] == retained_before["eventId"]
    assert (root / "ingest" / IMPORT_ID / "sip.zip").read_bytes() == ZIP_BYTES


def test_store_enforces_stream_limit_and_declared_length(tmp_path: Path):
    store = QuarantineStore(tmp_path, chunk_bytes=4)
    with pytest.raises(UploadTooLarge):
        store.store(
            IMPORT_ID,
            REQUEST_ID,
            io.BytesIO(ZIP_BYTES),
            declared_size_bytes=len(ZIP_BYTES),
            max_bytes=8,
        )
    with pytest.raises(UploadLengthMismatch):
        store.store(
            IMPORT_ID,
            REQUEST_ID,
            io.BytesIO(ZIP_BYTES),
            declared_size_bytes=len(ZIP_BYTES) + 1,
            max_bytes=len(ZIP_BYTES) + 1,
        )
    assert not (tmp_path / IMPORT_ID).exists()
    assert not list(tmp_path.glob(".part-*"))


def test_store_removes_partial_directory_when_stream_read_fails(tmp_path: Path):
    class FailingStream:
        calls = 0

        def read(self, size: int) -> bytes:
            self.calls += 1
            if self.calls == 1:
                return b"PK\x03\x04partial"
            raise OSError("connection interrupted")

    store = QuarantineStore(tmp_path, chunk_bytes=4)
    with pytest.raises(OSError, match="interrupted"):
        store.store(
            IMPORT_ID,
            REQUEST_ID,
            FailingStream(),
            declared_size_bytes=100,
            max_bytes=100,
        )
    assert not (tmp_path / IMPORT_ID).exists()
    assert not list(tmp_path.glob(".part-*"))


def test_store_rejects_non_zip_without_finalizing(tmp_path: Path):
    store = QuarantineStore(tmp_path)
    with pytest.raises(InvalidZipContent):
        store.store(
            IMPORT_ID,
            REQUEST_ID,
            io.BytesIO(b"plain text"),
            declared_size_bytes=10,
            max_bytes=10,
        )
    assert not (tmp_path / IMPORT_ID).exists()


def test_service_callback_uses_purpose_token_and_exact_receipt_payload(
    monkeypatch, tmp_path: Path
):
    monkeypatch.setenv("OLDAP_IMPORT_UPLOAD_JWT_SECRET", UPLOAD_SECRET)
    store = QuarantineStore(tmp_path)
    receipt, _ = store.store(
        IMPORT_ID,
        REQUEST_ID,
        io.BytesIO(ZIP_BYTES),
        declared_size_bytes=len(ZIP_BYTES),
        max_bytes=len(ZIP_BYTES),
    )

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"importId": IMPORT_ID, "state": "VALIDATING"}

    class Session:
        call = None

        @classmethod
        def post(cls, url, **kwargs):
            cls.call = (url, kwargs)
            return Response()

    current = datetime.now(UTC)
    notifier = ImportApiNotifier(
        "https://api.example",
        SERVICE_SECRET,
        subject="media.example",
    )
    notifier.deliver(receipt, session=Session, now=current)

    url, call = Session.call
    token = call["headers"]["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(
        token,
        SERVICE_SECRET,
        algorithms=["HS256"],
        audience="oldap-api-import-service",
        issuer="https://oldap.org",
    )
    assert url == f"https://api.example/internal/imports/{IMPORT_ID}/sip-stored"
    assert claims["typ"] == "import-service"
    assert claims["sub"] == "media.example"
    assert call["json"] == {
        "eventId": receipt.event_id,
        "storedAt": receipt.stored_at.isoformat().replace("+00:00", "Z"),
        "sizeBytes": len(ZIP_BYTES),
        "sha256": hashlib.sha256(ZIP_BYTES).hexdigest(),
        "uploadRequestId": REQUEST_ID,
    }
    assert call["timeout"] == 10.0


def test_reconciliation_retains_pending_on_failure_then_delivers(tmp_path: Path):
    store = QuarantineStore(tmp_path)
    receipt, _ = store.store(
        IMPORT_ID,
        REQUEST_ID,
        io.BytesIO(ZIP_BYTES),
        declared_size_bytes=len(ZIP_BYTES),
        max_bytes=len(ZIP_BYTES),
    )

    class Notifier:
        fail = True
        observed: list[str] = []

        @classmethod
        def deliver(cls, current_receipt):
            cls.observed.append(current_receipt.event_id)
            if cls.fail:
                raise CallbackUnavailable("offline")

    class Logger:
        def info(self, message, *args):
            pass

        def warning(self, message, *args):
            pass

    assert reconcile_pending_receipts(store, Notifier(), Logger()) == (0, 1)
    assert store.pending_receipts() == (receipt,)

    Notifier.fail = False
    assert reconcile_pending_receipts(store, Notifier(), Logger()) == (1, 0)
    assert store.pending_receipts() == ()
    assert Notifier.observed == [receipt.event_id, receipt.event_id]


def test_abandoned_part_cleanup_is_bounded_and_never_touches_finalized_data(
    tmp_path: Path, tmp_path_factory
):
    store = QuarantineStore(tmp_path)
    receipt, _ = store.store(
        IMPORT_ID,
        REQUEST_ID,
        io.BytesIO(ZIP_BYTES),
        declared_size_bytes=len(ZIP_BYTES),
        max_bytes=len(ZIP_BYTES),
    )
    now = datetime.now(UTC)
    old_timestamp = (now - timedelta(hours=2)).timestamp()
    os.utime(tmp_path / IMPORT_ID, (old_timestamp, old_timestamp))

    abandoned = tmp_path / f".part-{IMPORT_ID}-abandoned"
    abandoned.mkdir()
    (abandoned / "sip.zip.part").write_bytes(b"partial")
    os.utime(abandoned, (old_timestamp, old_timestamp))

    recent = tmp_path / f".part-{IMPORT_ID}-recent"
    recent.mkdir()
    unknown = tmp_path / ".part-not-an-import-old"
    unknown.mkdir()
    outside = tmp_path_factory.mktemp("outside-part-cleanup")
    os.utime(outside, (old_timestamp, old_timestamp))
    linked = tmp_path / f".part-{IMPORT_ID}-linked"
    linked.symlink_to(outside, target_is_directory=True)

    removed = store.cleanup_abandoned_parts(
        now=now,
        max_age_seconds=60 * 60,
        limit=100,
    )

    assert removed == 1
    assert not abandoned.exists()
    assert recent.is_dir()
    assert unknown.is_dir()
    assert linked.is_symlink()
    assert outside.is_dir()
    assert (tmp_path / IMPORT_ID / "sip.zip").read_bytes() == ZIP_BYTES
    assert store.pending_receipts() == (receipt,)


def test_abandoned_part_cleanup_honors_per_pass_limit(tmp_path: Path):
    store = QuarantineStore(tmp_path)
    now = datetime.now(UTC)
    old_timestamp = (now - timedelta(days=2)).timestamp()
    for suffix in ("first", "second"):
        directory = tmp_path / f".part-{IMPORT_ID}-{suffix}"
        directory.mkdir(parents=True)
        os.utime(directory, (old_timestamp, old_timestamp))

    assert store.cleanup_abandoned_parts(now=now, limit=1) == 1
    assert len(list(tmp_path.glob(".part-*"))) == 1
