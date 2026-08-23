"""HTTP contract and authentication failure tests for `/media/v1`."""

from __future__ import annotations

from io import BytesIO
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from flask import Flask


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
REPOSITORY_ROOT = MEDIAHELPER_SOURCE.parent
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from config import MobileUploadLimits  # noqa: E402
from mobile_upload_domain import (  # noqa: E402
    MobileAccessIdentity,
    MobileUploadError,
    ResolvedMobileInbox,
)
from mobile_upload_registry import MobileUploadRegistry  # noqa: E402
from mobile_upload_routes import register_mobile_upload_routes  # noqa: E402


AREA = "urn:uuid:11111111-1111-4111-8111-111111111111"
ASSET = "22222222-2222-4222-8222-222222222222"
INIT_KEY = "33333333-3333-4333-8333-333333333333"
COMMIT_KEY = "44444444-4444-4444-8444-444444444444"
DEVICE = "55555555-5555-4555-8555-555555555555"
CHECKSUM = "sha256:" + "a" * 64
ALICE = MobileAccessIdentity("alice", "https://oldap.org/users/alice")
BOB = MobileAccessIdentity("bob", "https://oldap.org/users/bob")


class Verifier:
    def __init__(self) -> None:
        self.allowed = True
        self.calls: list[tuple[str, str, str]] = []

    def verify(
        self, access_token: str, owner_user_id: str, staging_area_id: str
    ) -> ResolvedMobileInbox:
        self.calls.append((access_token, owner_user_id, staging_area_id))
        if not self.allowed:
            raise MobileUploadError(
                403,
                "mobile_destination_unavailable",
                "The protected mobile destination is unavailable",
            )
        return ResolvedMobileInbox(
            staging_area_id=staging_area_id,
            mobile_folder_id="urn:uuid:66666666-6666-4666-8666-666666666666",
            default_role_id="urn:uuid:77777777-7777-4777-8777-777777777777",
        )


@pytest.fixture()
def mobile_http(tmp_path: Path):
    app = Flask(__name__)
    registry = MobileUploadRegistry(
        tmp_path / "mobile",
        MobileUploadLimits(
            max_original_bytes=100,
            chunk_bytes=4,
            inactivity_seconds=60,
            lease_seconds=30,
            max_active_per_user=20,
            max_active_per_staging_area=100,
            max_reserved_bytes_per_user=1000,
            max_reserved_bytes_per_staging_area=1000,
            max_processing_jobs=2,
        ),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
    )
    verifier = Verifier()

    def authenticate(token: str) -> MobileAccessIdentity:
        if token in {"alice", "alice-renewed"}:
            return ALICE
        if token == "bob":
            return BOB
        raise MobileUploadError(
            401,
            "authentication_invalid",
            "Access token is invalid or expired",
        )

    register_mobile_upload_routes(app, registry, authenticate, verifier)  # type: ignore[arg-type]
    return app.test_client(), registry, verifier


def headers(token: str = "alice", **extra: str) -> dict[str, str]:
    value = {
        "Authorization": f"Bearer {token}",
        "X-App-Version": "0.0.1",
        "X-Platform": "ios",
        "X-Device-Id": DEVICE,
    }
    value.update(extra)
    return value


def initialize_body(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "clientAssetId": ASSET,
        "stagingAreaId": AREA,
        "originalName": "photo.jpg",
        "originalMimeType": "image/jpeg",
        "byteLength": 8,
        "checksum": CHECKSUM,
        "comment": "Keller",
    }
    value.update(changes)
    return value


def initialize(client, *, token: str = "alice"):
    return client.post(
        "/media/v1/uploads",
        json=initialize_body(),
        headers=headers(token, **{"Idempotency-Key": INIT_KEY}),
    )


def test_initialize_status_chunks_and_commit_follow_v1_transport(mobile_http) -> None:
    client, _, verifier = mobile_http
    created = initialize(client)
    upload_id = created.json["uploadId"]
    status = client.get(f"/media/v1/uploads/{upload_id}", headers=headers())
    first = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"abcd",
        headers=headers(
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "0",
                "Upload-Length": "8",
            }
        ),
    )
    second = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"efgh",
        headers=headers(
            "alice-renewed",
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "4",
                "Upload-Length": "8",
            },
        ),
    )
    commit = client.post(
        f"/media/v1/uploads/{upload_id}/commit",
        json={"clientAssetId": ASSET, "byteLength": 8, "checksum": CHECKSUM},
        headers=headers(**{"Idempotency-Key": COMMIT_KEY}),
    )
    replay = client.post(
        f"/media/v1/uploads/{upload_id}/commit",
        json={"checksum": CHECKSUM, "byteLength": 8, "clientAssetId": ASSET},
        headers=headers(**{"Idempotency-Key": COMMIT_KEY}),
    )

    assert created.status_code == 201
    assert created.headers["Location"] == f"/media/v1/uploads/{upload_id}"
    assert created.headers["Cache-Control"] == "no-store"
    assert status.status_code == 200
    assert first.status_code == 204 and first.headers["Upload-Offset"] == "4"
    assert second.status_code == 204 and second.headers["Upload-Offset"] == "8"
    assert commit.status_code == replay.status_code == 202
    assert commit.headers["Retry-After"] == "2"
    assert commit.json["state"] == replay.json["state"] == "verifying"
    assert [call[0] for call in verifier.calls] == [
        "alice",
        "alice",
        "alice-renewed",
        "alice",
        "alice",
    ]


def test_authentication_is_checked_before_json_or_chunk_bytes(mobile_http) -> None:
    client, registry, verifier = mobile_http
    rejected_init = client.post(
        "/media/v1/uploads",
        data=b"not-json-and-must-not-be-read",
        headers=headers("expired", **{"Idempotency-Key": INIT_KEY}),
    )
    created = initialize(client)
    upload_id = created.json["uploadId"]
    expires_before = registry.get_status(upload_id, ALICE).expires_at
    rejected_chunk = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"abcd",
        headers=headers(
            "expired",
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "0",
                "Upload-Length": "8",
            },
        ),
    )
    current = registry.get_status(upload_id, ALICE)

    assert rejected_init.status_code == rejected_chunk.status_code == 401
    assert rejected_init.content_type == "application/problem+json"
    assert rejected_chunk.headers["WWW-Authenticate"] == "Bearer"
    assert current.offset == 0
    assert current.expires_at == expires_before
    assert len(verifier.calls) == 1


def test_current_permission_loss_blocks_new_bytes_but_preserves_upload(
    mobile_http,
) -> None:
    client, registry, verifier = mobile_http
    created = initialize(client)
    upload_id = created.json["uploadId"]
    verifier.allowed = False

    rejected = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"abcd",
        headers=headers(
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "0",
                "Upload-Length": "8",
            }
        ),
    )

    assert rejected.status_code == 403
    assert rejected.json["code"] == "mobile_destination_unavailable"
    assert registry.get_status(upload_id, ALICE).offset == 0
    assert (registry.root / "uploads" / upload_id / "original.part").read_bytes() == b""


def test_expired_token_after_progress_or_before_commit_preserves_all_accepted_bytes(
    mobile_http,
) -> None:
    client, registry, _ = mobile_http
    upload_id = initialize(client).json["uploadId"]
    first = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"abcd",
        headers=headers(
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "0",
                "Upload-Length": "8",
            }
        ),
    )
    rejected_progress = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"efgh",
        headers=headers(
            "expired",
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "4",
                "Upload-Length": "8",
            },
        ),
    )
    resumed = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"efgh",
        headers=headers(
            "alice-renewed",
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "4",
                "Upload-Length": "8",
            },
        ),
    )
    rejected_commit = client.post(
        f"/media/v1/uploads/{upload_id}/commit",
        json={"clientAssetId": ASSET, "byteLength": 8, "checksum": CHECKSUM},
        headers=headers("expired", **{"Idempotency-Key": COMMIT_KEY}),
    )

    stored = registry.root / "uploads" / upload_id / "original.part"
    assert first.status_code == 204
    assert rejected_progress.status_code == rejected_commit.status_code == 401
    assert resumed.status_code == 204
    assert registry.get_status(upload_id, ALICE).offset == 8
    assert stored.read_bytes() == b"abcdefgh"


def test_other_users_cannot_observe_or_cancel_an_upload(mobile_http) -> None:
    client, registry, _ = mobile_http
    upload_id = initialize(client).json["uploadId"]
    hidden = client.get(f"/media/v1/uploads/{upload_id}", headers=headers("bob"))
    cancel = client.delete(f"/media/v1/uploads/{upload_id}", headers=headers("bob"))

    assert hidden.status_code == cancel.status_code == 404
    assert registry.get_status(upload_id, ALICE).state == "initialized"


def test_offset_conflict_and_idempotent_cancellation_expose_stable_headers(
    mobile_http,
) -> None:
    client, registry, _ = mobile_http
    upload_id = initialize(client).json["uploadId"]
    mismatch = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"abcd",
        headers=headers(
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "4",
                "Upload-Length": "8",
            }
        ),
    )
    first = client.delete(f"/media/v1/uploads/{upload_id}", headers=headers())
    replay = client.delete(f"/media/v1/uploads/{upload_id}", headers=headers())

    assert mismatch.status_code == 409
    assert mismatch.json["code"] == "upload_offset_mismatch"
    assert mismatch.headers["Upload-Offset"] == "0"
    assert first.status_code == replay.status_code == 204
    assert registry.get_status(upload_id, ALICE).state == "cancelled"


@pytest.mark.parametrize(
    ("changed_headers", "expected_code"),
    [
        ({"X-Platform": "web"}, "invalid_platform"),
        ({"X-Device-Id": "not-a-uuid"}, "invalid_request"),
        ({"X-App-Version": ""}, "missing_required_header"),
    ],
)
def test_required_mobile_headers_fail_closed(
    mobile_http, changed_headers: dict[str, str], expected_code: str
) -> None:
    client, _, verifier = mobile_http
    request_headers = headers(**{"Idempotency-Key": INIT_KEY})
    request_headers.update(changed_headers)
    response = client.post(
        "/media/v1/uploads", json=initialize_body(), headers=request_headers
    )

    assert response.status_code == 400
    assert response.json["code"] == expected_code
    assert verifier.calls == []


def test_json_body_is_bounded_without_content_length(mobile_http) -> None:
    client, _, verifier = mobile_http
    response = client.open(
        "/media/v1/uploads",
        method="POST",
        input_stream=BytesIO(b" " * (64 * 1024 + 1)),
        content_type="application/json",
        headers=headers(**{"Idempotency-Key": INIT_KEY}),
        environ_overrides={"CONTENT_LENGTH": "", "wsgi.input_terminated": True},
    )

    assert response.status_code == 413
    assert response.json["code"] == "request_too_large"
    assert verifier.calls == []


def test_oversized_numeric_upload_header_stays_in_closed_error_contract(
    mobile_http,
) -> None:
    client, _, verifier = mobile_http
    upload_id = initialize(client).json["uploadId"]

    response = client.patch(
        f"/media/v1/uploads/{upload_id}",
        data=b"abcd",
        headers=headers(
            **{
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": "9" * 100,
                "Upload-Length": "8",
            }
        ),
    )

    assert response.status_code == 400
    assert response.content_type == "application/problem+json"
    assert response.json["code"] == "invalid_upload_offset"
    assert len(verifier.calls) == 1


@pytest.mark.parametrize(
    "configuration",
    ["Caddyfile", "ansible/templates/Caddyfile.j2"],
)
def test_mobile_transport_remains_absent_from_public_routing(
    configuration: str,
) -> None:
    value = (REPOSITORY_ROOT / configuration).read_text(encoding="utf-8")
    assert "/media/v1" not in value
