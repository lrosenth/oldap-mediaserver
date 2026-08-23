"""Purpose-token and ambiguity tests for the OLDAP mobile-media client."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import jwt
import pytest
import requests


SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from mobile_media_commit import (  # noqa: E402
    MobileMediaCommitFailure,
    OldapMobileMediaCommitClient,
)


SECRET = "mobile-media-purpose-secret-at-least-32-bytes"
UPLOAD = "11111111-1111-4111-8111-111111111111"
ASSET = "22222222-2222-4222-8222-222222222222"
EVENT = "33333333-3333-4333-8333-333333333333"
AREA = "urn:uuid:44444444-4444-4444-8444-444444444444"
CHECKSUM = "sha256:" + "a" * 64


class Response:
    def __init__(self, status: int, value: object) -> None:
        self.status_code = status
        self.value = value

    def json(self) -> object:
        return self.value


class Session:
    def __init__(self, value: Response | Exception) -> None:
        self.value = value
        self.call: tuple[str, dict[str, object]] | None = None

    def post(self, url: str, **kwargs: object) -> Response:
        self.call = (url, kwargs)
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


def payload() -> dict[str, object]:
    return {
        "eventId": EVENT,
        "uploadId": UPLOAD,
        "clientAssetId": ASSET,
        "ownerUserIri": "https://oldap.org/users/alice",
        "stagingAreaId": AREA,
        "originalName": "photo.jpg",
        "originalMimeType": "image/jpeg",
        "byteLength": 8,
        "checksum": CHECKSUM,
        "publication": {
            "ownerUploadId": UPLOAD,
            "assetId": ASSET,
            "byteLength": 8,
            "checksum": CHECKSUM,
            "derivativeNames": ["master.tif"],
            "storagePath": "fasnacht/image/bmg",
        },
    }


def result(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "eventId": EVENT,
        "uploadId": UPLOAD,
        "clientAssetId": ASSET,
        "stagingAreaId": AREA,
        "assetId": ASSET,
        "resourceIri": "urn:uuid:55555555-5555-4555-8555-555555555555",
        "checksum": CHECKSUM,
        "committedAt": "2026-08-23T12:00:00Z",
    }
    value.update(changes)
    return value


def test_client_uses_short_purpose_specific_token_and_exact_route() -> None:
    session = Session(Response(200, result()))
    client = OldapMobileMediaCommitClient(
        "https://api.example/",
        SECRET,
        session=session,
        clock=lambda: datetime(2026, 8, 23, 12, tzinfo=UTC),
    )

    assert client.commit(UPLOAD, EVENT, payload()) == result()
    assert session.call is not None
    url, options = session.call
    assert url.endswith(f"/internal/mobile-media/v1/uploads/{UPLOAD}/commit")
    token = str(options["headers"]["Authorization"]).removeprefix("Bearer ")  # type: ignore[index]
    claims = jwt.decode(
        token,
        SECRET,
        algorithms=["HS256"],
        audience="oldap-api-mobile-media",
        issuer="https://oldap.org",
        options={"verify_exp": False},
    )
    assert claims["typ"] == "mobile-media-service"
    assert claims["purpose"] == "mobile-media-commit"
    assert claims["sub"] == "oldap-mediaserver"
    assert claims["exp"] - claims["iat"] == 120
    assert options["headers"]["X-Request-ID"] == EVENT  # type: ignore[index]


def test_client_rejects_shared_secret_and_conflicting_success_receipt() -> None:
    with pytest.raises(RuntimeError, match="purpose-specific"):
        OldapMobileMediaCommitClient(
            "https://api.example", SECRET, other_secrets=(SECRET,)
        )
    client = OldapMobileMediaCommitClient(
        "https://api.example",
        SECRET,
        session=Session(Response(200, result(assetId=UPLOAD))),
    )
    with pytest.raises(MobileMediaCommitFailure) as caught:
        client.commit(UPLOAD, EVENT, payload())
    assert caught.value.retryable is True


@pytest.mark.parametrize(
    ("response", "retryable"),
    [
        (Response(401, {"code": "invalid_credentials", "retryable": False}), True),
        (Response(404, {"code": "route_not_found", "retryable": False}), True),
        (Response(409, {"code": "unknown_conflict", "retryable": False}), True),
        (Response(409, {"code": "client_asset_conflict", "retryable": False}), False),
        (Response(400, {"code": "validation_failed", "retryable": False}), False),
        (Response(503, {"code": "upstream_unavailable", "retryable": True}), True),
        (requests.ConnectionError("lost"), True),
    ],
)
def test_client_compensates_only_closed_definitive_rejections(
    response: Response | Exception, retryable: bool
) -> None:
    client = OldapMobileMediaCommitClient(
        "https://api.example", SECRET, session=Session(response)
    )
    with pytest.raises(MobileMediaCommitFailure) as caught:
        client.commit(UPLOAD, EVENT, payload())
    assert caught.value.retryable is retryable
