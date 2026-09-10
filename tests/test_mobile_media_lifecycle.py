"""Purpose-bound lifecycle claim and acknowledgement transport tests."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import jwt
import pytest

SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from mobile_media_lifecycle import (  # noqa: E402
    OldapMobileMediaLifecycleClient,
    MobileMediaLifecycleTransportError,
)

SECRET = "l" * 64
WORKER = "worker-1"
EVENT = "11111111-1111-4111-8111-111111111111"
CLAIM = "22222222-2222-4222-8222-222222222222"
NOW = datetime(2026, 9, 2, 12, tzinfo=UTC)


class Response:
    def __init__(self, status_code: int, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def claim_body():
    return {
        "eventId": EVENT,
        "claimId": CLAIM,
        "workerId": WORKER,
        "kind": "staging_deleted",
        "uploadId": "33333333-3333-4333-8333-333333333333",
        "clientAssetId": "44444444-4444-4444-8444-444444444444",
        "ownerUserIri": "https://oldap.org/users/alice",
        "stagingAreaId": "urn:uuid:55555555-5555-4555-8555-555555555555",
        "resourceIri": "urn:uuid:66666666-6666-4666-8666-666666666666",
        "checksum": "sha256:" + "a" * 64,
        "occurredAt": "2026-09-02T12:00:00Z",
        "leaseExpiresAt": "2026-09-02T12:05:00Z",
    }


def test_claim_and_completion_use_the_lifecycle_token_purpose() -> None:
    session = Session(
        [
            Response(200, claim_body()),
            Response(200, {"eventId": EVENT, "state": "delivered"}),
        ]
    )
    client = OldapMobileMediaLifecycleClient(
        "https://api.example.org",
        SECRET,
        session=session,
        clock=lambda: NOW,
    )

    event = client.claim(WORKER)
    assert event is not None
    client.complete(event)

    assert session.calls[0][0].endswith("/lifecycle-events/claims")
    assert session.calls[1][0].endswith(f"/lifecycle-events/{EVENT}/complete")
    token = session.calls[0][1]["headers"]["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(
        token,
        SECRET,
        algorithms=["HS256"],
        audience="oldap-api-mobile-media-lifecycle",
        issuer="https://oldap.org",
        options={"verify_exp": False},
    )
    assert claims["purpose"] == "mobile-media-lifecycle"
    assert claims["sub"] == "oldap-mediaserver"


def test_empty_claim_and_ambiguous_response_are_distinct() -> None:
    empty = OldapMobileMediaLifecycleClient(
        "https://api.example.org",
        SECRET,
        session=Session([Response(204)]),
        clock=lambda: NOW,
    )
    assert empty.claim(WORKER) is None

    invalid = OldapMobileMediaLifecycleClient(
        "https://api.example.org",
        SECRET,
        session=Session([Response(200, {**claim_body(), "kind": "deleted"})]),
        clock=lambda: NOW,
    )
    with pytest.raises(MobileMediaLifecycleTransportError):
        invalid.claim(WORKER)
