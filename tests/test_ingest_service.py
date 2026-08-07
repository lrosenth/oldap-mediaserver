"""Control-plane parsing and authentication tests for the ingest worker."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from ingest_service import (  # noqa: E402
    CleanupClaim,
    ImportClaim,
    ImportServiceClient,
    IngestServiceUnavailable,
    ValidationClaim,
)

SERVICE_SECRET = "worker-service-test-secret-at-least-thirty-two-bytes"
IMPORT_ID = "11111111-1111-4111-8111-111111111111"
CLAIM_ID = "22222222-2222-4222-8222-222222222222"


class Response:
    def __init__(self, status_code: int, value=None):
        self.status_code = status_code
        self._value = value

    def json(self):
        return self._value


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def post(self, url, **kwargs):
        self.requests.append((url, kwargs))
        return self.responses.pop(0)


def _client() -> ImportServiceClient:
    return ImportServiceClient(
        api_base_url="https://api.example",
        secret=SERVICE_SECRET,
        worker_id="worker-1",
    )


def _claim() -> dict:
    return {
        "claimId": CLAIM_ID,
        "importId": IMPORT_ID,
        "task": "VALIDATE",
        "stateVersion": 2,
        "claimedAt": "2026-08-05T00:00:00Z",
        "leaseExpiresAt": "2026-08-05T00:05:00Z",
        "jobCreatedAt": "2026-08-04T23:00:00Z",
        "requestedByIri": "https://example.org/users/alice",
        "originalFileName": "archive.zip",
        "compressedSizeBytes": 100,
        "sipSha256": "a" * 64,
        "target": {
            "projectShortName": "fasnacht",
            "stagingAreaIri": "https://example.org/staging",
            "stagingAreaName": "Staging",
            "targetRootFolderIri": "https://example.org/root",
            "targetRootFolderName": "Root",
        },
    }


def test_claim_and_heartbeat_use_short_purpose_specific_tokens() -> None:
    session = Session(
        [
            Response(200, _claim()),
            Response(
                200,
                {
                    "claimId": CLAIM_ID,
                    "leaseExpiresAt": "2026-08-05T00:10:00Z",
                },
            ),
        ]
    )
    client = _client()

    claim = client.claim_validation(session=session)
    expiry = client.heartbeat(claim, session=session)

    assert claim.import_id == IMPORT_ID
    assert expiry == datetime(2026, 8, 5, 0, 10, tzinfo=UTC)
    for _, request in session.requests:
        token = request["headers"]["Authorization"].split()[1]
        claims = jwt.decode(
            token,
            SERVICE_SECRET,
            algorithms=["HS256"],
            audience="oldap-api-import-service",
            issuer="https://oldap.org",
        )
        assert claims["typ"] == "import-service"
        assert datetime.fromtimestamp(claims["exp"], UTC) - datetime.fromtimestamp(
            claims["iat"], UTC
        ) == timedelta(seconds=60)


def test_empty_queue_returns_none() -> None:
    assert _client().claim_validation(session=Session([Response(204)])) is None


def test_claim_next_parses_import_and_commit_verifies_exact_mapping() -> None:
    claim_value = _claim() | {"task": "IMPORT", "manifestSha256": "b" * 64}
    resources = [
        {
            "entryIndex": 0,
            "relativePath": "Folder",
            "resourceIri": "urn:uuid:33333333-3333-4333-8333-333333333333",
        },
        {
            "entryIndex": 1,
            "relativePath": "Folder/note.txt",
            "resourceIri": "urn:uuid:44444444-4444-4444-8444-444444444444",
            "assetId": "asset-1",
        },
    ]
    session = Session(
        [
            Response(200, claim_value),
            Response(
                200,
                {
                    "eventId": "ef8666b4-9960-5e48-b65f-6625dbccb703",
                    "job": {"importId": IMPORT_ID, "state": "IMPORTED"},
                    "resources": resources,
                },
            ),
        ]
    )
    client = _client()

    claim = client.claim_next(session=session)
    assert isinstance(claim, ImportClaim)
    result = client.commit_import(
        claim,
        folders=(
            {
                "entryIndex": 0,
                "relativePath": "Folder",
                "parentRelativePath": "",
                "name": "Folder",
            },
        ),
        media=(
            {
                "entryIndex": 1,
                "relativePath": "Folder/note.txt",
                "parentRelativePath": "Folder",
                "assetId": "asset-1",
            },
        ),
        session=session,
    )

    assert result["resources"] == resources
    assert session.requests[0][1]["json"]["supportedTasks"] == [
        "VALIDATE",
        "IMPORT",
        "CLEANUP",
    ]
    assert session.requests[1][1]["json"]["eventId"] == result["eventId"]


def test_cleanup_claim_and_result_are_closed_and_deterministic() -> None:
    claim_value = _claim() | {
        "task": "CLEANUP",
        "cleanupReason": "EXPIRED",
    }
    session = Session(
        [
            Response(200, claim_value),
            Response(
                200,
                {
                    "importId": IMPORT_ID,
                    "state": "EXPIRED",
                    "cleanupPending": False,
                },
            ),
        ]
    )
    client = _client()

    claim = client.claim_next(session=session)
    assert isinstance(claim, CleanupClaim)
    result = client.publish_cleanup_result(
        claim,
        completed_at=datetime(2026, 8, 5, 1, 0, tzinfo=UTC),
        session=session,
    )

    assert result["state"] == "EXPIRED"
    assert session.requests[0][1]["json"]["supportedTasks"] == [
        "VALIDATE",
        "IMPORT",
        "CLEANUP",
    ]
    payload = session.requests[1][1]["json"]
    assert payload["reason"] == "EXPIRED"
    assert payload["temporaryPayloadDeleted"] is True
    assert payload["completedAt"] == "2026-08-05T01:00:00Z"


def test_target_preflight_is_claim_bound_and_strictly_parsed() -> None:
    claim = ValidationClaim.from_dict(_claim())
    entries = (
        {"entryIndex": 0, "name": "Photos", "entryType": "directory"},
        {"entryIndex": 1, "name": "notes.txt", "entryType": "file"},
    )
    session = Session(
        [
            Response(
                200,
                {
                    "claimId": CLAIM_ID,
                    "targetRootFolderIri": "https://example.org/root",
                    "findings": [
                        {
                            "entryIndex": 0,
                            "code": "TARGET_FOLDER_COLLISION",
                            "blocking": True,
                            "existingKind": "folder",
                            "existingName": "photos",
                        },
                        {
                            "entryIndex": 1,
                            "code": "TARGET_MEDIA_NAME_COLLISION",
                            "blocking": False,
                            "existingKind": "media",
                            "existingName": "Notes.txt",
                        },
                    ],
                },
            )
        ]
    )

    findings = _client().preflight_target(
        claim, entries, timeout_seconds=3.0, session=session
    )

    assert [finding.code for finding in findings] == [
        "TARGET_FOLDER_COLLISION",
        "TARGET_MEDIA_NAME_COLLISION",
    ]
    assert session.requests[0][0].endswith(
        f"/internal/import-claims/{CLAIM_ID}/target-preflight"
    )
    assert session.requests[0][1]["json"]["topLevelEntries"] == list(entries)
    assert session.requests[0][1]["timeout"] == 3.0


def test_target_preflight_rejects_mismatched_response() -> None:
    claim = ValidationClaim.from_dict(_claim())
    entries = ({"entryIndex": 0, "name": "Photos", "entryType": "directory"},)
    session = Session(
        [
            Response(
                200,
                {
                    "claimId": CLAIM_ID,
                    "targetRootFolderIri": "https://example.org/other",
                    "findings": [],
                },
            )
        ]
    )

    try:
        _client().preflight_target(claim, entries, session=session)
    except IngestServiceUnavailable:
        pass
    else:
        raise AssertionError("A mismatched target response must fail closed.")
