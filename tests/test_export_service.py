"""Contract tests for the export worker control-plane client."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import rfc8785

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mediaserver"))

from export_service import (  # noqa: E402
    SERVICE_TOKEN_AUDIENCE,
    SERVICE_TOKEN_TYPE,
    BuildClaim,
    ExportServiceClient,
    ExportServiceUnavailable,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
EXPORT_ID = "11111111-1111-4111-8111-111111111111"
CLAIM_ID = "22222222-2222-4222-8222-222222222222"
SECRET = "export-service-secret-at-least-32-bytes"


class Response:
    """Minimal requests-compatible response stub."""

    def __init__(self, status: int, value: object, *, content: bytes | None = None):
        self.status_code = status
        self._value = value
        self.content = content if content is not None else json.dumps(value).encode()
        self.headers: dict[str, str] = {}

    def json(self) -> object:
        return self._value


class Session:
    """Capture one client request and return a prepared response."""

    def __init__(self, response: Response):
        self.response = response
        self.calls: list[tuple[object, ...]] = []

    def request(self, *args: object, **kwargs: object) -> Response:
        self.calls.append((*args, kwargs))
        return self.response


def client() -> ExportServiceClient:
    return ExportServiceClient("https://api.example", SECRET, "worker-1")


def test_claim_uses_a_purpose_specific_service_token() -> None:
    response = Response(
        200,
        {
            "claimId": CLAIM_ID,
            "exportId": EXPORT_ID,
            "task": "BUILD",
            "stateVersion": 3,
            "claimedAt": NOW.isoformat(),
            "leaseExpiresAt": (NOW + timedelta(minutes=5)).isoformat(),
            "manifestSha256": "a" * 64,
        },
    )
    session = Session(response)

    claim = client().claim_next(session=session)

    assert isinstance(claim, BuildClaim)
    method, url, options = session.calls[0]
    assert method == "POST"
    assert url == "https://api.example/internal/export-claims"
    token = options["headers"]["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(
        token,
        SECRET,
        algorithms=["HS256"],
        audience=SERVICE_TOKEN_AUDIENCE,
        issuer="https://oldap.org",
    )
    assert claims["typ"] == SERVICE_TOKEN_TYPE
    assert set(options["json"]["supportedTasks"]) == {"BUILD", "CLEANUP"}


def manifest(*, kind: str = "STAGING_FOLDER") -> dict[str, object]:
    """Return one minimal manifest envelope for worker contract tests."""

    value: dict[str, object] = {
        "documentType": "oldap.zip-export.manifest",
        "schemaVersion": "1.0.0",
        "exportId": EXPORT_ID,
        "generatedAt": NOW.isoformat(),
        "kind": kind,
        "projectShortName": "future-project",
        "requestedByIri": "https://example.org/users/alice",
        "profile": {},
        "selection": {},
        "limits": {"maxArchiveBytes": 50_000_000_000},
        "directories": [],
        "media": [],
    }
    if kind in {"ARCHIVE_UNIT", "ARCHIVE_ALL"}:
        value["archiveUnits"] = []
    return value


def response_for_manifest(value: dict[str, object]) -> tuple[Response, BuildClaim]:
    """Bind canonical manifest bytes and Digest header to a build claim."""

    content = rfc8785.dumps(value)
    digest = hashlib.sha256(content).hexdigest()
    claim = BuildClaim(CLAIM_ID, EXPORT_ID, 3, NOW, NOW + timedelta(minutes=5), digest)
    response = Response(200, value, content=content)
    import base64

    response.headers["Digest"] = (
        "sha-256=" + base64.b64encode(bytes.fromhex(digest)).decode()
    )
    return response, claim


def test_manifest_requires_canonical_bytes_and_claim_digest() -> None:
    value = manifest()
    response, claim = response_for_manifest(value)
    assert client().get_manifest(claim, session=Session(response)) == value

    response.content += b" "
    try:
        client().get_manifest(claim, session=Session(response))
    except ExportServiceUnavailable:
        pass
    else:
        raise AssertionError("non-canonical or digest-mismatched manifest accepted")


def test_manifest_accepts_a_bounded_deployment_archive_limit() -> None:
    value = manifest()
    value["limits"] = {"maxArchiveBytes": 1_000_000}
    response, claim = response_for_manifest(value)

    assert client().get_manifest(claim, session=Session(response)) == value

    value["limits"] = {"maxArchiveBytes": 50_000_000_001}
    response, claim = response_for_manifest(value)
    try:
        client().get_manifest(claim, session=Session(response))
    except ExportServiceUnavailable:
        pass
    else:
        raise AssertionError("manifest above the v1 hard ceiling accepted")


def test_manifest_accepts_archive_units_only_for_archive_exports() -> None:
    value = manifest(kind="ARCHIVE_UNIT")
    response, claim = response_for_manifest(value)
    assert client().get_manifest(claim, session=Session(response)) == value

    staging = manifest()
    staging["archiveUnits"] = []
    response, claim = response_for_manifest(staging)
    try:
        client().get_manifest(claim, session=Session(response))
    except ExportServiceUnavailable:
        pass
    else:
        raise AssertionError("archiveUnits accepted for a staging export")

    archive = manifest(kind="ARCHIVE_ALL")
    del archive["archiveUnits"]
    response, claim = response_for_manifest(archive)
    try:
        client().get_manifest(claim, session=Session(response))
    except ExportServiceUnavailable:
        pass
    else:
        raise AssertionError("archive manifest without archiveUnits accepted")
