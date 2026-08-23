"""Tests for current OLDAP permission and protected Mobile-inbox verification."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest
import requests


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from mobile_staging import OldapMobileStagingVerifier  # noqa: E402
from mobile_upload_domain import MobileUploadError  # noqa: E402


AREA = "urn:uuid:11111111-1111-4111-8111-111111111111"
ORGANISATION = "urn:uuid:22222222-2222-4222-8222-222222222222"
ROLE = "urn:uuid:33333333-3333-4333-8333-333333333333"
TOP = "urn:uuid:44444444-4444-4444-8444-444444444444"
MOBILE = "urn:uuid:55555555-5555-4555-8555-555555555555"


class Response:
    def __init__(self, status: int, value: Any) -> None:
        self.status_code = status
        self.value = value

    def json(self) -> Any:
        return self.value


class Session:
    def __init__(self, responses: list[Response | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.calls.append((method, url, kwargs))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def valid_responses(*, mobile_roles: dict[str, str] | None = None) -> list[Response]:
    return [
        Response(
            200,
            {
                "userId": "alice",
                "isActive": True,
                "userclass": "fasnacht:FasnachtUser",
                "inProjects": [
                    {
                        "project": "https://fasnacht.digital",
                        "permissions": ["oldap:ADMIN_CREATE"],
                    }
                ],
                "hasRole": {ROLE: ["DATA_VIEW"]},
                "additionalProperties": {
                    "fasnacht:memberOfOrganisation": [ORGANISATION]
                },
            },
        ),
        Response(
            200,
            {
                "iri": AREA,
                "rdf:type": ["fasnacht:StagingArea"],
                "fasnacht:depositingOrganisation": ORGANISATION,
                "shared:stagingDefaultRole": ROLE,
            },
        ),
        Response(
            200,
            [
                {
                    "iri": TOP,
                    "schema:name": ["top@de"],
                    "shared:inStagingArea": AREA,
                },
                {
                    "iri": MOBILE,
                    "schema:name": ["Mobile@de"],
                    "shared:inStagingArea": AREA,
                    "shared:inStagingFolder": TOP,
                },
            ],
        ),
        Response(
            200,
            {
                "rdf:type": ["shared:StagingFolder"],
                "oldap:attachedToRole": mobile_roles or {ROLE: "DATA_VIEW"},
            },
        ),
    ]


def test_verifier_resolves_only_current_exact_read_only_mobile_inbox() -> None:
    session = Session(valid_responses())
    verifier = OldapMobileStagingVerifier("https://api.example/", session=session)

    result = verifier.verify("access-token", "alice", AREA)

    assert result.staging_area_id == AREA
    assert result.mobile_folder_id == MOBILE
    assert result.default_role_id == ROLE
    assert len(session.calls) == 4
    assert all(
        call[2]["headers"]["Authorization"] == "Bearer access-token"
        for call in session.calls
    )
    assert session.calls[2][2]["json"]["includeProperties"] == [
        "schema:name",
        "shared:inStagingArea",
        "shared:inStagingFolder",
    ]


@pytest.mark.parametrize(
    "responses",
    [
        valid_responses(mobile_roles={ROLE: "DATA_UPDATE"}),
        [*valid_responses()[:2], Response(200, [])],
        [
            *valid_responses()[:2],
            Response(
                200,
                [
                    {
                        "iri": TOP,
                        "schema:name": "top",
                        "shared:inStagingArea": AREA,
                    },
                    {
                        "iri": MOBILE,
                        "schema:name": "mobile",
                        "shared:inStagingArea": AREA,
                        "shared:inStagingFolder": TOP,
                    },
                ],
            ),
        ],
    ],
)
def test_verifier_fails_closed_for_unprotected_missing_or_misnamed_inbox(
    responses: list[Response],
) -> None:
    verifier = OldapMobileStagingVerifier(
        "https://api.example", session=Session(responses)
    )
    with pytest.raises(MobileUploadError) as denied:
        verifier.verify("access-token", "alice", AREA)
    assert denied.value.status == 403
    assert denied.value.code == "mobile_destination_unavailable"


def test_verifier_rejects_a_mismatched_staging_area_response() -> None:
    responses = valid_responses()
    responses[1].value["iri"] = "urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    verifier = OldapMobileStagingVerifier(
        "https://api.example", session=Session(responses)
    )

    with pytest.raises(MobileUploadError) as denied:
        verifier.verify("access-token", "alice", AREA)

    assert denied.value.status == 403
    assert denied.value.code == "mobile_destination_unavailable"


def test_verifier_maps_authentication_and_backend_failure_without_leaking_details() -> (
    None
):
    unauthorized = OldapMobileStagingVerifier(
        "https://api.example", session=Session([Response(401, {"secret": "detail"})])
    )
    unavailable = OldapMobileStagingVerifier(
        "https://api.example",
        session=Session([requests.ConnectionError("private network detail")]),
    )

    with pytest.raises(MobileUploadError) as authentication:
        unauthorized.verify("expired", "alice", AREA)
    with pytest.raises(MobileUploadError) as backend:
        unavailable.verify("access", "alice", AREA)

    assert authentication.value.status == 401
    assert authentication.value.code == "authentication_invalid"
    assert backend.value.status == 503
    assert backend.value.retryable is True
    assert "private" not in str(backend.value)


def test_default_http_sessions_are_isolated_per_worker_thread(monkeypatch) -> None:
    created: list[object] = []

    def session_factory() -> object:
        session = object()
        created.append(session)
        return session

    monkeypatch.setattr(requests, "Session", session_factory)
    verifier = OldapMobileStagingVerifier("https://api.example")
    barrier = Barrier(2)

    def obtain_session() -> tuple[int, int]:
        first = verifier._http_session()
        barrier.wait()
        second = verifier._http_session()
        return id(first), id(second)

    with ThreadPoolExecutor(max_workers=2) as executor:
        sessions = list(executor.map(lambda _: obtain_session(), range(2)))

    assert all(first == second for first, second in sessions)
    assert sessions[0][0] != sessions[1][0]
    assert len(created) == 2
