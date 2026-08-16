"""Tests for the authenticated ZIP-export original resolver boundary."""

from __future__ import annotations

import hashlib
import importlib
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from export_sources import (  # noqa: E402
    EXPORT_SOURCE_TOKEN_AUDIENCE,
    ExportSourceAuthenticationUnavailable,
    ExportSourceAuthorizationError,
    ExportSourceConflictError,
    ExportSourceNotFoundError,
    ExportSourceRequestError,
    authorize_export_source_token,
    parse_export_source_request,
    resolve_export_sources,
)


EXPORT_SECRET = "export-source-service-secret-at-least-32-bytes"
ACCESS_SECRET = "export-test-access-secret-at-least-32-bytes"
MEDIA_SECRET = "export-test-media-secret-at-least-32-bytes"
ISSUER = "https://oldap.example.org"
MEDIA_IRI = "urn:uuid:11111111-1111-4111-8111-111111111111"


def _token(
    *,
    secret: str = EXPORT_SECRET,
    token_type: str = "export-source-resolver",
    subject: str = "oldap-api",
    lifetime: timedelta = timedelta(minutes=1),
) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "typ": token_type,
            "sub": subject,
            "iat": now,
            "exp": now + lifetime,
            "iss": ISSUER,
            "aud": EXPORT_SOURCE_TOKEN_AUDIENCE,
        },
        secret,
        algorithm="HS256",
    )


def _payload(**updates) -> dict:
    item = {
        "mediaIri": MEDIA_IRI,
        "assetId": "asset-one",
        "storagePathCandidate": "museum/image/archive",
        "originalName": "source.jpg",
    }
    item.update(updates)
    return {"items": [item]}


def _write_original(root: Path, content: bytes = b"\xff\xd8\xffpayload") -> Path:
    path = root / "museum/image/archive/asset-one/original/source.jpg"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    return path


def test_authorization_accepts_only_short_purpose_specific_api_tokens(
    monkeypatch,
) -> None:
    claims = authorize_export_source_token(
        f"Bearer {_token()}", secret=EXPORT_SECRET, issuer=ISSUER
    )
    assert claims["typ"] == "export-source-resolver"
    assert claims["sub"] == "oldap-api"

    for token in (
        _token(token_type="access"),
        _token(subject="media.oldap.org"),
        _token(lifetime=timedelta(minutes=5)),
    ):
        with pytest.raises(ExportSourceAuthorizationError):
            authorize_export_source_token(
                f"Bearer {token}", secret=EXPORT_SECRET, issuer=ISSUER
            )

    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", EXPORT_SECRET)
    with pytest.raises(ExportSourceAuthenticationUnavailable, match="purpose-specific"):
        authorize_export_source_token(
            f"Bearer {_token()}", secret=EXPORT_SECRET, issuer=ISSUER
        )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"items": []},
        _payload(storagePathCandidate="../museum/image"),
        _payload(originalName="../source.jpg"),
        _payload(assetId="unsafe/id"),
        _payload(mediaIri="not-an-iri"),
        {"items": _payload()["items"] * 2},
    ],
)
def test_request_parser_rejects_open_unsafe_or_duplicate_shapes(payload) -> None:
    with pytest.raises(ExportSourceRequestError):
        parse_export_source_request(payload)


def test_resolver_returns_canonical_path_size_digest_and_signature_mime(
    tmp_path: Path,
) -> None:
    content = b"\xff\xd8\xffpayload"
    _write_original(tmp_path, content)
    references = parse_export_source_request(_payload())

    resolved = resolve_export_sources(tmp_path, references)

    assert len(resolved) == 1
    assert resolved[0].to_dict() == {
        "mediaIri": MEDIA_IRI,
        "assetId": "asset-one",
        "storagePath": "museum/image/archive/asset-one/original/source.jpg",
        "originalName": "source.jpg",
        "originalMimeType": "image/jpeg",
        "sizeBytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_resolver_fails_closed_for_missing_and_symlinked_originals(
    tmp_path: Path,
) -> None:
    references = parse_export_source_request(_payload())
    with pytest.raises(ExportSourceNotFoundError):
        resolve_export_sources(tmp_path, references)

    outside = tmp_path.parent / f"{tmp_path.name}-outside.jpg"
    outside.write_bytes(b"\xff\xd8\xffoutside")
    original = tmp_path / "museum/image/archive/asset-one/original/source.jpg"
    original.parent.mkdir(parents=True)
    original.symlink_to(outside)
    with pytest.raises(ExportSourceConflictError):
        resolve_export_sources(tmp_path, references)


@pytest.fixture()
def export_app(monkeypatch, tmp_path: Path):
    """Import Flask with isolated roots and resolver authentication."""

    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path))
    monkeypatch.setenv("OLDAP_INGEST_ROOT", str(tmp_path / "ingest"))
    monkeypatch.setenv("OLDAP_IMPORT_RECORDS_ROOT", str(tmp_path / "records"))
    monkeypatch.setenv("OLDAP_EXPORT_SERVICE_JWT_SECRET", EXPORT_SECRET)
    monkeypatch.setenv("OLDAP_ACCESS_JWT_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", MEDIA_SECRET)
    monkeypatch.setenv("OLDAP_JWT_ISSUER", ISSUER)
    monkeypatch.setitem(
        sys.modules,
        "pyvips",
        types.SimpleNamespace(Image=types.SimpleNamespace()),
    )
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    return module.app.test_client(), tmp_path


def test_internal_route_is_authenticated_closed_and_all_or_nothing(export_app) -> None:
    client, media_root = export_app
    content = b"\xff\xd8\xffroute"
    _write_original(media_root, content)

    unauthorized = client.post("/internal/export-sources/resolve", json=_payload())
    assert unauthorized.status_code == 401
    assert unauthorized.headers["Cache-Control"] == "no-store"

    response = client.post(
        "/internal/export-sources/resolve",
        json=_payload(),
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert (
        response.get_json()["items"][0]["sha256"] == hashlib.sha256(content).hexdigest()
    )

    missing = client.post(
        "/internal/export-sources/resolve",
        json=_payload(originalName="missing.jpg"),
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert missing.status_code == 404
    assert missing.get_json() == {"message": "Export source original not found."}


def test_internal_route_rejects_invalid_json_without_exposing_details(
    export_app,
) -> None:
    client, _ = export_app
    response = client.post(
        "/internal/export-sources/resolve",
        data="not-json",
        content_type="application/json",
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid export source request."}
