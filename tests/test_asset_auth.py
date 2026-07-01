"""Focused tests for Caddy asset authorization decisions."""

import importlib
import sys
import types
from pathlib import Path

import jwt
import pytest


@pytest.fixture()
def media_app(monkeypatch, tmp_path):
    """Import the Flask app with a temporary media root and mocked image runtime."""
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path))
    monkeypatch.setenv("OLDAP_JWT_SECRET", "test-secret")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173,https://public.example")
    monkeypatch.setitem(sys.modules, "pyvips", types.SimpleNamespace(Image=types.SimpleNamespace()))

    media_path = str(Path.cwd() / "mediaserver")
    if media_path not in sys.path:
        sys.path.insert(0, media_path)

    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    return module, module.app.test_client(), tmp_path


def _asset_token(asset_id: str, **claims) -> str:
    payload = {
        "assetId": asset_id,
        "path": "fasnacht/image/archive",
        "originalName": "source.tif",
        "derivativeName": "iiif.jp2",
        "protocol": "iiif",
    }
    payload.update(claims)
    return jwt.encode(payload, "test-secret", algorithm="HS256")


def test_iiif_original_download_resolves_as_attachment(media_app):
    """IIIF originals are downloadable through /asset while preserving auth headers."""
    module, client, media_root = media_app
    asset_id = "asset-iiif"
    original = media_root / "fasnacht/image/archive" / asset_id / "original" / "source.tif"
    original.parent.mkdir(parents=True)
    original.write_bytes(b"original")

    token = _asset_token(asset_id)
    response = client.get(
        f"/auth/asset/{asset_id}/original?token={token}&download=1",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 204
    assert response.headers["X-OLDAP-Internal-Path"] == str(original.resolve())
    assert response.headers["X-OLDAP-Content-Disposition"] == 'attachment; filename="source.tif"'
    assert response.headers["X-OLDAP-Cors-Allow-Origin"] == "http://localhost:5173"
    assert Path(response.headers["X-OLDAP-Internal-Path"]).is_relative_to(module.IMAGE_ROOT.resolve())


def test_iiif_derived_is_not_served_through_asset_endpoint(media_app):
    """IIIF derivatives must stay behind the IIIF image server, not /asset."""
    _, client, _ = media_app
    asset_id = "asset-iiif"
    token = _asset_token(asset_id)

    response = client.get(f"/auth/asset/{asset_id}/derived?token={token}")

    assert response.status_code == 403


def test_original_without_download_stays_inline(media_app):
    """Original files remain inline unless the caller explicitly asks for download=1."""
    _, client, media_root = media_app
    asset_id = "asset-http"
    original = media_root / "fasnacht/image/archive" / asset_id / "original" / "source.tif"
    original.parent.mkdir(parents=True)
    original.write_bytes(b"original")

    token = _asset_token(asset_id, protocol="http")
    response = client.get(f"/auth/asset/{asset_id}/original?token={token}")

    assert response.status_code == 204
    assert response.headers["X-OLDAP-Content-Disposition"] == 'inline; filename="source.tif"'


def test_auth_asset_preflight_uses_configured_cors_origins(media_app):
    """CORS preflight succeeds only with headers for configured browser origins."""
    _, client, _ = media_app

    allowed = client.options(
        "/auth/asset/asset-iiif/original",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    denied = client.options(
        "/auth/asset/asset-iiif/original",
        headers={
            "Origin": "https://not-configured.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://localhost:5173"
    assert "GET" in allowed.headers["Access-Control-Allow-Methods"]
    assert "Access-Control-Allow-Origin" not in denied.headers
