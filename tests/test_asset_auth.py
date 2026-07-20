"""Focused tests for Caddy asset authorization decisions."""

import importlib
import sys
import types
from pathlib import Path

import pytest
from oldaplib.src.authentication import TokenCodec, TokenSettings


ACCESS_SECRET = "mediaserver-test-access-secret-at-least-32-bytes"
MEDIA_SECRET = "mediaserver-test-media-secret-at-least-32-bytes"


@pytest.fixture()
def media_app(monkeypatch, tmp_path):
    """Import the Flask app with a temporary media root and mocked image runtime."""
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path))
    monkeypatch.setenv("OLDAP_ACCESS_JWT_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", MEDIA_SECRET)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173,https://public.example")
    monkeypatch.delenv("MEDIAHELPER_VERSION", raising=False)
    monkeypatch.delenv("MEDIASERVER_VERSION", raising=False)
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
        "derivativeName": "master.tif",
        "protocol": "iiif",
    }
    payload.update(claims)
    codec = TokenCodec(
        TokenSettings(access_secret=ACCESS_SECRET, media_secret=MEDIA_SECRET)
    )
    return codec.issue_media_token("tester", payload)


def test_detect_app_version_reads_component_version_file(media_app, monkeypatch):
    """Direct local runs report the checked-in mediahelper component version."""
    module, _, _ = media_app
    monkeypatch.delenv("MEDIAHELPER_VERSION", raising=False)
    monkeypatch.delenv("MEDIASERVER_VERSION", raising=False)

    version, source = module.detect_app_version()
    version_path = Path(module.__file__).resolve().parent / "VERSION"

    assert version == version_path.read_text(encoding="utf-8").strip()
    assert source == f"file:{version_path}"


def test_detect_app_version_prefers_image_environment(media_app, monkeypatch):
    """Container metadata overrides the source-tree VERSION file at runtime."""
    module, _, _ = media_app
    monkeypatch.setenv("MEDIAHELPER_VERSION", "1.2.3")

    assert module.detect_app_version() == ("1.2.3", "env:MEDIAHELPER_VERSION")


def test_status_reports_mediahelper_component_version(media_app):
    """The public status payload exposes the resolved component version."""
    module, client, _ = media_app
    version_path = Path(module.__file__).resolve().parent / "VERSION"

    response = client.get("/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "service": "oldap-mediahelper",
        "status": "ok",
        "version": version_path.read_text(encoding="utf-8").strip(),
        "versionSource": f"file:{version_path}",
    }


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
