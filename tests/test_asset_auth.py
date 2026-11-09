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
    monkeypatch.setenv("OLDAP_MOBILE_UPLOAD_ROOT", str(tmp_path / "mobile-uploads"))
    monkeypatch.setenv("OLDAP_ACCESS_JWT_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", MEDIA_SECRET)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173,https://public.example")
    monkeypatch.delenv("MEDIAHELPER_VERSION", raising=False)
    monkeypatch.delenv("MEDIASERVER_VERSION", raising=False)
    monkeypatch.setitem(
        sys.modules, "pyvips", types.SimpleNamespace(Image=types.SimpleNamespace())
    )

    media_path = str(Path.cwd() / "mediaserver")
    if media_path not in sys.path:
        sys.path.insert(0, media_path)

    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    return module, module.app.test_client(), tmp_path


def _asset_token(asset_id: str, **claims) -> str:
    payload = {
        "assetId": asset_id,
        "permval": 2,
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


def test_mobile_routes_are_additive_and_reject_media_capabilities(media_app):
    """The new transport is registered without weakening token-purpose separation."""

    module, client, _ = media_app
    rules: dict[str, set[str]] = {}
    for rule in module.app.url_map.iter_rules():
        rules.setdefault(rule.rule, set()).update(rule.methods or ())
    rejected = client.post(
        "/media/v1/uploads",
        headers={"Authorization": f"Bearer {_asset_token('asset-iiif')}"},
    )

    assert "POST" in rules["/upload"]
    assert "POST" in rules["/media/v1/uploads"]
    assert "GET" in rules["/media/v1/uploads/<upload_id>"]
    assert "PATCH" in rules["/media/v1/uploads/<upload_id>"]
    assert "DELETE" in rules["/media/v1/uploads/<upload_id>"]
    assert "POST" in rules["/media/v1/uploads/<upload_id>/commit"]
    assert rejected.status_code == 401
    assert rejected.content_type == "application/problem+json"
    assert rejected.json["code"] == "authentication_invalid"


@pytest.mark.parametrize("permission", [1, 2, 6])
def test_iiif_original_download_resolves_as_attachment(media_app, permission):
    """IIIF originals are downloadable through /asset while preserving auth headers."""
    module, client, media_root = media_app
    asset_id = "asset-iiif"
    original = (
        media_root / "fasnacht/image/archive" / asset_id / "original" / "source.tif"
    )
    original.parent.mkdir(parents=True)
    original.write_bytes(b"original")

    token = _asset_token(asset_id, permval=permission)
    response = client.get(
        f"/auth/asset/{asset_id}/original?token={token}&download=1",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 204
    assert response.headers["X-OLDAP-Internal-Path"] == str(original.resolve())
    assert (
        response.headers["X-OLDAP-Content-Disposition"]
        == 'attachment; filename="source.tif"'
    )
    assert response.headers["X-OLDAP-Cors-Allow-Origin"] == "http://localhost:5173"
    assert Path(response.headers["X-OLDAP-Internal-Path"]).is_relative_to(
        module.IMAGE_ROOT.resolve()
    )


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
    original = (
        media_root / "fasnacht/image/archive" / asset_id / "original" / "source.tif"
    )
    original.parent.mkdir(parents=True)
    original.write_bytes(b"original")

    token = _asset_token(asset_id, protocol="http")
    response = client.get(f"/auth/asset/{asset_id}/original?token={token}")

    assert response.status_code == 204
    assert (
        response.headers["X-OLDAP-Content-Disposition"]
        == 'inline; filename="source.tif"'
    )


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


@pytest.mark.parametrize("permission", [0, -1, 7, None, True, False, "2", 1.5, [], {}])
def test_signed_invalid_permission_never_falls_back(media_app, monkeypatch, permission):
    """Signed but invalid grants must fail before lookup or path resolution."""
    module, client, _ = media_app

    def unexpected_lookup(*args, **kwargs):
        pytest.fail("Rejected capability must not perform anonymous lookup")

    monkeypatch.setattr(module, "OldapClient", unexpected_lookup)
    token = _asset_token("asset", permval=permission)
    assert (
        client.get(
            "/auth/asset/asset/original", query_string={"token": token}
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "claims",
    [
        {"assetId": None},
        {"assetId": "other"},
        {"id": "asset", "assetId": "other"},
        {"id": "other", "assetId": "asset"},
    ],
)
def test_capability_identity_cannot_fall_back(media_app, monkeypatch, claims):
    """Every supplied asset identifier must match the requested asset."""
    module, client, _ = media_app

    def unexpected_lookup(*args, **kwargs):
        pytest.fail("Mismatched capability must not perform anonymous lookup")

    monkeypatch.setattr(module, "OldapClient", unexpected_lookup)
    token = _asset_token("asset", **claims)
    assert (
        client.get(
            "/auth/asset/asset/original", query_string={"token": token}
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "query", ["token=", "token=invalid", "token=invalid&token=also-invalid"]
)
def test_supplied_invalid_token_never_falls_back(media_app, monkeypatch, query):
    """Presence of a token selects capability authorization, including empty input."""
    module, client, _ = media_app

    def unexpected_lookup(*args, **kwargs):
        pytest.fail("Invalid supplied token must not perform anonymous lookup")

    monkeypatch.setattr(module, "OldapClient", unexpected_lookup)
    assert client.get("/auth/asset/asset/original?" + query).status_code == 403


@pytest.mark.parametrize("permission", [1, 2, 6, 0, None, True, "2"])
def test_tokenless_lookup_checks_permission(media_app, monkeypatch, permission):
    """Public resolution remains available but must carry a valid numeric grant."""
    from types import SimpleNamespace

    module, client, root = media_app
    original = root / "public" / "asset" / "original" / "test.pdf"
    original.parent.mkdir(parents=True)
    original.write_bytes(b"%PDF-test")
    monkeypatch.setattr(
        module,
        "OldapClient",
        lambda **kwargs: SimpleNamespace(
            get_mediaobject_by_assetid_unknown=lambda asset: {
                "shared:path": "public",
                "shared:originalName": "test.pdf",
                "shared:protocol": "http",
                "permval": permission,
            }
        ),
    )
    expected = 204 if type(permission) is int and permission in (1, 2, 6) else 403
    assert client.get("/auth/asset/asset/original").status_code == expected


def test_expired_capability_never_falls_back(media_app, monkeypatch):
    """Expiry remains a denial even if the requested file might be public."""
    import jwt

    module, client, _ = media_app

    def unexpected_lookup(*args, **kwargs):
        pytest.fail("Expired token must not perform anonymous lookup")

    monkeypatch.setattr(module, "OldapClient", unexpected_lookup)
    claims = jwt.decode(
        _asset_token("asset"),
        MEDIA_SECRET,
        algorithms=["HS256"],
        audience="oldap-api-media",
    )
    claims["exp"] = 1
    token = jwt.encode(claims, MEDIA_SECRET, algorithm="HS256")
    assert (
        client.get(
            "/auth/asset/asset/original", query_string={"token": token}
        ).status_code
        == 403
    )


@pytest.mark.parametrize("missing", ["permval", "assetId"])
def test_missing_capability_grant_or_identity_is_denied(
    media_app, monkeypatch, missing
):
    """A correctly signed envelope without a grant or asset binding is insufficient."""
    import jwt

    module, client, _ = media_app

    def unexpected_lookup(*args, **kwargs):
        pytest.fail("Incomplete capability must not perform anonymous lookup")

    monkeypatch.setattr(module, "OldapClient", unexpected_lookup)
    claims = jwt.decode(
        _asset_token("asset"),
        MEDIA_SECRET,
        algorithms=["HS256"],
        audience="oldap-api-media",
    )
    del claims[missing]
    token = jwt.encode(claims, MEDIA_SECRET, algorithm="HS256")
    assert (
        client.get(
            "/auth/asset/asset/original", query_string={"token": token}
        ).status_code
        == 403
    )
