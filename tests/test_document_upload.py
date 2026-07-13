"""Focused tests for PDF document upload and HTTP asset delivery."""

import io
import importlib
import json
import sys
import types
from pathlib import Path

import jwt
import pytest
from PIL import Image
from oldaplib.src.enums.adminpermissions import AdminPermission
from oldaplib.src.helpers.serializer import serializer
from oldaplib.src.in_project import InProjectClass
from oldaplib.src.userdataclass import UserData
from oldaplib.src.xsd.iri import Iri
from oldaplib.src.xsd.xsd_boolean import Xsd_boolean
from oldaplib.src.xsd.xsd_ncname import Xsd_NCName
from oldaplib.src.xsd.xsd_string import Xsd_string


PDF_BYTES = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture()
def media_app(monkeypatch, tmp_path):
    """Import the Flask app with a temporary media root and mocked image runtime."""
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path))
    monkeypatch.setenv("OLDAP_JWT_SECRET", "test-secret")
    monkeypatch.setenv("MEDIA_BASE_URL", "http://media.example/")
    monkeypatch.setitem(sys.modules, "pyvips", types.SimpleNamespace(Image=types.SimpleNamespace()))

    media_path = str(Path.cwd() / "mediaserver")
    if media_path not in sys.path:
        sys.path.insert(0, media_path)

    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    return module, module.app.test_client(), tmp_path


def _upload_token() -> str:
    """Build a signed token whose embedded UserData has create permission."""
    userdata = UserData(
        userIri=Iri("https://example.test/users/tester"),
        userId=Xsd_NCName("tester"),
        familyName=Xsd_string("Test"),
        givenName=Xsd_string("User"),
        email=Xsd_string("tester@example.test"),
        isActive=Xsd_boolean(True),
        inProject=InProjectClass({Iri("oldap:TestProject"): {AdminPermission.ADMIN_CREATE}}),
    )
    payload = {"userdata": json.dumps(userdata, default=serializer.encoder_default)}
    return jwt.encode(payload, "test-secret", algorithm="HS256")


class FakeOldapClient:
    """Capture media resource creation without contacting oldap-api."""

    created: list[tuple[str, dict]] = []

    def __init__(self, oldap_api_url: str, projectId: str | None = None, token: str | None = None):
        self.project = {
            "projectIri": "oldap:TestProject",
            "projectShortName": "testproject",
        }

    def create_resource(self, resource: str, resource_data: dict) -> dict:
        self.created.append((resource, resource_data))
        return {"iri": "test:mediaObject"}


class FailingCreateOldapClient(FakeOldapClient):
    """Simulate an OLDAP registration failure after local derivatives exist."""

    def create_resource(self, resource: str, resource_data: dict) -> dict:
        raise RuntimeError("OLDAP create failed")


@pytest.mark.parametrize("identifier", ["-nanoid-style", "_nanoid-style", "asset.id~1"])
def test_asset_identifier_accepts_url_safe_nanoid_characters(media_app, identifier):
    """Valid URL-safe identifiers include every character used by NanoID."""
    module, _, _ = media_app

    assert module.validate_asset_identifier(identifier) == identifier


@pytest.mark.parametrize("identifier", [".", ".."])
def test_asset_identifier_rejects_special_path_segments(media_app, identifier):
    """Special dot path segments remain invalid despite using URL-safe characters."""
    module, _, _ = media_app

    with pytest.raises(ValueError):
        module.validate_asset_identifier(identifier)


def test_legacy_asset_identifier_remains_addressable_as_safe_path_segment(media_app):
    """Existing non-traversing identifiers remain valid for auth and deletion paths."""
    module, _, _ = media_app

    assert module.validate_asset_path_segment("legacy:asset") == "legacy:asset"
    with pytest.raises(ValueError):
        module.validate_asset_identifier("legacy:asset")


def test_pdf_upload_creates_canonical_document_derivative(media_app, monkeypatch):
    """PDF uploads create an HTTP MediaObject and a stable document.pdf derivative."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    monkeypatch.setattr(
        module,
        "convert_from_path",
        lambda *args, **kwargs: [Image.new("RGB", (400, 200), "red")],
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "asset-pdf",
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/octet-stream"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["assetId"] == "asset-pdf"
    assert payload["mediaType"] == "document"
    assert payload["originalMimeType"] == "application/pdf"
    assert payload["derivativeName"] == "document.pdf"
    assert payload["dctermsType"] == "dcmitype:Text"
    assert payload["protocol"] == "http"
    assert payload["assetUrl"] == "http://media.example/asset/asset-pdf"
    assert payload["storedPath"] == "testproject/document/archive"
    assert payload["thumb128Name"] == "thumb128.jpg"
    assert payload["thumb256Name"] == "thumb256.jpg"
    assert payload["thumb128Url"] == (
        "http://media.example/asset/asset-pdf?derivative=thumb128.jpg"
    )
    assert payload["thumb256Url"] == (
        "http://media.example/asset/asset-pdf?derivative=thumb256.jpg"
    )

    assert FakeOldapClient.created == [
        (
            "shared:MediaObject",
            {
                "dcterms:type": "dcmitype:Text",
                "shared:originalName": "scan.pdf",
                "shared:originalMimeType": "application/pdf",
                "shared:serverUrl": "http://media.example/",
                "shared:assetId": "asset-pdf",
                "shared:protocol": "http",
                "shared:derivativeName": "document.pdf",
                "shared:path": "testproject/document/archive",
                "shared:mediaAccessMode": "local",
            },
        )
    ]

    asset_root = media_root / "testproject" / "document" / "archive" / "asset-pdf"
    assert (asset_root / "original" / "scan.pdf").read_bytes() == PDF_BYTES
    assert (asset_root / "derived" / "document.pdf").read_bytes() == PDF_BYTES
    with Image.open(asset_root / "derived" / "thumb128.jpg") as thumbnail:
        assert thumbnail.size == (128, 128)
        assert thumbnail.format == "JPEG"
        assert thumbnail.getpixel((64, 64))[0] > 200
        assert min(thumbnail.getpixel((64, 8))) > 240
    with Image.open(asset_root / "derived" / "thumb256.jpg") as thumbnail:
        assert thumbnail.size == (256, 256)
        assert thumbnail.format == "JPEG"


def test_unrenderable_pdf_is_rejected_without_creating_media(media_app, monkeypatch):
    """A PDF whose first page Poppler cannot render leaves no asset or OLDAP object."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    def fail_render(*args, **kwargs):
        raise module.PDFPageCountError("Unable to read PDF page count")

    monkeypatch.setattr(module, "convert_from_path", fail_render)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "unrenderable-pdf",
            "file": (io.BytesIO(PDF_BYTES), "broken.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "first PDF page" in response.get_json()["message"]
    assert FakeOldapClient.created == []
    assert not (
        media_root / "testproject" / "document" / "archive" / "unrenderable-pdf"
    ).exists()


def test_oldap_create_failure_removes_new_pdf_asset(media_app, monkeypatch):
    """A failed MediaObject registration removes the newly rendered PDF asset."""
    module, client, media_root = media_app
    monkeypatch.setattr(module, "OldapClient", FailingCreateOldapClient)
    monkeypatch.setattr(
        module,
        "convert_from_path",
        lambda *args, **kwargs: [Image.new("RGB", (200, 400), "blue")],
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "oldap-create-failure",
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 500
    assert "Failed to create OLDAP resource" in response.get_json()["error"]
    assert not (
        media_root / "testproject" / "document" / "archive" / "oldap-create-failure"
    ).exists()


def test_conversion_failure_removes_new_non_document_asset(media_app, monkeypatch):
    """A failed conversion does not leave an asset directory that blocks retries."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="simulated ffprobe failure",
        ),
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "audio-conversion-failure",
            "file": (io.BytesIO(b"not audio"), "sound.mp3", "audio/mpeg"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 500
    assert "ffprobe audio validation failed" in response.get_json()["error"]
    assert FakeOldapClient.created == []
    assert not (
        media_root / "testproject" / "audio" / "audio-conversion-failure"
    ).exists()


def test_invalid_pdf_upload_is_rejected_before_resource_creation(media_app, monkeypatch):
    """Spoofed or incomplete PDF uploads do not create OLDAP resources or asset folders."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "bad-pdf",
            "file": (io.BytesIO(b"%PDF-1.4\nmissing EOF"), "bad.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "PDF" in response.get_json()["message"]
    assert FakeOldapClient.created == []
    assert not (media_root / "testproject" / "document" / "bad-pdf").exists()


@pytest.mark.parametrize("identifier", ["../../escaped-asset", "asset?query"])
def test_upload_rejects_unsafe_asset_identifier(media_app, monkeypatch, identifier):
    """An explicit asset identifier must be safe in filesystem paths and URLs."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": identifier,
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "identifier" in response.get_json()["message"]
    assert FakeOldapClient.created == []
    assert not (media_root / "escaped-asset").exists()


def test_upload_rejects_asset_path_symlink_escape(media_app, monkeypatch, tmp_path_factory):
    """A storage subpath symlink cannot redirect an upload outside the media root."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    outside = tmp_path_factory.mktemp("outside-media-root")
    linked_path = media_root / "testproject" / "document" / "linked"
    linked_path.parent.mkdir(parents=True)
    linked_path.symlink_to(outside, target_is_directory=True)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "linked",
            "identifier": "symlink-escape",
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 403
    assert "escapes media root" in response.get_json()["message"]
    assert FakeOldapClient.created == []
    assert not (outside / "symlink-escape").exists()


def test_existing_asset_identifier_is_rejected_without_modification(media_app, monkeypatch):
    """A duplicate asset identifier is rejected before existing files are touched."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    existing = media_root / "testproject" / "document" / "existing-pdf" / "derived" / "document.pdf"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(PDF_BYTES)
    existing_thumbnail = existing.parent / "thumb256.jpg"
    existing_thumbnail.write_bytes(b"existing thumbnail")

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "existing-pdf",
            "file": (io.BytesIO(PDF_BYTES), "replacement.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 409
    assert "already exists" in response.get_json()["message"]
    assert existing.read_bytes() == PDF_BYTES
    assert existing_thumbnail.read_bytes() == b"existing thumbnail"
    assert FakeOldapClient.created == []


def test_asset_directory_initialization_failure_is_cleaned_up(media_app, monkeypatch):
    """A partial asset directory is removed when its child directories cannot be created."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    original_mkdir = Path.mkdir

    def fail_derived_directory(path, *args, **kwargs):
        if path.name == "derived" and path.parent.name == "directory-init-failure":
            raise OSError("simulated directory error")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_derived_directory)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "directory-init-failure",
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 500
    assert "Could not initialize asset directory" in response.get_json()["error"]
    assert FakeOldapClient.created == []
    assert not (
        media_root / "testproject" / "document" / "directory-init-failure"
    ).exists()


def test_original_copy_failure_releases_asset_identifier(media_app, monkeypatch):
    """A failed original copy removes both temporary and reserved asset files."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    def fail_copy(*args, **kwargs):
        raise OSError("simulated copy error")

    monkeypatch.setattr(module.shutil, "copy2", fail_copy)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "original-copy-failure",
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 500
    assert "Could not store uploaded file" in response.get_json()["error"]
    assert FakeOldapClient.created == []
    assert not (
        media_root / "testproject" / "document" / "original-copy-failure"
    ).exists()
    assert not (media_root / "_tmp" / "original-copy-failure.pdf").exists()


def test_pdf_derivative_resolves_as_http_asset(media_app):
    """PDF derivatives are delivered through the HTTP asset path, not IIIF."""
    _, client, media_root = media_app
    asset_id = "asset-pdf"
    derived = media_root / "fasnacht" / "document" / "archive" / asset_id / "derived" / "document.pdf"
    derived.parent.mkdir(parents=True)
    derived.write_bytes(PDF_BYTES)
    thumbnail = derived.parent / "thumb256.jpg"
    Image.new("RGB", (256, 256), "white").save(thumbnail, format="JPEG")

    token = jwt.encode(
        {
            "assetId": asset_id,
            "path": "fasnacht/document/archive",
            "originalName": "scan.pdf",
            "derivativeName": "document.pdf",
            "protocol": "http",
        },
        "test-secret",
        algorithm="HS256",
    )
    response = client.get(f"/auth/asset/{asset_id}?token={token}")

    assert response.status_code == 204
    assert response.headers["X-OLDAP-Internal-Path"] == str(derived.resolve())
    assert response.headers["X-OLDAP-Content-Type"] == "application/pdf"
    assert response.headers["X-OLDAP-Content-Disposition"] == 'inline; filename="document.pdf"'

    thumbnail_response = client.get(
        f"/auth/asset/{asset_id}?token={token}&derivative=thumb256.jpg"
    )

    assert thumbnail_response.status_code == 204
    assert thumbnail_response.headers["X-OLDAP-Internal-Path"] == str(thumbnail.resolve())
    assert thumbnail_response.headers["X-OLDAP-Content-Type"] == "image/jpeg"
