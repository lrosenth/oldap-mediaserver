"""Focused tests for PDF document upload and HTTP asset delivery."""

import io
import importlib
import json
import sys
import types
from pathlib import Path

import jwt
import pytest
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


def test_pdf_upload_creates_canonical_document_derivative(media_app, monkeypatch):
    """PDF uploads create an HTTP MediaObject and a stable document.pdf derivative."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

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


def test_invalid_pdf_upload_does_not_remove_existing_asset_directory(media_app, monkeypatch):
    """Rejecting a bad PDF must not delete files from an existing assetId."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    existing = media_root / "testproject" / "document" / "existing-pdf" / "derived" / "document.pdf"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(PDF_BYTES)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "existing-pdf",
            "file": (io.BytesIO(b"%PDF-1.4\nmissing EOF"), "bad.pdf", "application/pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert existing.read_bytes() == PDF_BYTES
    assert FakeOldapClient.created == []


def test_pdf_derivative_resolves_as_http_asset(media_app):
    """PDF derivatives are delivered through the HTTP asset path, not IIIF."""
    _, client, media_root = media_app
    asset_id = "asset-pdf"
    derived = media_root / "fasnacht" / "document" / "archive" / asset_id / "derived" / "document.pdf"
    derived.parent.mkdir(parents=True)
    derived.write_bytes(PDF_BYTES)

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
