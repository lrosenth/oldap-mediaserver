"""Focused tests for PDF document upload and HTTP asset delivery."""

import io
import importlib
import hashlib
import sys
import types
from contextlib import contextmanager
from pathlib import Path

import pytest
from pdf2image.exceptions import PDFPageCountError
from PIL import Image
from oldaplib.src.authentication import AuthorizationContext, TokenCodec, TokenSettings
from oldaplib.src.enums.adminpermissions import AdminPermission
from oldaplib.src.helpers.observable_dict import ObservableDict
from oldaplib.src.in_project import InProjectClass
from oldaplib.src.xsd.iri import Iri
from oldaplib.src.xsd.xsd_ncname import Xsd_NCName


PDF_BYTES = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
ACCESS_SECRET = "mediaserver-test-access-secret-at-least-32-bytes"
MEDIA_SECRET = "mediaserver-test-media-secret-at-least-32-bytes"


@pytest.fixture()
def media_app(monkeypatch, tmp_path):
    """Import the Flask app with a temporary media root and mocked image runtime."""
    monkeypatch.setenv("UPLOADER_IMGDIR", str(tmp_path))
    monkeypatch.setenv("OLDAP_MOBILE_UPLOAD_ROOT", str(tmp_path / "mobile-uploads"))
    monkeypatch.setenv("OLDAP_ACCESS_JWT_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("OLDAP_MEDIA_JWT_SECRET", MEDIA_SECRET)
    monkeypatch.setenv("MEDIA_BASE_URL", "http://media.example/")
    monkeypatch.setitem(
        sys.modules, "pyvips", types.SimpleNamespace(Image=types.SimpleNamespace())
    )

    media_path = str(Path.cwd() / "mediaserver")
    if media_path not in sys.path:
        sys.path.insert(0, media_path)

    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    return module, module.app.test_client(), tmp_path


def _codec() -> TokenCodec:
    return TokenCodec(
        TokenSettings(access_secret=ACCESS_SECRET, media_secret=MEDIA_SECRET)
    )


def _upload_token() -> str:
    """Build an access token whose authorization context permits creation."""
    context = AuthorizationContext(
        userIri=Iri("https://example.test/users/tester"),
        userId=Xsd_NCName("tester"),
        inProject=InProjectClass(
            {Iri("oldap:TestProject"): {AdminPermission.ADMIN_CREATE}}
        ),
        hasRole=ObservableDict(),
    )
    return _codec().issue_access_token(context)


def test_upload_rejects_media_capability_as_bearer(media_app):
    """A media delivery capability must not authenticate an upload request."""
    _, client, _ = media_app
    media_token = _codec().issue_media_token("tester", {"assetId": "asset-pdf"})

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {media_token}"},
    )

    assert response.status_code == 401


def test_delete_requires_access_token(media_app):
    """Asset deletion rejects missing credentials and media capabilities."""
    _, client, _ = media_app
    media_token = _codec().issue_media_token("tester", {"assetId": "asset-pdf"})

    missing = client.delete("/upload/asset-pdf")
    media_capability = client.delete(
        "/upload/asset-pdf",
        headers={"Authorization": f"Bearer {media_token}"},
    )

    assert missing.status_code == 401
    assert media_capability.status_code == 401


@pytest.mark.parametrize(
    "outcome", ["success", "conflict", "timeout", "cleanup_failure"]
)
def test_legacy_delete_coordinates_exact_mobile_files_with_the_worker_lock(
    media_app, monkeypatch, outcome
):
    """Mobile-origin deletion shares owner checks and locking without changing the route."""

    module, client, media_root = media_app
    asset_id = "11111111-1111-4111-8111-111111111111"
    resource_iri = "urn:uuid:22222222-2222-4222-8222-222222222222"
    asset_root = media_root / "test/image/mobile" / asset_id
    asset_root.mkdir(parents=True)
    calls: list[str] = []

    class Response:
        status_code = 200
        text = "ok"

        def __init__(self, payload=None):
            self._payload = payload

        def json(self):
            return self._payload

    monkeypatch.setattr(
        module.requests,
        "get",
        lambda *args, **kwargs: Response(
            {
                "graph": "test:data",
                "permval": module.DataPermission.DATA_DELETE.numeric,
                "iri": resource_iri,
                "shared:assetId": asset_id,
                "shared:path": "test/image/mobile",
            }
        ),
    )

    def authoritative_delete(*args, **kwargs):
        assert asset_root.exists()
        assert calls == []
        calls.append("oldap-delete")
        if outcome == "timeout":
            raise module.requests.exceptions.Timeout("ambiguous deletion")
        response = Response()
        if outcome == "conflict":
            response.status_code = 409
        return response

    monkeypatch.setattr(module.requests, "delete", authoritative_delete)
    mobile_asset = types.SimpleNamespace(
        upload_id="33333333-3333-4333-8333-333333333333",
        client_asset_id=asset_id,
        original_name="photo.jpg",
        original_mime_type="image/jpeg",
        byte_length=8,
        checksum="sha256:" + "a" * 64,
        storage_path="test/image/mobile",
        upload_directory=Path("/private/mobile/upload"),
    )

    class Registry:
        def committed_asset_for_legacy_delete(self, *facts):
            assert facts == (asset_id, resource_iri, "test/image/mobile")
            return mobile_asset

        @contextmanager
        def upload_operation_lock(self, upload_id):
            assert upload_id == mobile_asset.upload_id
            calls.append("lock-enter")
            yield
            calls.append("lock-exit")

    class Assets:
        def delete_committed(self, spec):
            assert spec.upload_id == mobile_asset.upload_id
            assert spec.client_asset_id == asset_id
            calls.append("delete")
            if outcome == "cleanup_failure":
                raise module.MobileMediaAssetError("owner marker mismatch")

    monkeypatch.setattr(module, "MOBILE_UPLOAD_REGISTRY", Registry())
    monkeypatch.setattr(module, "MOBILE_ASSET_STORE", Assets())

    response = client.delete(
        f"/upload/{asset_id}",
        headers={"Authorization": f"Bearer {_upload_token()}"},
    )

    assert (
        response.status_code
        == {"success": 200, "conflict": 409, "timeout": 502, "cleanup_failure": 200}[
            outcome
        ]
    )
    if outcome == "success":
        assert calls == ["oldap-delete", "lock-enter", "delete", "lock-exit"]
    elif outcome == "cleanup_failure":
        assert response.get_json()["cleanupPending"] is True
        assert asset_root.exists()
    else:
        assert calls == ["oldap-delete"]
        assert asset_root.exists()


def test_staging_discard_withdraws_files_and_deletes_exact_oldap_resource(
    media_app, monkeypatch
):
    """A confirmed Staging discard removes one identity-bound RDF/file pair."""

    module, client, media_root = media_app
    asset_id = "staging-delete"
    resource_iri = "testproject:StagedImage"
    asset_root = media_root / "testproject" / "image" / "trusted" / asset_id
    (asset_root / "original").mkdir(parents=True)
    (asset_root / "original" / "image.jpg").write_bytes(b"image")
    calls: list[tuple[str, str]] = []

    class FakeResponse:
        def __init__(self, status_code: int, payload: dict, text: str = ""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    def fake_get(url, **_kwargs):
        calls.append(("GET", url))
        return FakeResponse(
            200,
            {
                "iri": resource_iri,
                "graph": "testproject:data",
                "permval": 6,
                "shared:assetId": asset_id,
                "shared:path": "testproject/image/trusted",
                "shared:inStagingArea": ["testproject:Area"],
                "shared:inStagingFolder": ["testproject:Folder"],
                "shared:stagingStatus": ["shared:StagingStatusNew"],
            },
        )

    def fake_delete(url, **_kwargs):
        calls.append(("DELETE", url))
        assert asset_root.exists()
        assert list(asset_root.parent.glob(f".discard-{asset_id}-*")) == []
        return FakeResponse(200, {"message": "deleted"})

    monkeypatch.setattr(module.requests, "get", fake_get)
    monkeypatch.setattr(module.requests, "delete", fake_delete)

    response = client.delete(
        f"/upload/{asset_id}",
        query_string={
            "expectedResourceIri": resource_iri,
            "stagingOnly": "true",
        },
        headers={"Authorization": f"Bearer {_upload_token()}"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "message": f"Discarded asset {asset_id}",
        "iri": resource_iri,
        "assetId": asset_id,
        "cleanupPending": False,
    }
    assert calls == [
        ("GET", "http://localhost:8000/data/mediaobject/iri/testproject%3AStagedImage"),
        ("DELETE", "http://localhost:8000/data/testproject/testproject%3AStagedImage"),
    ]
    assert not asset_root.exists()
    assert list(asset_root.parent.glob(f".discard-{asset_id}-*")) == []


@pytest.mark.parametrize(
    "outcome", ["conflict", "timeout", "cleanup_failure", "already_archived"]
)
def test_staging_discard_keeps_files_when_oldap_rejects_delete(
    media_app, monkeypatch, outcome
):
    """An OLDAP conflict must leave the previously published asset untouched."""

    module, client, media_root = media_app
    asset_id = "staging-retained"
    resource_iri = "testproject:ReferencedImage"
    asset_root = media_root / "testproject" / "image" / "trusted" / asset_id
    (asset_root / "original").mkdir(parents=True)
    original = asset_root / "original" / "image.jpg"
    original.write_bytes(b"image")

    class FakeResponse:
        def __init__(self, status_code: int, payload: dict, text: str = ""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    monkeypatch.setattr(
        module.requests,
        "get",
        lambda *_args, **_kwargs: FakeResponse(
            200,
            {
                "iri": resource_iri,
                "graph": "testproject:data",
                "permval": 6,
                "shared:assetId": asset_id,
                "shared:path": "testproject/image/trusted",
                "shared:inStagingArea": (
                    [] if outcome == "already_archived" else ["testproject:Area"]
                ),
                "shared:inStagingFolder": ["testproject:Folder"],
                "shared:stagingStatus": ["shared:StagingStatusNew"],
            },
        ),
    )

    def authoritative_delete(*_args, **_kwargs):
        assert outcome != "already_archived"
        assert original.read_bytes() == b"image"
        assert list(asset_root.parent.glob(f".discard-{asset_id}-*")) == []
        if outcome == "timeout":
            raise module.requests.exceptions.Timeout("ambiguous database result")
        if outcome == "cleanup_failure":
            return FakeResponse(200, {})
        return FakeResponse(409, {}, "resource is referenced")

    monkeypatch.setattr(module.requests, "delete", authoritative_delete)
    if outcome == "cleanup_failure":

        def fail_rename(*_args, **_kwargs):
            raise OSError("read-only filesystem")

        monkeypatch.setattr(Path, "rename", fail_rename)

    response = client.delete(
        f"/upload/{asset_id}",
        query_string={
            "expectedResourceIri": resource_iri,
            "stagingOnly": "true",
        },
        headers={"Authorization": f"Bearer {_upload_token()}"},
    )

    assert (
        response.status_code
        == {
            "conflict": 409,
            "timeout": 502,
            "cleanup_failure": 200,
            "already_archived": 409,
        }[outcome]
    )
    if outcome == "conflict":
        assert "resource is referenced" in response.get_json()["error"]
    if outcome == "cleanup_failure":
        assert response.get_json()["cleanupPending"] is True
    assert original.read_bytes() == b"image"
    assert list(asset_root.parent.glob(f".discard-{asset_id}-*")) == []


@pytest.mark.parametrize("target_format", [None, "tiff", "TIFF"])
def test_image_target_format_normalizes_to_tiff(media_app, target_format):
    """Images use pyramidal TIFF whether the target is omitted or explicit."""
    module, _, _ = media_app

    assert (
        module.validate_target_format(module.MediaType.IMAGE, target_format) == "tiff"
    )


@pytest.mark.parametrize("target_format", ["jp2", "j2k", "jpeg"])
def test_image_target_format_rejects_non_tiff_formats(media_app, target_format):
    """Removed image targets fail explicitly instead of changing storage silently."""
    module, _, _ = media_app

    with pytest.raises(ValueError, match="allowed: \\['tiff'\\]"):
        module.validate_target_format(module.MediaType.IMAGE, target_format)


class FakeOldapClient:
    """Capture media resource creation without contacting oldap-api."""

    created: list[tuple[str, dict]] = []
    updated: list[tuple[str, dict]] = []
    existing_media: dict | None = None
    staging_target: dict = {
        "stagingAreaIri": "test:Area",
        "stagingFolderIri": "test:Photos",
        "mediaPath": "trusted-staging",
        "quotaBytes": 10_000_000,
        "attachedToRole": {"test:Curator": "DATA_PERMISSIONS"},
    }

    def __init__(
        self, oldap_api_url: str, projectId: str | None = None, token: str | None = None
    ):
        self.project = {
            "projectIri": "oldap:TestProject",
            "projectShortName": "testproject",
        }

    def create_resource(self, resource: str, resource_data: dict) -> dict:
        self.created.append((resource, resource_data))
        return {"iri": "test:mediaObject"}

    def authorize_staging_upload(
        self, staging_area_iri: str, staging_folder_iri: str
    ) -> dict:
        assert staging_area_iri == "test:Area"
        assert staging_folder_iri == "test:Photos"
        return self.staging_target

    def get_mediaobject_by_iri(self, resource_iri: str) -> dict | None:
        return self.existing_media

    def update_resource(self, resource_iri: str, resource_data: dict) -> dict:
        self.updated.append((resource_iri, resource_data))
        return {"iri": resource_iri, "message": "Instance successfully updated"}


class FailingCreateOldapClient(FakeOldapClient):
    """Simulate an OLDAP registration failure after local derivatives exist."""

    def create_resource(self, resource: str, resource_data: dict) -> dict:
        raise RuntimeError("OLDAP create failed")


class RejectingCreateOldapClient(FakeOldapClient):
    """Simulate a detailed OLDAP validation rejection."""

    def create_resource(self, resource: str, resource_data: dict) -> dict:
        response = types.SimpleNamespace(
            status_code=400,
            json=lambda: {"message": "Property shared:path is invalid."},
            text='{"message":"Property shared:path is invalid."}',
            reason="Bad Request",
        )
        raise sys.modules["app"].OldapApiError(
            "OLDAP resource creation failed", response
        )


class FailingUpdateOldapClient(FakeOldapClient):
    """Simulate OLDAP rejecting attachment after local derivatives exist."""

    def update_resource(self, resource_iri: str, resource_data: dict) -> dict:
        raise RuntimeError("OLDAP update failed")


def test_image_upload_defaults_to_pyramidal_tiff(media_app, monkeypatch):
    """An image upload creates the canonical master.tif IIIF derivative."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    class FakeVipsImage:
        def tiffsave(self, destination: str, **options) -> None:
            assert options == {
                "tile": True,
                "pyramid": True,
                "compression": "none",
                "tile_width": 256,
                "tile_height": 256,
                "bigtiff": True,
            }
            Path(destination).write_bytes(b"pyramidal tiff")

    def fake_vips_load(source: str, *, access: str):
        assert Path(source).read_bytes() == b"image bytes"
        assert access == "sequential"
        return FakeVipsImage()

    monkeypatch.setattr(module.DERIVATIVE_PROCESSOR, "vips_loader", fake_vips_load)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "asset-image",
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["mediaType"] == "image"
    assert payload["derivativeName"] == "master.tif"
    assert payload["protocol"] == "iiif"
    assert payload["checksum"] == hashlib.sha256(b"image bytes").hexdigest()

    asset_root = media_root / "testproject" / "image" / "archive" / "asset-image"
    assert (asset_root / "original" / "scan.png").read_bytes() == b"image bytes"
    assert (asset_root / "derived" / "master.tif").read_bytes() == b"pyramidal tiff"
    assert FakeOldapClient.created[0][1]["shared:derivativeName"] == "master.tif"
    assert (
        FakeOldapClient.created[0][1]["shared:checksum"]
        == hashlib.sha256(b"image bytes").hexdigest()
    )


def test_staging_upload_uses_only_server_derived_target_facts(media_app, monkeypatch):
    """Folder, path, status, and permissions cannot be selected independently."""

    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    class FakeVipsImage:
        def tiffsave(self, destination: str, **options) -> None:
            Path(destination).write_bytes(b"pyramidal tiff")

    monkeypatch.setattr(
        module.DERIVATIVE_PROCESSOR,
        "vips_loader",
        lambda *args, **kwargs: FakeVipsImage(),
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "resourceClass": "shared:StagingMediaObject",
            "stagingAreaIri": "test:Area",
            "stagingFolderIri": "test:Photos",
            "identifier": "staging-image",
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200, response.get_json()
    resource_class, metadata = FakeOldapClient.created[0]
    assert resource_class == "shared:StagingMediaObject"
    assert metadata["attachedToRole"] == {"test:Curator": "DATA_PERMISSIONS"}
    assert metadata["shared:inStagingArea"] == "test:Area"
    assert metadata["shared:inStagingFolder"] == "test:Photos"
    assert metadata["shared:stagingStatus"] == "shared:StagingStatusNew"
    assert metadata["shared:path"] == "testproject/image/trusted-staging"
    assert (
        media_root
        / "testproject"
        / "image"
        / "trusted-staging"
        / "staging-image"
        / "derived"
        / "master.tif"
    ).is_file()


def test_staging_upload_rejects_client_path_and_role_overrides(media_app, monkeypatch):
    """Trusted Staging configuration cannot be shadowed by multipart fields."""

    module, client, _ = media_app
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "resourceClass": "shared:StagingMediaObject",
            "stagingAreaIri": "test:Area",
            "stagingFolderIri": "test:Photos",
            "path": "untrusted",
            "attachedToRole": '{"test:Admin": "DATA_PERMISSIONS"}',
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "server-owned" in response.get_json()["message"]


def test_oldap_validation_detail_is_forwarded_and_asset_is_removed(
    media_app, monkeypatch
):
    """A useful OLDAP 400 must reach the browser without leaving local files."""

    module, client, media_root = media_app
    monkeypatch.setattr(module, "OldapClient", RejectingCreateOldapClient)

    class FakeVipsImage:
        def tiffsave(self, destination: str, **options) -> None:
            Path(destination).write_bytes(b"pyramidal tiff")

    monkeypatch.setattr(
        module.DERIVATIVE_PROCESSOR,
        "vips_loader",
        lambda *args, **kwargs: FakeVipsImage(),
    )
    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "rejected-image",
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["message"] == "Property shared:path is invalid."
    assert not (
        media_root / "testproject" / "image" / "archive" / "rejected-image"
    ).exists()


def test_heic_upload_uses_content_derived_mime_and_pyramidal_tiff(
    media_app, monkeypatch
):
    """Single-file HEIC upload preserves its original and creates master.tif."""

    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" b"content"

    class FakeVipsImage:
        def get_typeof(self, name: str) -> int:
            return 1 if name in {"vips-loader", "n-pages"} else 0

        def get(self, name: str):
            return {"vips-loader": "heifload", "n-pages": 1}[name]

        def tiffsave(self, destination: str, **options) -> None:
            Path(destination).write_bytes(b"pyramidal heic derivative")

    def fake_vips_load(source: str, *, access: str):
        assert Path(source).read_bytes() == heic
        assert access == "sequential"
        return FakeVipsImage()

    monkeypatch.setattr(module.DERIVATIVE_PROCESSOR, "vips_loader", fake_vips_load)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "asset-heic",
            "file": (io.BytesIO(heic), "IMG_0001.HEIC", "application/octet-stream"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.get_json()["originalMimeType"] == "image/heic"
    asset_root = media_root / "testproject" / "image" / "archive" / "asset-heic"
    assert (asset_root / "original" / "IMG_0001.HEIC").read_bytes() == heic
    assert (asset_root / "derived" / "master.tif").is_file()
    assert FakeOldapClient.created[0][1]["shared:originalMimeType"] == "image/heic"


def test_heic_upload_attaches_asset_to_existing_mediaobject(media_app, monkeypatch):
    """An existing catalogue record receives only verified delivery metadata."""

    module, client, media_root = media_app
    FakeOldapClient.created = []
    FakeOldapClient.updated = []
    heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" b"content"
    checksum = hashlib.sha256(heic).hexdigest()
    FakeOldapClient.existing_media = {
        "iri": "test:IMG_0001",
        "dcterms:type": "dcmitype:StillImage",
        "shared:originalName": "IMG_0001.HEIC",
        "shared:originalMimeType": "image/heic",
        "shared:checksum": checksum,
        "shared:mediaAccessMode": "local",
        "shared:protocol": "custom",
    }
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    class FakeVipsImage:
        def get_typeof(self, name: str) -> int:
            return 1 if name in {"vips-loader", "n-pages"} else 0

        def get(self, name: str):
            return {"vips-loader": "heifload", "n-pages": 1}[name]

        def tiffsave(self, destination: str, **options) -> None:
            Path(destination).write_bytes(b"pyramidal heic derivative")

    monkeypatch.setattr(
        module.DERIVATIVE_PROCESSOR,
        "vips_loader",
        lambda *args, **kwargs: FakeVipsImage(),
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "catalogue",
            "identifier": "IMG_0001",
            "existingResourceIri": "test:IMG_0001",
            "untrusted:description": "must not be forwarded",
            "file": (io.BytesIO(heic), "IMG_0001.HEIC", "application/octet-stream"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["attachedToExistingResource"] is True
    assert FakeOldapClient.created == []
    assert FakeOldapClient.updated == [
        (
            "test:IMG_0001",
            {
                "shared:serverUrl": "http://localhost:8088/iiif/3/",
                "shared:assetId": "IMG_0001",
                "shared:protocol": "iiif",
                "shared:derivativeName": "master.tif",
                "shared:path": "testproject/image/catalogue",
            },
        )
    ]
    asset_root = media_root / "testproject" / "image" / "catalogue" / "IMG_0001"
    assert (asset_root / "original" / "IMG_0001.HEIC").read_bytes() == heic
    assert (asset_root / "derived" / "master.tif").is_file()


def test_attach_rejects_existing_delivery_metadata_without_writing(
    media_app, monkeypatch
):
    """Attaching never replaces an existing local or external delivery binding."""

    module, client, media_root = media_app
    FakeOldapClient.created = []
    FakeOldapClient.updated = []
    FakeOldapClient.existing_media = {
        "iri": "test:IMG_0001",
        "shared:assetId": "already-bound",
    }
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "replacement",
            "existingResourceIri": "test:IMG_0001",
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 409
    assert "shared:assetId" in response.get_json()["message"]
    assert FakeOldapClient.created == []
    assert FakeOldapClient.updated == []
    assert not (media_root / "testproject" / "image" / "replacement").exists()


def test_attach_rejects_file_metadata_conflict_and_removes_asset(
    media_app, monkeypatch
):
    """A mismatching binary cannot be attached to an existing catalogue record."""

    module, client, media_root = media_app
    FakeOldapClient.created = []
    FakeOldapClient.updated = []
    FakeOldapClient.existing_media = {
        "iri": "test:IMG_0001",
        "shared:originalName": "different.png",
    }
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    class FakeVipsImage:
        def tiffsave(self, destination: str, **options) -> None:
            Path(destination).write_bytes(b"pyramidal tiff")

    monkeypatch.setattr(
        module.DERIVATIVE_PROCESSOR,
        "vips_loader",
        lambda *args, **kwargs: FakeVipsImage(),
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "IMG_0001",
            "existingResourceIri": "test:IMG_0001",
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 409
    assert response.get_json()["conflicts"]["shared:originalName"] == {
        "existing": "different.png",
        "uploaded": "scan.png",
    }
    assert FakeOldapClient.updated == []
    assert not (media_root / "testproject" / "image" / "IMG_0001").exists()


def test_attach_update_failure_removes_new_asset(media_app, monkeypatch):
    """A rejected OLDAP attachment leaves no unregistered asset directory."""

    module, client, media_root = media_app
    FailingUpdateOldapClient.existing_media = {
        "iri": "test:IMG_0001",
        "shared:originalName": "scan.png",
        "shared:originalMimeType": "image/png",
        "shared:checksum": hashlib.sha256(b"image bytes").hexdigest(),
        "shared:mediaAccessMode": "local",
        "shared:protocol": "custom",
    }
    monkeypatch.setattr(module, "OldapClient", FailingUpdateOldapClient)

    class FakeVipsImage:
        def tiffsave(self, destination: str, **options) -> None:
            Path(destination).write_bytes(b"pyramidal tiff")

    monkeypatch.setattr(
        module.DERIVATIVE_PROCESSOR,
        "vips_loader",
        lambda *args, **kwargs: FakeVipsImage(),
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "identifier": "IMG_0001",
            "existingResourceIri": "test:IMG_0001",
            "file": (io.BytesIO(b"image bytes"), "scan.png", "image/png"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 500
    assert "Failed to update OLDAP resource" in response.get_json()["error"]
    assert not (media_root / "testproject" / "image" / "IMG_0001").exists()


def test_multi_image_heif_single_upload_is_rejected(media_app, monkeypatch):
    """Single upload cannot silently reduce a HEIF collection to its first image."""

    module, client, media_root = media_app
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)
    heif = b"\x00\x00\x00\x14ftypmif1\x00\x00\x00\x00mif1content"

    class FakeCollection:
        def get_typeof(self, name: str) -> int:
            return 1 if name in {"vips-loader", "n-pages"} else 0

        def get(self, name: str):
            return {"vips-loader": "heifload", "n-pages": 2}[name]

    monkeypatch.setattr(
        module.DERIVATIVE_PROCESSOR,
        "vips_loader",
        lambda *args, **kwargs: FakeCollection(),
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "asset-heif-collection",
            "file": (io.BytesIO(heif), "collection.heif", "image/heif"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["message"] == (
        "Multi-image HEIF files are not supported."
    )
    assert not (
        media_root / "testproject" / "image" / "archive" / "asset-heif-collection"
    ).exists()


def test_heic_upload_rejects_extension_content_mismatch(media_app, monkeypatch):
    """A HEIC filename cannot route unrelated bytes into the image pipeline."""

    module, client, media_root = media_app
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "asset-fake-heic",
            "file": (io.BytesIO(b"not heif"), "fake.heic", "image/heic"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "not a supported HEIF/HEIC" in response.get_json()["message"]
    assert not (
        media_root / "testproject" / "image" / "archive" / "asset-fake-heic"
    ).exists()


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
        module.DERIVATIVE_PROCESSOR,
        "pdf_renderer",
        lambda *args, **kwargs: [Image.new("RGB", (400, 200), "red")],
    )

    response = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_upload_token()}"},
        data={
            "projectId": "test",
            "path": "archive",
            "identifier": "asset-pdf",
            "shared:checksum": "attacker-controlled-value",
            "file": (io.BytesIO(PDF_BYTES), "scan.pdf", "application/octet-stream"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["assetId"] == "asset-pdf"
    assert payload["mediaType"] == "document"
    assert payload["originalMimeType"] == "application/pdf"
    assert payload["checksum"] == hashlib.sha256(PDF_BYTES).hexdigest()
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
                "shared:checksum": hashlib.sha256(PDF_BYTES).hexdigest(),
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
        raise PDFPageCountError("Unable to read PDF page count")

    monkeypatch.setattr(module.DERIVATIVE_PROCESSOR, "pdf_renderer", fail_render)

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
        module.DERIVATIVE_PROCESSOR,
        "pdf_renderer",
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
        module.DERIVATIVE_PROCESSOR,
        "command_runner",
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


def test_invalid_pdf_upload_is_rejected_before_resource_creation(
    media_app, monkeypatch
):
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
            "file": (
                io.BytesIO(b"%PDF-1.4\nmissing EOF"),
                "bad.pdf",
                "application/pdf",
            ),
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


def test_upload_rejects_asset_path_symlink_escape(
    media_app, monkeypatch, tmp_path_factory
):
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


def test_existing_asset_identifier_is_rejected_without_modification(
    media_app, monkeypatch
):
    """A duplicate asset identifier is rejected before existing files are touched."""
    module, client, media_root = media_app
    FakeOldapClient.created = []
    monkeypatch.setattr(module, "OldapClient", FakeOldapClient)

    existing = (
        media_root
        / "testproject"
        / "document"
        / "existing-pdf"
        / "derived"
        / "document.pdf"
    )
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

    monkeypatch.setattr(module, "store_original_with_sha256", fail_copy)

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
    assert not list((media_root / "_tmp").iterdir())


def test_pdf_derivative_resolves_as_http_asset(media_app):
    """PDF derivatives are delivered through the HTTP asset path, not IIIF."""
    _, client, media_root = media_app
    asset_id = "asset-pdf"
    derived = (
        media_root
        / "fasnacht"
        / "document"
        / "archive"
        / asset_id
        / "derived"
        / "document.pdf"
    )
    derived.parent.mkdir(parents=True)
    derived.write_bytes(PDF_BYTES)
    thumbnail = derived.parent / "thumb256.jpg"
    Image.new("RGB", (256, 256), "white").save(thumbnail, format="JPEG")

    token = _codec().issue_media_token(
        "tester",
        {
            "assetId": asset_id,
            "path": "fasnacht/document/archive",
            "originalName": "scan.pdf",
            "derivativeName": "document.pdf",
            "protocol": "http",
        },
    )
    response = client.get(f"/auth/asset/{asset_id}?token={token}")

    assert response.status_code == 204
    assert response.headers["X-OLDAP-Internal-Path"] == str(derived.resolve())
    assert response.headers["X-OLDAP-Content-Type"] == "application/pdf"
    assert (
        response.headers["X-OLDAP-Content-Disposition"]
        == 'inline; filename="document.pdf"'
    )

    thumbnail_response = client.get(
        f"/auth/asset/{asset_id}?token={token}&derivative=thumb256.jpg"
    )

    assert thumbnail_response.status_code == 204
    assert thumbnail_response.headers["X-OLDAP-Internal-Path"] == str(
        thumbnail.resolve()
    )
    assert thumbnail_response.headers["X-OLDAP-Content-Type"] == "image/jpeg"
