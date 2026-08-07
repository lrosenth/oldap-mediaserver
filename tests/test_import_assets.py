"""Filesystem-boundary tests for confirmed ZIP import asset preparation."""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

import pytest
import rfc8785

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from derivatives import DerivativeResult
from import_assets import ImportAssetError, ImportAssetPreparer
from storage import AssetAlreadyExistsError


IMPORT_ID = "11111111-1111-4111-8111-111111111111"


class CopyingDerivativeProcessor:
    """Create the planned primary derivative without invoking native tools."""

    def generate(self, source, derived_directory, classification):
        names = {
            ("image", "tiff"): "master.tif",
            ("document", "txt"): "document.txt",
        }
        destination = (
            derived_directory
            / names[(classification.media_type.value, classification.target_format)]
        )
        shutil.copy2(source, destination)
        return DerivativeResult(primary=destination)


def _entry(index: int, path: str, content: bytes, category: str) -> dict:
    name = Path(path).name
    facts = {
        "image": {
            "mime": "image/jpeg",
            "dcterms": "dcmitype:StillImage",
            "protocol": "iiif",
            "derivative": "master.tif",
        },
        "document": {
            "mime": "text/plain",
            "dcterms": "dcmitype:Text",
            "protocol": "http",
            "derivative": "document.txt",
        },
    }[category]
    parent = Path(path).parent.as_posix()
    return {
        "entryIndex": index,
        "normalizedPath": path,
        "parentNormalizedPath": "" if parent == "." else parent,
        "normalizedName": name,
        "entryType": "file",
        "disposition": "IMPORT",
        "sha256": hashlib.sha256(content).hexdigest(),
        "detectedContent": {"category": category, "mimeType": facts["mime"]},
        "plannedResource": {
            "kind": "media",
            "resourceClass": "shared:StagingMediaObject",
            "originalName": name,
            "originalMimeType": facts["mime"],
            "dctermsType": facts["dcterms"],
            "protocol": facts["protocol"],
            "derivativeName": facts["derivative"],
        },
    }


def _manifest(entries: list[dict]) -> dict:
    return {
        "documentType": "oldap.zip-import.manifest",
        "schemaVersion": "1.0.0",
        "importId": IMPORT_ID,
        "validationOutcome": "READY",
        "job": {"target": {"projectShortName": "fasnacht"}},
        "entries": entries,
    }


def _digest(manifest: dict) -> str:
    return hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()


def test_prepare_promote_retry_and_compensate_owned_assets(tmp_path: Path) -> None:
    extraction = tmp_path / "extracted"
    (extraction / "photos").mkdir(parents=True)
    image = b"jpeg evidence"
    text = "Grüezi Fasnacht\n".encode()
    (extraction / "photos" / "bild.jpg").write_bytes(image)
    (extraction / "notiz.txt").write_bytes(text)
    manifest = _manifest(
        [
            _entry(2, "photos/bild.jpg", image, "image"),
            _entry(7, "notiz.txt", text, "document"),
        ]
    )
    digest = _digest(manifest)
    preparer = ImportAssetPreparer(
        tmp_path / "media",
        derivative_processor=CopyingDerivativeProcessor(),
    )

    prepared = preparer.prepare(IMPORT_ID, digest, manifest, extraction)
    assert [item.entry_index for item in prepared.media] == [2, 7]
    assert prepared.media[0].storage_path == "fasnacht/image"
    assert prepared.media[1].derivative_name == "document.txt"
    assert prepared.media[0].asset_id != prepared.media[1].asset_id

    promoted = preparer.promote(prepared)
    assert all(item.final_root and item.final_root.is_dir() for item in promoted.media)
    assert not promoted.job_work_root.exists()

    replay = preparer.promote(preparer.prepare(IMPORT_ID, digest, manifest, extraction))
    assert [item.asset_id for item in replay.media] == [
        item.asset_id for item in promoted.media
    ]

    preparer.compensate(replay)
    assert all(
        item.final_root and not item.final_root.exists() for item in replay.media
    )


def test_prepare_rejects_changed_manifest_or_original(tmp_path: Path) -> None:
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    content = b"original"
    (extraction / "note.txt").write_bytes(content)
    manifest = _manifest([_entry(1, "note.txt", content, "document")])
    preparer = ImportAssetPreparer(
        tmp_path / "media",
        derivative_processor=CopyingDerivativeProcessor(),
    )

    with pytest.raises(ImportAssetError, match="Manifest checksum"):
        preparer.prepare(IMPORT_ID, "0" * 64, manifest, extraction)

    (extraction / "note.txt").write_bytes(b"changed")
    with pytest.raises(ImportAssetError, match="original checksum"):
        preparer.prepare(IMPORT_ID, _digest(manifest), manifest, extraction)
    assert not (tmp_path / "media" / "_import-work" / IMPORT_ID).exists()


def test_promotion_never_replaces_an_unowned_asset(tmp_path: Path) -> None:
    extraction = tmp_path / "extracted"
    extraction.mkdir()
    content = b"original"
    (extraction / "note.txt").write_bytes(content)
    manifest = _manifest([_entry(1, "note.txt", content, "document")])
    preparer = ImportAssetPreparer(
        tmp_path / "media",
        derivative_processor=CopyingDerivativeProcessor(),
    )
    prepared = preparer.prepare(IMPORT_ID, _digest(manifest), manifest, extraction)
    collision = (
        tmp_path / "media" / "fasnacht" / "document" / prepared.media[0].asset_id
    )
    collision.mkdir(parents=True)
    sentinel = collision / "belongs-to-someone-else"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(AssetAlreadyExistsError):
        preparer.promote(prepared)

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert prepared.media[0].work_root.is_dir()
