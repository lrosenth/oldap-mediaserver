"""Content validation, durable publication, and exact compensation tests."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from mobile_media_assets import (  # noqa: E402
    COMPENSATION_NAME,
    MobileAssetSpec,
    MobileMediaAssetError,
    MobileMediaAssetStore,
)


UPLOAD = "11111111-1111-4111-8111-111111111111"
ASSET = "22222222-2222-4222-8222-222222222222"


class Derivatives:
    def generate(self, source: Path, derived: Path, classification: object):
        target = derived / "master.tif"
        target.write_bytes(b"tiff")
        return type("Result", (), {"primary": target})()


def spec(
    tmp_path: Path, content: bytes, *, mime: str = "image/jpeg"
) -> MobileAssetSpec:
    upload = tmp_path / "uploads" / UPLOAD
    upload.mkdir(parents=True)
    (upload / "original.part").write_bytes(content)
    return MobileAssetSpec(
        upload_id=UPLOAD,
        client_asset_id=ASSET,
        original_name="photo.jpg",
        original_mime_type=mime,
        byte_length=len(content),
        checksum=f"sha256:{hashlib.sha256(content).hexdigest()}",
        storage_path="fasnacht/image/bmg",
        upload_directory=upload,
    )


def test_prepare_publish_replay_and_exact_compensation(tmp_path: Path) -> None:
    item = spec(tmp_path, b"\xff\xd8\xffimage")
    store = MobileMediaAssetStore(tmp_path / "media", derivatives=Derivatives())  # type: ignore[arg-type]

    assert store.verify_original(item) == item.checksum
    store.prepare(item)
    first = store.publish(item)
    second = store.publish(item)

    assert first == second
    assert first.to_dict()["derivativeNames"] == ["master.tif"]
    final = store.final_root(item)
    assert (final / "original" / "photo.jpg").read_bytes() == b"\xff\xd8\xffimage"
    store.compensate(item)
    store.compensate(item)
    assert not final.exists()


def test_prepare_recovers_incomplete_private_work_without_owner_marker(
    tmp_path: Path,
) -> None:
    item = spec(tmp_path, b"\xff\xd8\xffimage")
    work = item.upload_directory / "asset.work"
    work.mkdir()
    (work / "partial").write_bytes(b"interrupted")
    store = MobileMediaAssetStore(tmp_path / "media", derivatives=Derivatives())  # type: ignore[arg-type]

    store.prepare(item)

    assert not (work / "partial").exists()
    assert (work / ".oldap-mobile-owner.json").is_file()


def test_validation_rejects_checksum_and_mime_confusion(tmp_path: Path) -> None:
    item = spec(tmp_path, b"\x89PNG\r\n\x1a\nbody", mime="image/jpeg")
    store = MobileMediaAssetStore(tmp_path / "media", derivatives=Derivatives())  # type: ignore[arg-type]
    with pytest.raises(MobileMediaAssetError, match="MIME"):
        store.verify_original(item)

    changed = replace(
        item, original_mime_type="image/png", checksum="sha256:" + "0" * 64
    )
    with pytest.raises(MobileMediaAssetError, match="digest"):
        store.verify_original(changed)


def test_compensation_refuses_foreign_or_changed_final_asset(tmp_path: Path) -> None:
    item = spec(tmp_path, b"\xff\xd8\xffimage")
    store = MobileMediaAssetStore(tmp_path / "media", derivatives=Derivatives())  # type: ignore[arg-type]
    store.prepare(item)
    store.publish(item)
    final = store.final_root(item)
    (final / ".oldap-mobile-owner.json").write_text("{}", encoding="utf-8")

    with pytest.raises(MobileMediaAssetError, match="not owned"):
        store.compensate(item)
    assert final.exists()


def test_compensation_recovers_after_crash_during_private_deletion(
    tmp_path: Path,
) -> None:
    item = spec(tmp_path, b"\xff\xd8\xffimage")
    store = MobileMediaAssetStore(tmp_path / "media", derivatives=Derivatives())  # type: ignore[arg-type]
    store.prepare(item)
    store.publish(item)
    final = store.final_root(item)
    withdrawn = item.upload_directory / COMPENSATION_NAME

    final.rename(withdrawn)
    (withdrawn / ".oldap-mobile-owner.json").unlink()
    (withdrawn / "derived" / "master.tif").unlink()

    store.compensate(item)

    assert not final.exists()
    assert not withdrawn.exists()
