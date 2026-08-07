"""Unit tests for reusable media storage and integrity primitives."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from storage import (  # noqa: E402
    AssetAlreadyExistsError,
    StoragePathEscapeError,
    operation_workspace,
    reserve_asset_layout,
    store_original_with_sha256,
)


def test_store_original_streams_exact_bytes_and_sha256(tmp_path: Path) -> None:
    """Original storage returns integrity metadata for the exact copied bytes."""

    content = (b"OLDAP-integrity\x00" * 100_000) + b"tail"
    source = tmp_path / "source.bin"
    destination = tmp_path / "original.bin"
    source.write_bytes(content)

    stored = store_original_with_sha256(source, destination, chunk_bytes=4093)

    assert stored.path == destination
    assert stored.size_bytes == len(content)
    assert stored.sha256 == hashlib.sha256(content).hexdigest()
    assert destination.read_bytes() == content


def test_store_original_never_replaces_existing_destination(tmp_path: Path) -> None:
    """An existing original survives an exclusive-copy collision unchanged."""

    source = tmp_path / "source.bin"
    destination = tmp_path / "original.bin"
    source.write_bytes(b"replacement")
    destination.write_bytes(b"existing")

    with pytest.raises(FileExistsError):
        store_original_with_sha256(source, destination)

    assert destination.read_bytes() == b"existing"


def test_asset_layout_reservation_is_exclusive(tmp_path: Path) -> None:
    """A second reservation cannot merge into or modify an existing asset."""

    first = reserve_asset_layout(tmp_path, "project", "image", "archive", "asset-1")
    sentinel = first.original / "sentinel.bin"
    sentinel.write_bytes(b"existing")

    with pytest.raises(AssetAlreadyExistsError):
        reserve_asset_layout(tmp_path, "project", "image", "archive", "asset-1")

    assert sentinel.read_bytes() == b"existing"


def test_asset_layout_rejects_symlink_escape(tmp_path: Path, tmp_path_factory) -> None:
    """A symlinked grouping directory cannot redirect storage outside the root."""

    outside = tmp_path_factory.mktemp("outside-storage")
    linked = tmp_path / "project" / "image" / "linked"
    linked.parent.mkdir(parents=True)
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(StoragePathEscapeError):
        reserve_asset_layout(tmp_path, "project", "image", "linked", "asset-1")

    assert not (outside / "asset-1").exists()


def test_operation_workspaces_are_unique_and_always_removed(tmp_path: Path) -> None:
    """Repeated operations with one asset ID never share temporary paths."""

    work_root = tmp_path / "_tmp"
    observed: list[Path] = []
    for _ in range(2):
        with operation_workspace(work_root, "asset-1") as workspace:
            observed.append(workspace)
            (workspace / "source.bin").write_bytes(b"temporary")
            assert workspace.is_dir()
        assert not observed[-1].exists()

    assert observed[0] != observed[1]
    assert list(work_root.iterdir()) == []
