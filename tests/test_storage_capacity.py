"""Deterministic tests for physical ZIP-ingest admission."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from storage_capacity import (  # noqa: E402
    DiskUsage,
    PhysicalCapacityInsufficient,
    StorageCapacityGuard,
    import_asset_bytes,
    potential_extracted_bytes,
)


def test_guard_preserves_larger_percentage_or_absolute_reserve(tmp_path: Path) -> None:
    """An allocation may leave exactly the effective reserve, never less."""

    percentage = StorageCapacityGuard(
        disk_usage=lambda path: DiskUsage(total=1_000, used=700, free=300)
    )
    assert percentage.require(tmp_path, additional_bytes=100).reserve_bytes == 200
    with pytest.raises(PhysicalCapacityInsufficient) as rejected:
        percentage.require(tmp_path, additional_bytes=101)
    assert rejected.value.snapshot.free_bytes == 300

    absolute = StorageCapacityGuard(
        250, disk_usage=lambda path: DiskUsage(total=1_000, used=700, free=300)
    )
    with pytest.raises(PhysicalCapacityInsufficient):
        absolute.require(tmp_path, additional_bytes=51)


def test_phase_estimates_are_bounded_and_explicit() -> None:
    """ZIP expansion and asset-copy estimates use the reviewed v1 constants."""

    assert potential_extracted_bytes(10, maximum_bytes=3_000_000_000) == 500
    assert potential_extracted_bytes(500_000_000, maximum_bytes=3_000_000_000) == (
        3_000_000_000
    )
    assert import_asset_bytes(3_000_000_000) == 6_000_000_000
