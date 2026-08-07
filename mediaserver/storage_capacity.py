"""Physical free-space admission for ZIP ingest filesystem writes.

The API owns logical staging quotas. This module protects the media host's
physical filesystems independently, immediately before a bounded write phase.
It deliberately keeps no reservation database: the MVP has one sequential
ingest worker, and every later phase repeats the check against current facts.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple


MINIMUM_FREE_PERCENT = 20
IMPORT_ASSET_ESTIMATE_FACTOR = 2


class DiskUsage(NamedTuple):
    """Portable subset returned by :func:`shutil.disk_usage`."""

    total: int
    used: int
    free: int


class PhysicalCapacityInsufficient(OSError):
    """Raised before a write would cross the configured free-space reserve."""

    def __init__(self, snapshot: "CapacitySnapshot") -> None:
        super().__init__("Physical storage capacity is insufficient.")
        self.snapshot = snapshot


@dataclass(frozen=True, slots=True)
class CapacitySnapshot:
    """Non-sensitive capacity facts suitable for structured operator logging."""

    total_bytes: int
    free_bytes: int
    reserve_bytes: int
    required_bytes: int


class StorageCapacityGuard:
    """Enforce the frozen 20% reserve plus an operator absolute minimum."""

    def __init__(
        self,
        absolute_reserve_bytes: int = 0,
        *,
        disk_usage: Callable[[Path], DiskUsage] = shutil.disk_usage,
    ) -> None:
        if absolute_reserve_bytes < 0:
            raise ValueError("absolute_reserve_bytes must not be negative.")
        self.absolute_reserve_bytes = absolute_reserve_bytes
        self._disk_usage = disk_usage

    def require(self, path: Path, *, additional_bytes: int) -> CapacitySnapshot:
        """Return current facts or reject a bounded additional allocation.

        Args:
            path: Existing path on the filesystem that will receive the data.
            additional_bytes: Conservative bytes the next phase may add.

        Raises:
            ValueError: If the requested allocation is negative.
            PhysicalCapacityInsufficient: If the phase would leave less than
                ``max(20% of total, absolute_reserve_bytes)`` free.
            OSError: If filesystem capacity cannot be inspected.
        """

        if additional_bytes < 0:
            raise ValueError("additional_bytes must not be negative.")
        usage = self._disk_usage(path)
        reserve = max(
            (usage.total * MINIMUM_FREE_PERCENT + 99) // 100,
            self.absolute_reserve_bytes,
        )
        snapshot = CapacitySnapshot(
            total_bytes=usage.total,
            free_bytes=usage.free,
            reserve_bytes=reserve,
            required_bytes=additional_bytes,
        )
        if usage.free < reserve + additional_bytes:
            raise PhysicalCapacityInsufficient(snapshot)
        return snapshot


def potential_extracted_bytes(compressed_bytes: int, *, maximum_bytes: int) -> int:
    """Estimate the validation allocation from the frozen 50:1 ZIP ceiling."""

    if compressed_bytes < 1 or maximum_bytes < 1:
        raise ValueError("Capacity inputs must be positive.")
    return min(maximum_bytes, compressed_bytes * 50)


def import_asset_bytes(extracted_bytes: int) -> int:
    """Estimate originals plus derivatives prepared beside retained extraction.

    The preparation phase copies every extracted original once. A second copy
    of the total is reserved as simple derivative headroom. The mandatory 20%
    volume reserve remains untouched if an individual derivative is larger.
    """

    if extracted_bytes < 0:
        raise ValueError("extracted_bytes must not be negative.")
    return extracted_bytes * IMPORT_ASSET_ESTIMATE_FACTOR
