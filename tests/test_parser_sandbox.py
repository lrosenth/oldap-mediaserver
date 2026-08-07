"""Retry and path-safety tests for the parser workspace boundary."""

from __future__ import annotations

import sys
from pathlib import Path


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from parser_sandbox import ParserSandbox, ParserSandboxError  # noqa: E402


def _paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    ingest_root = tmp_path / "ingest"
    quarantine = ingest_root / "11111111-1111-4111-8111-111111111111"
    quarantine.mkdir(parents=True)
    sip_path = quarantine / "sip.zip"
    sip_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    return ingest_root, quarantine, sip_path


def test_local_workspace_is_retry_safe_and_promotes_atomically(tmp_path: Path) -> None:
    ingest_root, quarantine, sip_path = _paths(tmp_path)
    stale = quarantine / ".parser-work" / "extracted"
    stale.mkdir(parents=True)
    (stale / "partial.txt").write_text("partial", encoding="utf-8")
    sandbox = ParserSandbox()

    workspace = sandbox.prepare(ingest_root, quarantine, sip_path)

    assert not workspace.extraction_root.exists()
    workspace.extraction_root.mkdir()
    (workspace.extraction_root / "complete.txt").write_text(
        "complete", encoding="utf-8"
    )
    promoted = sandbox.promote(workspace)
    assert promoted == quarantine / "extracted"
    assert (promoted / "complete.txt").read_text(encoding="utf-8") == "complete"
    assert not workspace.root.exists()


def test_workspace_symlink_is_rejected_without_touching_target(tmp_path: Path) -> None:
    ingest_root, quarantine, sip_path = _paths(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    (quarantine / ".parser-work").symlink_to(outside, target_is_directory=True)

    try:
        ParserSandbox().prepare(ingest_root, quarantine, sip_path)
    except ParserSandboxError:
        pass
    else:
        raise AssertionError("A symlink workspace must fail closed.")

    assert marker.read_text(encoding="utf-8") == "keep"


def test_quarantine_symlink_is_rejected_before_workspace_cleanup(
    tmp_path: Path,
) -> None:
    ingest_root = tmp_path / "ingest"
    ingest_root.mkdir()
    outside = tmp_path / "outside"
    workspace = outside / ".parser-work"
    workspace.mkdir(parents=True)
    marker = workspace / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    sip_path = outside / "sip.zip"
    sip_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    quarantine = ingest_root / "11111111-1111-4111-8111-111111111111"
    quarantine.symlink_to(outside, target_is_directory=True)

    try:
        ParserSandbox().prepare(ingest_root, quarantine, quarantine / "sip.zip")
    except ParserSandboxError:
        pass
    else:
        raise AssertionError("A symlink quarantine must fail before cleanup.")

    assert marker.read_text(encoding="utf-8") == "keep"
