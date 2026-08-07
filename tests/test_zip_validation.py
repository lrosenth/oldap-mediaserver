"""Deterministic structural ZIP validation and extraction tests."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import struct
import sys
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from config import ZipImportLimits  # noqa: E402
from zip_validation import STRUCTURAL_ISSUE_CODES, ZipStructureValidator  # noqa: E402


class _NonSeekableBuffer(io.BytesIO):
    """Force zipfile to emit a data descriptor like a streaming ZIP writer."""

    def seekable(self) -> bool:
        return False

    def seek(self, *args, **kwargs):
        raise io.UnsupportedOperation("not seekable")


def _write_zip(
    path: Path,
    entries: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    comment: bytes = b"",
) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, content in entries:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Duplicate name:.*")
                archive.writestr(name, content)
        archive.comment = comment


def _codes(result) -> set[str]:
    return {issue.code for issue in result.issues}


def _patch_flags(path: Path, flags: int) -> None:
    data = bytearray(path.read_bytes())
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, local + 6, flags)
    struct.pack_into("<H", data, central + 8, flags)
    path.write_bytes(data)


def _patch_method(path: Path, method: int) -> None:
    data = bytearray(path.read_bytes())
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, local + 8, method)
    struct.pack_into("<H", data, central + 10, method)
    path.write_bytes(data)


def _add_self_extracting_preamble(path: Path, preamble: bytes) -> None:
    original = bytearray(path.read_bytes())
    central = original.find(b"PK\x01\x02")
    eocd = original.rfind(b"PK\x05\x06")
    local_offset = struct.unpack_from("<L", original, central + 42)[0]
    central_offset = struct.unpack_from("<L", original, eocd + 16)[0]
    struct.pack_into("<L", original, central + 42, local_offset + len(preamble))
    struct.pack_into("<L", original, eocd + 16, central_offset + len(preamble))
    path.write_bytes(preamble + original)


def test_clean_utf8_archive_is_extracted_entry_by_entry(tmp_path: Path) -> None:
    sip = tmp_path / "sip.zip"
    payload = b"not-yet-content-probed"
    _write_zip(sip, [("Ordner/", b""), ("Ordner/Fasnacht-é.txt", payload)])

    result = ZipStructureValidator().validate_and_extract(sip, tmp_path / "work")

    assert result.accepted
    assert result.inventory_complete
    assert result.entries_declared == 2
    assert result.actual_extracted_bytes == len(payload)
    assert result.max_depth == 1
    assert (tmp_path / "work" / "Ordner" / "Fasnacht-é.txt").read_bytes() == payload
    file_entry = result.entries[1]
    assert file_entry.sha256 == hashlib.sha256(payload).hexdigest()
    assert file_entry.crc32_actual == file_entry.crc32_declared
    assert file_entry.actual_uncompressed_size_bytes == len(payload)


def test_archive_comment_is_a_non_blocking_warning(tmp_path: Path) -> None:
    sip = tmp_path / "comment.zip"
    _write_zip(
        sip,
        [("photo.jpg", b"jpeg-placeholder")],
        comment=b"ignored PK\x05\x06 marker",
    )

    result = ZipStructureValidator().inspect(sip)

    assert result.accepted
    assert _codes(result) == {"ARCHIVE_COMMENT_IGNORED"}
    assert result.issues[0].severity == "WARNING"
    assert result.issues[0].message_key == "zipImport.issue.archive_comment_ignored"


def test_structural_issue_codes_are_frozen_by_the_v1_contract() -> None:
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "zip-import"
            / "v1"
            / "common.schema.json"
        ).read_text(encoding="utf-8")
    )
    contract_codes = set(schema["$defs"]["IssueCode"]["enum"])

    assert STRUCTURAL_ISSUE_CODES <= contract_codes


def test_accepts_a_consistent_streaming_data_descriptor_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    buffer = _NonSeekableBuffer()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("streamed.txt", b"streamed content")
    sip = tmp_path / "descriptor.zip"
    sip.write_bytes(buffer.getvalue())

    accepted = ZipStructureValidator().inspect(sip)
    assert accepted.accepted
    assert accepted.entries[0].flags & (1 << 3)

    data = bytearray(sip.read_bytes())
    descriptor_offset = accepted.entries[0].data_end_offset
    crc_offset = descriptor_offset + (
        4 if data[descriptor_offset : descriptor_offset + 4] == b"PK\x07\x08" else 0
    )
    data[crc_offset] ^= 0xFF
    sip.write_bytes(data)
    rejected = ZipStructureValidator().inspect(sip)
    assert "ZIP_FORMAT_UNSUPPORTED" in _codes(rejected)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("../escape.jpg", "PARENT_TRAVERSAL"),
        ("a/../../escape.jpg", "PARENT_TRAVERSAL"),
        ("/absolute.jpg", "ABSOLUTE_PATH"),
        ("C:\\escape.jpg", "ABSOLUTE_PATH"),
        ("\\\\server\\share\\escape.jpg", "ABSOLUTE_PATH"),
        ("a\\..\\escape.jpg", "PARENT_TRAVERSAL"),
        ("CON.txt", "RESERVED_NAME"),
        ("safe/na\u202eme.jpg", "RESERVED_NAME"),
        ("a/b/c/d/e/f/photo.jpg", "PATH_DEPTH_LIMIT"),
    ],
)
def test_rejects_unsafe_and_overdeep_paths(
    tmp_path: Path,
    name: str,
    expected: str,
) -> None:
    sip = tmp_path / "unsafe.zip"
    _write_zip(sip, [(name, b"content")])

    result = ZipStructureValidator().validate_and_extract(sip, tmp_path / "work")

    assert expected in _codes(result)
    assert not result.accepted
    assert not (tmp_path / "work").exists()


def test_rejects_symlink_and_special_unix_entries(tmp_path: Path) -> None:
    sip = tmp_path / "types.zip"
    with zipfile.ZipFile(sip, "w") as archive:
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(symlink, "target")
        fifo = zipfile.ZipInfo("pipe")
        fifo.create_system = 3
        fifo.external_attr = (stat.S_IFIFO | 0o600) << 16
        archive.writestr(fifo, b"")

    result = ZipStructureValidator().inspect(sip)

    assert {"SYMLINK_NOT_ALLOWED", "SPECIAL_FILE_NOT_ALLOWED"} <= _codes(result)
    assert not result.accepted


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        ([("same.txt", b"a"), ("same.txt", b"b")], "DUPLICATE_PATH"),
        ([("é.txt", b"a"), ("e\u0301.txt", b"b")], "NAME_NORMALIZATION_COLLISION"),
        ([("Photo.jpg", b"a"), ("photo.jpg", b"b")], "CASE_COLLISION"),
        (
            [("folder", b"file"), ("folder/child.txt", b"child")],
            "FILE_DIRECTORY_CONFLICT",
        ),
        ([("same", b"file"), ("same/", b"")], "FILE_DIRECTORY_CONFLICT"),
    ],
)
def test_detects_duplicate_normalized_portable_and_type_collisions(
    tmp_path: Path,
    entries: list[tuple[str, bytes]],
    expected: str,
) -> None:
    sip = tmp_path / "collision.zip"
    _write_zip(sip, entries)

    result = ZipStructureValidator().inspect(sip)

    assert expected in _codes(result)
    assert not result.accepted


def test_rejects_encryption_unsupported_method_and_legacy_non_ascii_name(
    tmp_path: Path,
) -> None:
    encrypted = tmp_path / "encrypted.zip"
    _write_zip(encrypted, [("file.txt", b"content")], compression=zipfile.ZIP_STORED)
    _patch_flags(encrypted, 1)
    assert "ENCRYPTED_ENTRY" in _codes(ZipStructureValidator().inspect(encrypted))

    unsupported = tmp_path / "unsupported.zip"
    _write_zip(unsupported, [("file.txt", b"content")], compression=zipfile.ZIP_STORED)
    _patch_method(unsupported, 12)
    assert "UNSUPPORTED_COMPRESSION_METHOD" in _codes(
        ZipStructureValidator().inspect(unsupported)
    )

    legacy = tmp_path / "legacy.zip"
    _write_zip(legacy, [("é.txt", b"content")], compression=zipfile.ZIP_STORED)
    _patch_flags(legacy, 0)
    assert "INVALID_NAME_ENCODING" in _codes(ZipStructureValidator().inspect(legacy))

    bzip2 = tmp_path / "bzip2.zip"
    _write_zip(bzip2, [("file.txt", b"content")], compression=zipfile.ZIP_BZIP2)
    bzip2_codes = _codes(ZipStructureValidator().inspect(bzip2))
    assert "UNSUPPORTED_COMPRESSION_METHOD" in bzip2_codes
    assert "ZIP64_NOT_ALLOWED" not in bzip2_codes


def test_rejects_self_extracting_preamble_and_zip64_version(tmp_path: Path) -> None:
    self_extracting = tmp_path / "self-extracting.zip"
    _write_zip(self_extracting, [("file.txt", b"content")])
    _add_self_extracting_preamble(self_extracting, b"MZ-harmless-preamble")
    assert "SELF_EXTRACTING_ZIP_NOT_ALLOWED" in _codes(
        ZipStructureValidator().inspect(self_extracting)
    )

    zip64 = tmp_path / "zip64.zip"
    _write_zip(zip64, [("file.txt", b"content")])
    data = bytearray(zip64.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd + 8, 0xFFFF)
    struct.pack_into("<H", data, eocd + 10, 0xFFFF)
    zip64.write_bytes(data)
    assert "ZIP64_NOT_ALLOWED" in _codes(ZipStructureValidator().inspect(zip64))


def test_rejects_mismatched_local_header_and_crc_and_removes_output(
    tmp_path: Path,
) -> None:
    mismatched = tmp_path / "mismatch.zip"
    _write_zip(mismatched, [("file.txt", b"content")], compression=zipfile.ZIP_STORED)
    data = bytearray(mismatched.read_bytes())
    local = data.find(b"PK\x03\x04")
    data[local + 30] = ord("X")
    mismatched.write_bytes(data)
    assert "ZIP_FORMAT_UNSUPPORTED" in _codes(
        ZipStructureValidator().inspect(mismatched)
    )

    bad_crc = tmp_path / "bad-crc.zip"
    _write_zip(bad_crc, [("file.txt", b"content")], compression=zipfile.ZIP_STORED)
    data = bytearray(bad_crc.read_bytes())
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    original_crc = struct.unpack_from("<L", data, local + 14)[0]
    patched_crc = original_crc ^ 0xFFFFFFFF
    struct.pack_into("<L", data, local + 14, patched_crc)
    struct.pack_into("<L", data, central + 16, patched_crc)
    bad_crc.write_bytes(data)
    result = ZipStructureValidator().validate_and_extract(bad_crc, tmp_path / "work")
    assert "ZIP_CRC_MISMATCH" in _codes(result)
    assert not (tmp_path / "work").exists()


def test_enforces_bounded_declared_and_streamed_limits(tmp_path: Path) -> None:
    sip = tmp_path / "limits.zip"
    _write_zip(sip, [("a.txt", b"A" * 50), ("b.txt", b"B" * 50)])

    count_limits = replace(ZipImportLimits(), max_entries=1)
    count_result = ZipStructureValidator(count_limits).inspect(sip)
    assert "ENTRY_COUNT_LIMIT" in _codes(count_result)
    assert not count_result.inventory_complete
    assert count_result.entries == ()

    size_limits = replace(
        ZipImportLimits(),
        max_individual_file_bytes=49,
        max_extracted_bytes=99,
        max_compression_ratio_per_file=10_000,
        max_aggregate_compression_ratio=10_000,
    )
    size_result = ZipStructureValidator(size_limits).inspect(sip)
    assert {"ENTRY_SIZE_LIMIT", "EXTRACTED_TOTAL_LIMIT"} <= _codes(size_result)

    ratio_limits = replace(
        ZipImportLimits(),
        max_compression_ratio_per_file=1,
        max_aggregate_compression_ratio=1,
    )
    ratio_result = ZipStructureValidator(ratio_limits).inspect(sip)
    assert "COMPRESSION_RATIO_LIMIT" in _codes(ratio_result)

    compressed_limit = replace(
        ZipImportLimits(), max_compressed_bytes=sip.stat().st_size - 1
    )
    assert _codes(ZipStructureValidator(compressed_limit).inspect(sip)) == {
        "ZIP_SIZE_LIMIT"
    }


def test_rejects_empty_and_truncated_archives(tmp_path: Path) -> None:
    empty = tmp_path / "empty.zip"
    _write_zip(empty, [])
    assert "NO_IMPORTABLE_CONTENT" in _codes(ZipStructureValidator().inspect(empty))

    truncated = tmp_path / "truncated.zip"
    _write_zip(truncated, [("file.txt", b"content")])
    truncated.write_bytes(truncated.read_bytes()[:-10])
    assert _codes(ZipStructureValidator().inspect(truncated)) == {
        "ZIP_FORMAT_UNSUPPORTED"
    }
