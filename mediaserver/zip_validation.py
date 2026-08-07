"""Bounded structural validation and safe extraction for conventional ZIP SIPs.

The validator deliberately supports only the Phase 0 MVP ZIP subset: one disk,
32-bit offsets and sizes, and stored or deflated entries. It parses the central
directory and local headers before Python's decompressor sees entry data, then
extracts entries individually into a fresh job-owned directory.
"""

from __future__ import annotations

import binascii
import hashlib
import os
import re
import shutil
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from config import ZipImportLimits


EOCD_SIGNATURE = b"PK\x05\x06"
CENTRAL_SIGNATURE = b"PK\x01\x02"
LOCAL_SIGNATURE = b"PK\x03\x04"
DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
EOCD_FIXED_BYTES = 22
CENTRAL_FIXED_BYTES = 46
LOCAL_FIXED_BYTES = 30
MAX_EOCD_SEARCH_BYTES = EOCD_FIXED_BYTES + 65_535
STREAM_CHUNK_BYTES = 1024 * 1024
UTF8_FLAG = 1 << 11
DATA_DESCRIPTOR_FLAG = 1 << 3
ENCRYPTED_FLAGS = (1 << 0) | (1 << 6)
ALLOWED_GENERAL_PURPOSE_FLAGS = UTF8_FLAG | DATA_DESCRIPTOR_FLAG | (1 << 1) | (1 << 2)
ALLOWED_METHODS = {zipfile.ZIP_STORED: "stored", zipfile.ZIP_DEFLATED: "deflate"}
DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:")
WINDOWS_FORBIDDEN_CHARS = frozenset('<>:"|?*')
STRUCTURAL_ISSUE_CODES = frozenset(
    {
        "ABSOLUTE_PATH",
        "ARCHIVE_COMMENT_IGNORED",
        "CASE_COLLISION",
        "COMPRESSION_RATIO_LIMIT",
        "DUPLICATE_PATH",
        "ENCRYPTED_ENTRY",
        "ENTRY_COUNT_LIMIT",
        "ENTRY_SIZE_LIMIT",
        "EXTRACTED_TOTAL_LIMIT",
        "FILE_DIRECTORY_CONFLICT",
        "INVALID_NAME_ENCODING",
        "MULTI_DISK_NOT_ALLOWED",
        "NAME_NORMALIZATION_COLLISION",
        "NO_IMPORTABLE_CONTENT",
        "NUL_IN_NAME",
        "PARENT_TRAVERSAL",
        "PATH_DEPTH_LIMIT",
        "PATH_LENGTH_LIMIT",
        "PATH_SEGMENT_LENGTH_LIMIT",
        "RESERVED_NAME",
        "SELF_EXTRACTING_ZIP_NOT_ALLOWED",
        "SPECIAL_FILE_NOT_ALLOWED",
        "SYMLINK_NOT_ALLOWED",
        "UNSUPPORTED_COMPRESSION_METHOD",
        "ZIP64_NOT_ALLOWED",
        "ZIP_CRC_MISMATCH",
        "ZIP_FORMAT_UNSUPPORTED",
        "ZIP_SIZE_LIMIT",
    }
)
RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
BIDI_CONTROLS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


@dataclass(frozen=True, slots=True)
class ZipIssue:
    """One stable structural validation finding."""

    code: str
    blocking: bool = True
    entry_index: int | None = None
    path: str | None = None
    details: tuple[tuple[str, int | str | bool], ...] = ()

    def __post_init__(self) -> None:
        """Reject accidental issue-code drift at the creation boundary."""

        if self.code not in STRUCTURAL_ISSUE_CODES:
            raise ValueError(f"Unknown structural ZIP issue code: {self.code}")

    @property
    def severity(self) -> str:
        """Return the contract severity implied by the blocking flag."""

        return "ERROR" if self.blocking else "WARNING"

    @property
    def message_key(self) -> str:
        """Return a stable localization key without embedding untrusted text."""

        return f"zipImport.issue.{self.code.lower()}"


@dataclass(frozen=True, slots=True)
class ZipEntry:
    """One bounded central-directory entry and its extraction evidence."""

    index: int
    source_name: str
    source_name_bytes: bytes
    normalized_path: str
    parent_normalized_path: str
    normalized_name: str
    entry_type: str
    depth: int
    flags: int
    compression_method_code: int
    compression_method: str
    external_attributes: int
    compressed_size_bytes: int
    declared_uncompressed_size_bytes: int
    crc32_declared: str
    local_header_offset: int
    data_offset: int
    data_end_offset: int
    actual_uncompressed_size_bytes: int | None = None
    crc32_actual: str | None = None
    sha256: str | None = None
    issues: tuple[ZipIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class ZipValidationResult:
    """Structural inventory and optional successful extraction evidence."""

    entries_declared: int
    inventory_complete: bool
    entries: tuple[ZipEntry, ...]
    issues: tuple[ZipIssue, ...]
    archive_comment_present: bool
    compression_methods_observed: tuple[int, ...]
    declared_extracted_bytes: int
    actual_extracted_bytes: int
    max_depth: int
    extraction_root: Path | None = None

    @property
    def accepted(self) -> bool:
        """Return whether no blocking structural issue exists."""

        return not any(issue.blocking for issue in self.issues)


class ZipStructureValidator:
    """Inspect and safely extract one conventional ZIP under frozen limits."""

    def __init__(
        self,
        limits: ZipImportLimits | None = None,
        *,
        chunk_bytes: int = STREAM_CHUNK_BYTES,
    ) -> None:
        if chunk_bytes <= 0:
            raise ValueError("chunk_bytes must be positive.")
        self.limits = limits or ZipImportLimits()
        self.chunk_bytes = chunk_bytes

    def inspect(self, sip_path: Path) -> ZipValidationResult:
        """Parse the complete bounded ZIP structure without extracting content."""

        with sip_path.open("rb") as source:
            file_size = _file_size(source)
            if file_size > self.limits.max_compressed_bytes:
                return _terminal_result("ZIP_SIZE_LIMIT")
            eocd_offset, eocd = _find_eocd(source, file_size)
            if eocd is None:
                return _terminal_result("ZIP_FORMAT_UNSUPPORTED")

            (
                disk_number,
                central_disk,
                entries_on_disk,
                entries_declared,
                central_size,
                central_offset,
                comment_length,
            ) = eocd
            issues: list[ZipIssue] = []
            comment_present = comment_length > 0
            if comment_present:
                issues.append(ZipIssue("ARCHIVE_COMMENT_IGNORED", blocking=False))
            if (
                disk_number != 0
                or central_disk != 0
                or entries_on_disk != entries_declared
            ):
                issues.append(ZipIssue("MULTI_DISK_NOT_ALLOWED"))
            if (
                entries_declared == 0xFFFF
                or entries_on_disk == 0xFFFF
                or central_size == 0xFFFFFFFF
                or central_offset == 0xFFFFFFFF
                or _has_zip64_marker(source, eocd_offset)
            ):
                issues.append(ZipIssue("ZIP64_NOT_ALLOWED"))
            if entries_declared > self.limits.max_entries:
                issues.append(
                    ZipIssue(
                        "ENTRY_COUNT_LIMIT",
                        details=(("declared", entries_declared),),
                    )
                )
                return ZipValidationResult(
                    entries_declared=entries_declared,
                    inventory_complete=False,
                    entries=(),
                    issues=tuple(issues),
                    archive_comment_present=comment_present,
                    compression_methods_observed=(),
                    declared_extracted_bytes=0,
                    actual_extracted_bytes=0,
                    max_depth=0,
                )
            if central_offset + central_size != eocd_offset:
                issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED"))
                return _result_with_issues(entries_declared, issues, comment_present)

            parsed_entries, parse_issues = self._parse_central_directory(
                source,
                central_offset=central_offset,
                central_size=central_size,
                entries_declared=entries_declared,
            )
            issues.extend(parse_issues)
            if len(parsed_entries) != entries_declared:
                issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED"))
            issues.extend(self._validate_paths(parsed_entries))
            issues.extend(
                self._validate_local_headers(
                    source,
                    parsed_entries,
                    central_offset=central_offset,
                )
            )
            issues.extend(self._validate_declared_limits(parsed_entries))

            if (
                parsed_entries
                and min(entry.local_header_offset for entry in parsed_entries) != 0
            ):
                issues.append(ZipIssue("SELF_EXTRACTING_ZIP_NOT_ALLOWED"))
            if not any(entry.entry_type == "file" for entry in parsed_entries):
                issues.append(ZipIssue("NO_IMPORTABLE_CONTENT"))

            methods = tuple(
                sorted({entry.compression_method_code for entry in parsed_entries})
            )
            return ZipValidationResult(
                entries_declared=entries_declared,
                inventory_complete=len(parsed_entries) == entries_declared,
                entries=tuple(parsed_entries),
                issues=_deduplicate_issues(issues),
                archive_comment_present=comment_present,
                compression_methods_observed=methods,
                declared_extracted_bytes=sum(
                    entry.declared_uncompressed_size_bytes
                    for entry in parsed_entries
                    if entry.entry_type == "file"
                ),
                actual_extracted_bytes=0,
                max_depth=max((entry.depth for entry in parsed_entries), default=0),
            )

    def validate_and_extract(
        self,
        sip_path: Path,
        work_root: Path,
    ) -> ZipValidationResult:
        """Inspect, then individually extract a structurally accepted archive.

        ``work_root`` must not exist. Any extraction failure removes all output
        before returning a rejected result.
        """

        inspected = self.inspect(sip_path)
        if not inspected.accepted:
            return inspected
        try:
            work_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError as error:
            raise ValueError("Extraction root must not already exist.") from error

        entries = list(inspected.entries)
        issues = list(inspected.issues)
        actual_total = 0
        try:
            with zipfile.ZipFile(sip_path, "r") as archive:
                infos = archive.infolist()
                if len(infos) != len(entries):
                    issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED"))
                    raise _ExtractionRejected
                compressed_total = sum(
                    entry.compressed_size_bytes
                    for entry in entries
                    if entry.entry_type == "file"
                )
                for index, (entry, info) in enumerate(zip(entries, infos, strict=True)):
                    if info.header_offset != entry.local_header_offset:
                        issues.append(
                            ZipIssue("ZIP_FORMAT_UNSUPPORTED", entry_index=index)
                        )
                        raise _ExtractionRejected
                    destination = _safe_destination(work_root, entry.normalized_path)
                    if entry.entry_type == "directory":
                        _mkdir_no_links(work_root, destination)
                        try:
                            with archive.open(info, "r") as source:
                                if source.read(1):
                                    issues.append(
                                        _entry_issue("ZIP_FORMAT_UNSUPPORTED", entry)
                                    )
                                    raise _ExtractionRejected
                        except (zipfile.BadZipFile, RuntimeError, EOFError, zlib.error):
                            issues.append(_entry_issue("ZIP_CRC_MISMATCH", entry))
                            raise _ExtractionRejected
                        continue
                    _mkdir_no_links(work_root, destination.parent)
                    digest = hashlib.sha256()
                    crc = 0
                    actual_size = 0
                    try:
                        with archive.open(info, "r") as source, destination.open(
                            "xb"
                        ) as target:
                            while chunk := source.read(self.chunk_bytes):
                                actual_size += len(chunk)
                                actual_total += len(chunk)
                                if actual_size > self.limits.max_individual_file_bytes:
                                    issues.append(
                                        _entry_issue("ENTRY_SIZE_LIMIT", entry)
                                    )
                                    raise _ExtractionRejected
                                if actual_total > self.limits.max_extracted_bytes:
                                    issues.append(
                                        _entry_issue("EXTRACTED_TOTAL_LIMIT", entry)
                                    )
                                    raise _ExtractionRejected
                                if _ratio_exceeded(
                                    actual_total,
                                    compressed_total,
                                    self.limits.max_aggregate_compression_ratio,
                                ):
                                    issues.append(ZipIssue("COMPRESSION_RATIO_LIMIT"))
                                    raise _ExtractionRejected
                                if _ratio_exceeded(
                                    actual_size,
                                    entry.compressed_size_bytes,
                                    self.limits.max_compression_ratio_per_file,
                                ):
                                    issues.append(
                                        _entry_issue("COMPRESSION_RATIO_LIMIT", entry)
                                    )
                                    raise _ExtractionRejected
                                target.write(chunk)
                                digest.update(chunk)
                                crc = binascii.crc32(chunk, crc)
                    except (zipfile.BadZipFile, RuntimeError, EOFError, zlib.error):
                        issues.append(_entry_issue("ZIP_CRC_MISMATCH", entry))
                        raise _ExtractionRejected
                    crc_hex = f"{crc & 0xFFFFFFFF:08x}"
                    if (
                        actual_size != entry.declared_uncompressed_size_bytes
                        or crc_hex != entry.crc32_declared
                    ):
                        issues.append(_entry_issue("ZIP_CRC_MISMATCH", entry))
                        raise _ExtractionRejected
                    entries[index] = replace(
                        entry,
                        actual_uncompressed_size_bytes=actual_size,
                        crc32_actual=crc_hex,
                        sha256=digest.hexdigest(),
                    )
                if _ratio_exceeded(
                    actual_total,
                    compressed_total,
                    self.limits.max_aggregate_compression_ratio,
                ):
                    issues.append(ZipIssue("COMPRESSION_RATIO_LIMIT"))
                    raise _ExtractionRejected
        except _ExtractionRejected:
            shutil.rmtree(work_root, ignore_errors=True)
            return replace(
                inspected,
                entries=tuple(entries),
                issues=_deduplicate_issues(issues),
                actual_extracted_bytes=actual_total,
            )
        except Exception:
            shutil.rmtree(work_root, ignore_errors=True)
            raise

        return replace(
            inspected,
            entries=tuple(entries),
            issues=_deduplicate_issues(issues),
            actual_extracted_bytes=actual_total,
            extraction_root=work_root,
        )

    def _parse_central_directory(
        self,
        source: BinaryIO,
        *,
        central_offset: int,
        central_size: int,
        entries_declared: int,
    ) -> tuple[list[ZipEntry], list[ZipIssue]]:
        source.seek(central_offset)
        central = source.read(central_size)
        if len(central) != central_size:
            return [], [ZipIssue("ZIP_FORMAT_UNSUPPORTED")]
        cursor = 0
        entries: list[ZipEntry] = []
        issues: list[ZipIssue] = []
        for index in range(entries_declared):
            if cursor + CENTRAL_FIXED_BYTES > len(central):
                issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED", entry_index=index))
                break
            fixed = central[cursor : cursor + CENTRAL_FIXED_BYTES]
            values = struct.unpack("<4s6H3L5H2L", fixed)
            if values[0] != CENTRAL_SIGNATURE:
                issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED", entry_index=index))
                break
            (
                _,
                version_made,
                version_needed,
                flags,
                method,
                _,
                _,
                crc32,
                compressed_size,
                uncompressed_size,
                name_length,
                extra_length,
                entry_comment_length,
                disk_start,
                _,
                external_attributes,
                local_offset,
            ) = values
            variable_end = (
                cursor
                + CENTRAL_FIXED_BYTES
                + name_length
                + extra_length
                + entry_comment_length
            )
            if variable_end > len(central) or name_length == 0:
                issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED", entry_index=index))
                break
            name_start = cursor + CENTRAL_FIXED_BYTES
            raw_name = central[name_start : name_start + name_length]
            extra = central[
                name_start + name_length : name_start + name_length + extra_length
            ]
            source_name, encoding_issue = _decode_name(raw_name, flags)
            path_for_issue = _bounded_path(source_name)
            if encoding_issue:
                issues.append(
                    ZipIssue(
                        "INVALID_NAME_ENCODING",
                        entry_index=index,
                        path=path_for_issue,
                    )
                )
            extra_ids, extra_valid = _extra_field_ids(extra)
            if not extra_valid:
                issues.append(
                    ZipIssue(
                        "ZIP_FORMAT_UNSUPPORTED", entry_index=index, path=path_for_issue
                    )
                )
            if (
                disk_start == 0xFFFF
                or compressed_size == 0xFFFFFFFF
                or uncompressed_size == 0xFFFFFFFF
                or local_offset == 0xFFFFFFFF
                or 0x0001 in extra_ids
            ):
                issues.append(
                    ZipIssue(
                        "ZIP64_NOT_ALLOWED", entry_index=index, path=path_for_issue
                    )
                )
            elif version_needed > 20:
                issues.append(
                    ZipIssue(
                        "ZIP_FORMAT_UNSUPPORTED",
                        entry_index=index,
                        path=path_for_issue,
                    )
                )
            if disk_start not in {0, 0xFFFF}:
                issues.append(
                    ZipIssue(
                        "MULTI_DISK_NOT_ALLOWED",
                        entry_index=index,
                        path=path_for_issue,
                    )
                )
            if flags & ENCRYPTED_FLAGS or 0x9901 in extra_ids:
                issues.append(
                    ZipIssue("ENCRYPTED_ENTRY", entry_index=index, path=path_for_issue)
                )
            if flags & ~ALLOWED_GENERAL_PURPOSE_FLAGS:
                issues.append(
                    ZipIssue(
                        "ZIP_FORMAT_UNSUPPORTED",
                        entry_index=index,
                        path=path_for_issue,
                    )
                )
            if method != zipfile.ZIP_DEFLATED and flags & ((1 << 1) | (1 << 2)):
                issues.append(
                    ZipIssue(
                        "ZIP_FORMAT_UNSUPPORTED",
                        entry_index=index,
                        path=path_for_issue,
                    )
                )
            if method not in ALLOWED_METHODS:
                issues.append(
                    ZipIssue(
                        "UNSUPPORTED_COMPRESSION_METHOD",
                        entry_index=index,
                        path=path_for_issue,
                        details=(("method", method),),
                    )
                )

            unix_mode = (
                (external_attributes >> 16) & 0xFFFF if version_made >> 8 == 3 else 0
            )
            name_is_directory = source_name.endswith(("/", "\\"))
            entry_type = "directory" if name_is_directory else "file"
            if unix_mode:
                file_type = stat.S_IFMT(unix_mode)
                if file_type == stat.S_IFLNK:
                    issues.append(
                        ZipIssue(
                            "SYMLINK_NOT_ALLOWED",
                            entry_index=index,
                            path=path_for_issue,
                        )
                    )
                elif file_type == stat.S_IFDIR:
                    entry_type = "directory"
                elif file_type not in {0, stat.S_IFREG}:
                    issues.append(
                        ZipIssue(
                            "SPECIAL_FILE_NOT_ALLOWED",
                            entry_index=index,
                            path=path_for_issue,
                        )
                    )
                if (file_type == stat.S_IFDIR and not name_is_directory) or (
                    file_type == stat.S_IFREG and name_is_directory
                ):
                    issues.append(
                        ZipIssue(
                            "ZIP_FORMAT_UNSUPPORTED",
                            entry_index=index,
                            path=path_for_issue,
                        )
                    )
            if entry_type == "directory" and (uncompressed_size != 0 or crc32 != 0):
                issues.append(
                    ZipIssue(
                        "ZIP_FORMAT_UNSUPPORTED",
                        entry_index=index,
                        path=path_for_issue,
                    )
                )

            normalized_path, parent, normalized_name, depth = _normalized_path_facts(
                source_name,
                entry_type,
            )
            entries.append(
                ZipEntry(
                    index=index,
                    source_name=source_name,
                    source_name_bytes=raw_name,
                    normalized_path=normalized_path,
                    parent_normalized_path=parent,
                    normalized_name=normalized_name,
                    entry_type=entry_type,
                    depth=depth,
                    flags=flags,
                    compression_method_code=method,
                    compression_method=ALLOWED_METHODS.get(method, "unsupported"),
                    external_attributes=external_attributes,
                    compressed_size_bytes=compressed_size,
                    declared_uncompressed_size_bytes=uncompressed_size,
                    crc32_declared=f"{crc32:08x}",
                    local_header_offset=local_offset,
                    data_offset=0,
                    data_end_offset=0,
                )
            )
            cursor = variable_end
        if cursor != len(central):
            issues.append(ZipIssue("ZIP_FORMAT_UNSUPPORTED"))
        return entries, issues

    def _validate_paths(self, entries: list[ZipEntry]) -> list[ZipIssue]:
        issues: list[ZipIssue] = []
        exact_paths: dict[str, ZipEntry] = {}
        normalized_paths: dict[str, ZipEntry] = {}
        portable_paths: dict[str, ZipEntry] = {}
        file_paths: set[str] = set()
        all_paths = {
            entry.normalized_path: entry for entry in entries if entry.normalized_path
        }
        for entry in entries:
            source_path = entry.source_name.replace("\\", "/")
            issue_path = _bounded_path(entry.normalized_path or source_path)
            segments = [
                segment for segment in source_path.rstrip("/").split("/") if segment
            ]
            if (
                source_path.startswith("/")
                or source_path.startswith("//")
                or DRIVE_PATH_RE.match(source_path)
            ):
                issues.append(_entry_issue("ABSOLUTE_PATH", entry, issue_path))
            if any(segment == ".." for segment in source_path.split("/")):
                issues.append(_entry_issue("PARENT_TRAVERSAL", entry, issue_path))
            if "\x00" in entry.source_name:
                issues.append(_entry_issue("NUL_IN_NAME", entry, issue_path))
            if not segments or any(
                segment in {"", "."} for segment in source_path.rstrip("/").split("/")
            ):
                issues.append(_entry_issue("RESERVED_NAME", entry, issue_path))
            for segment in segments:
                normalized_segment = unicodedata.normalize("NFC", segment)
                if (
                    len(normalized_segment.encode("utf-8"))
                    > self.limits.max_path_segment_utf8_bytes
                ):
                    issues.append(
                        _entry_issue("PATH_SEGMENT_LENGTH_LIMIT", entry, issue_path)
                    )
                if _is_reserved_segment(normalized_segment):
                    issues.append(_entry_issue("RESERVED_NAME", entry, issue_path))
            if (
                len(entry.normalized_path.encode("utf-8"))
                > self.limits.max_relative_path_utf8_bytes
            ):
                issues.append(_entry_issue("PATH_LENGTH_LIMIT", entry, issue_path))
            if entry.depth > self.limits.max_directory_depth:
                issues.append(_entry_issue("PATH_DEPTH_LIMIT", entry, issue_path))

            exact_key = source_path.rstrip("/")
            existing_exact = exact_paths.get(exact_key)
            if existing_exact is not None:
                code = (
                    "FILE_DIRECTORY_CONFLICT"
                    if existing_exact.entry_type != entry.entry_type
                    else "DUPLICATE_PATH"
                )
                issues.append(_entry_issue(code, entry, issue_path))
            else:
                exact_paths[exact_key] = entry

            existing_normalized = normalized_paths.get(entry.normalized_path)
            if (
                existing_normalized is not None
                and existing_normalized.source_name != entry.source_name
            ):
                code = (
                    "FILE_DIRECTORY_CONFLICT"
                    if existing_normalized.entry_type != entry.entry_type
                    else "NAME_NORMALIZATION_COLLISION"
                )
                issues.append(_entry_issue(code, entry, issue_path))
            else:
                normalized_paths[entry.normalized_path] = entry

            portable_key = _portable_path_key(entry.normalized_path)
            existing_portable = portable_paths.get(portable_key)
            if (
                existing_portable is not None
                and existing_portable.normalized_path != entry.normalized_path
            ):
                code = (
                    "FILE_DIRECTORY_CONFLICT"
                    if existing_portable.entry_type != entry.entry_type
                    else "CASE_COLLISION"
                )
                issues.append(_entry_issue(code, entry, issue_path))
            else:
                portable_paths[portable_key] = entry
            if entry.entry_type == "file":
                file_paths.add(entry.normalized_path)

        for path, entry in all_paths.items():
            for parent in PurePosixPath(path).parents:
                parent_text = "" if str(parent) == "." else str(parent)
                if parent_text in file_paths:
                    issues.append(_entry_issue("FILE_DIRECTORY_CONFLICT", entry))
                    break
        return issues

    def _validate_local_headers(
        self,
        source: BinaryIO,
        entries: list[ZipEntry],
        *,
        central_offset: int,
    ) -> list[ZipIssue]:
        issues: list[ZipIssue] = []
        ranges: list[tuple[int, int, int]] = []
        for list_index, entry in enumerate(entries):
            source.seek(entry.local_header_offset)
            fixed = source.read(LOCAL_FIXED_BYTES)
            if len(fixed) != LOCAL_FIXED_BYTES:
                issues.append(_entry_issue("ZIP_FORMAT_UNSUPPORTED", entry))
                continue
            values = struct.unpack("<4s5H3L2H", fixed)
            if values[0] != LOCAL_SIGNATURE:
                issues.append(_entry_issue("ZIP_FORMAT_UNSUPPORTED", entry))
                continue
            (
                _,
                _,
                local_flags,
                local_method,
                _,
                _,
                local_crc,
                local_compressed,
                local_uncompressed,
                name_length,
                extra_length,
            ) = values
            raw_name = source.read(name_length)
            local_extra = source.read(extra_length)
            data_offset = (
                entry.local_header_offset
                + LOCAL_FIXED_BYTES
                + name_length
                + extra_length
            )
            data_end = data_offset + entry.compressed_size_bytes
            if (
                raw_name != entry.source_name_bytes
                or local_flags != entry.flags
                or local_method != entry.compression_method_code
                or data_end > central_offset
            ):
                issues.append(_entry_issue("ZIP_FORMAT_UNSUPPORTED", entry))
            extra_ids, extra_valid = _extra_field_ids(local_extra)
            if not extra_valid:
                issues.append(_entry_issue("ZIP_FORMAT_UNSUPPORTED", entry))
            if 0x0001 in extra_ids or 0x9901 in extra_ids:
                issues.append(
                    _entry_issue(
                        (
                            "ZIP64_NOT_ALLOWED"
                            if 0x0001 in extra_ids
                            else "ENCRYPTED_ENTRY"
                        ),
                        entry,
                    )
                )
            if not entry.flags & DATA_DESCRIPTOR_FLAG and (
                local_crc != int(entry.crc32_declared, 16)
                or local_compressed != entry.compressed_size_bytes
                or local_uncompressed != entry.declared_uncompressed_size_bytes
            ):
                issues.append(_entry_issue("ZIP_FORMAT_UNSUPPORTED", entry))
            descriptor_end = data_end
            if entry.flags & DATA_DESCRIPTOR_FLAG:
                descriptor_valid, descriptor_end = _validate_data_descriptor(
                    source,
                    data_end,
                    entry,
                    central_offset,
                )
                if not descriptor_valid:
                    issues.append(_entry_issue("ZIP_FORMAT_UNSUPPORTED", entry))
            entries[list_index] = replace(
                entry,
                data_offset=data_offset,
                data_end_offset=data_end,
            )
            ranges.append((entry.local_header_offset, descriptor_end, entry.index))

        ranges.sort()
        for previous, current in zip(ranges, ranges[1:]):
            if current[0] < previous[1]:
                issues.append(
                    ZipIssue("ZIP_FORMAT_UNSUPPORTED", entry_index=current[2])
                )
        return issues

    def _validate_declared_limits(self, entries: list[ZipEntry]) -> list[ZipIssue]:
        issues: list[ZipIssue] = []
        compressed_total = 0
        extracted_total = 0
        for entry in entries:
            if entry.entry_type != "file":
                continue
            compressed_total += entry.compressed_size_bytes
            extracted_total += entry.declared_uncompressed_size_bytes
            if (
                entry.declared_uncompressed_size_bytes
                > self.limits.max_individual_file_bytes
            ):
                issues.append(_entry_issue("ENTRY_SIZE_LIMIT", entry))
            if _ratio_exceeded(
                entry.declared_uncompressed_size_bytes,
                entry.compressed_size_bytes,
                self.limits.max_compression_ratio_per_file,
            ):
                issues.append(_entry_issue("COMPRESSION_RATIO_LIMIT", entry))
        if extracted_total > self.limits.max_extracted_bytes:
            issues.append(ZipIssue("EXTRACTED_TOTAL_LIMIT"))
        if _ratio_exceeded(
            extracted_total,
            compressed_total,
            self.limits.max_aggregate_compression_ratio,
        ):
            issues.append(ZipIssue("COMPRESSION_RATIO_LIMIT"))
        return issues


class _ExtractionRejected(Exception):
    """Internal non-reportable control flow for all-or-nothing extraction."""


def _file_size(source: BinaryIO) -> int:
    source.seek(0, os.SEEK_END)
    return source.tell()


def _find_eocd(
    source: BinaryIO,
    file_size: int,
) -> tuple[int, tuple[int, int, int, int, int, int, int] | None]:
    search_size = min(file_size, MAX_EOCD_SEARCH_BYTES)
    source.seek(file_size - search_size)
    tail = source.read(search_size)
    search_end = len(tail)
    while True:
        relative_offset = tail.rfind(EOCD_SIGNATURE, 0, search_end)
        if relative_offset < 0:
            return -1, None
        if relative_offset + EOCD_FIXED_BYTES <= len(tail):
            values = struct.unpack(
                "<4s4H2LH", tail[relative_offset : relative_offset + EOCD_FIXED_BYTES]
            )
            comment_length = values[-1]
            if relative_offset + EOCD_FIXED_BYTES + comment_length == len(tail):
                return file_size - search_size + relative_offset, values[1:]
        search_end = relative_offset


def _has_zip64_marker(source: BinaryIO, eocd_offset: int) -> bool:
    if eocd_offset < 20:
        return False
    source.seek(eocd_offset - 20)
    return source.read(4) == ZIP64_LOCATOR_SIGNATURE


def _extra_field_ids(extra: bytes) -> tuple[set[int], bool]:
    ids: set[int] = set()
    cursor = 0
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            return ids, False
        field_id, field_size = struct.unpack("<HH", extra[cursor : cursor + 4])
        cursor += 4
        if cursor + field_size > len(extra):
            return ids, False
        if field_id in ids:
            return ids, False
        ids.add(field_id)
        cursor += field_size
    return ids, cursor == len(extra)


def _decode_name(raw_name: bytes, flags: int) -> tuple[str, bool]:
    if flags & UTF8_FLAG:
        try:
            return raw_name.decode("utf-8", errors="strict"), False
        except UnicodeDecodeError:
            return raw_name.decode("utf-8", errors="replace"), True
    if any(byte > 0x7F for byte in raw_name):
        return raw_name.decode("cp437", errors="replace"), True
    return raw_name.decode("ascii"), False


def _normalized_path_facts(
    source_name: str, entry_type: str
) -> tuple[str, str, str, int]:
    slash_path = source_name.replace("\\", "/")
    trimmed = slash_path.rstrip("/") if entry_type == "directory" else slash_path
    normalized = unicodedata.normalize("NFC", trimmed)
    path = PurePosixPath(normalized)
    name = "" if normalized in {"", "."} else path.name
    parent = "" if str(path.parent) == "." else str(path.parent)
    parts = [part for part in path.parts if part not in {"/", "", "."}]
    depth = len(parts) if entry_type == "directory" else max(0, len(parts) - 1)
    return normalized, parent, name, depth


def _is_reserved_segment(segment: str) -> bool:
    if any(ord(character) < 32 or ord(character) == 127 for character in segment):
        return True
    if any(character in BIDI_CONTROLS for character in segment):
        return True
    if any(character in WINDOWS_FORBIDDEN_CHARS for character in segment):
        return True
    if segment.endswith((" ", ".")):
        return True
    portable_stem = segment.rstrip(" .").split(".", 1)[0].upper()
    return portable_stem in RESERVED_WINDOWS_NAMES


def _portable_path_key(path: str) -> str:
    return "/".join(
        segment.rstrip(" .").casefold()
        for segment in path.replace("\\", "/").split("/")
    )


def _validate_data_descriptor(
    source: BinaryIO,
    data_end: int,
    entry: ZipEntry,
    central_offset: int,
) -> tuple[bool, int]:
    source.seek(data_end)
    prefix = source.read(16)
    if prefix.startswith(DATA_DESCRIPTOR_SIGNATURE):
        descriptor = prefix[4:16]
        descriptor_end = data_end + 16
    else:
        descriptor = prefix[:12]
        descriptor_end = data_end + 12
    if len(descriptor) != 12 or descriptor_end > central_offset:
        return False, descriptor_end
    crc, compressed_size, uncompressed_size = struct.unpack("<3L", descriptor)
    return (
        crc == int(entry.crc32_declared, 16)
        and compressed_size == entry.compressed_size_bytes
        and uncompressed_size == entry.declared_uncompressed_size_bytes,
        descriptor_end,
    )


def _safe_destination(root: Path, relative_path: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("Validated extraction path escaped its root.") from error
    return candidate


def _mkdir_no_links(root: Path, directory: Path) -> None:
    relative = directory.relative_to(root)
    current = root
    for segment in relative.parts:
        current = current / segment
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            if current.is_symlink() or not current.is_dir():
                raise OSError("Extraction parent is not a real directory.")


def _ratio_exceeded(uncompressed: int, compressed: int, limit: int) -> bool:
    if uncompressed == 0:
        return False
    if compressed == 0:
        return True
    return uncompressed > compressed * limit


def _entry_issue(code: str, entry: ZipEntry, path: str | None = None) -> ZipIssue:
    return ZipIssue(
        code,
        entry_index=entry.index,
        path=_bounded_path(path if path is not None else entry.normalized_path),
    )


def _bounded_path(path: str) -> str | None:
    if not path:
        return None
    return path[:1024]


def _deduplicate_issues(issues: list[ZipIssue]) -> tuple[ZipIssue, ...]:
    return tuple(dict.fromkeys(issues))


def _terminal_result(code: str) -> ZipValidationResult:
    return _result_with_issues(0, [ZipIssue(code)], False)


def _result_with_issues(
    entries_declared: int,
    issues: list[ZipIssue],
    comment_present: bool,
) -> ZipValidationResult:
    return ZipValidationResult(
        entries_declared=entries_declared,
        inventory_complete=False,
        entries=(),
        issues=_deduplicate_issues(issues),
        archive_comment_present=comment_present,
        compression_methods_observed=(),
        declared_extracted_bytes=0,
        actual_extracted_bytes=0,
        max_depth=0,
    )
