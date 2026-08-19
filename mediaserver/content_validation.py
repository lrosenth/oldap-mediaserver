"""Bounded content and codec validation for extracted ZIP import entries."""

from __future__ import annotations

import importlib
import json
import math
import re
import shutil
import subprocess
import tempfile
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable

from PIL import Image, UnidentifiedImageError

from config import ZipImportLimits
from media import detect_heif_variant, heif_page_count
from zip_validation import ZipEntry, ZipValidationResult


CONTENT_ISSUE_CODES = frozenset(
    {
        "AUDIO_BIT_DEPTH_UNSUPPORTED",
        "AUDIO_CHANNEL_LIMIT",
        "AUDIO_CODEC_UNSUPPORTED",
        "AUDIO_SAMPLE_RATE_UNSUPPORTED",
        "EXTENSION_CONTENT_MISMATCH",
        "IMAGE_AXIS_LIMIT",
        "IMAGE_PIXEL_LIMIT",
        "MULTI_IMAGE_HEIF_NOT_ALLOWED",
        "MULTIPAGE_TIFF_NOT_ALLOWED",
        "NESTED_ARCHIVE_NOT_ALLOWED",
        "NO_IMPORTABLE_CONTENT",
        "PACKAGING_ARTIFACT_IGNORED",
        "PARSER_FAILURE",
        "PDF_ACTIVE_CONTENT",
        "PDF_ATTACHMENT_NOT_ALLOWED",
        "PDF_ENCRYPTED",
        "PDF_NOT_PDFA_1_OR_2",
        "TEXT_INVALID_UTF8",
        "TEXT_SIZE_LIMIT",
        "TARGET_CHANGED",
        "TARGET_FOLDER_COLLISION",
        "TARGET_MEDIA_NAME_COLLISION",
        "UNSUPPORTED_MEDIA_TYPE",
        "VALIDATION_TIMEOUT",
        "VIDEO_AUDIO_CODEC_UNSUPPORTED",
        "VIDEO_CODEC_UNSUPPORTED",
        "VIDEO_DIMENSION_LIMIT",
        "VIDEO_DURATION_LIMIT",
        "VIDEO_FRAMERATE_LIMIT",
        "VIDEO_STREAM_LAYOUT_UNSUPPORTED",
    }
)
PACKAGING_NAMES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})
NESTED_ARCHIVE_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
)
STRUCTURED_TEXT_PREFIXES = (
    b"<!doctype",
    b"<html",
    b"<?xml",
    b"<svg",
    b"{\\rtf",
    b"#!",
)
FFPROBE_TIMEOUT_SECONDS = 60
PDFINFO_TIMEOUT_SECONDS = 60
QPDF_TIMEOUT_SECONDS = 60
VERAPDF_TIMEOUT_SECONDS = 300
MAX_TOOL_OUTPUT_BYTES = 8 * 1024 * 1024
PDFA_RE = re.compile(r"PDF/A[-_ ]?([1-4])\s*([ABUEF])", re.IGNORECASE)


class ContentValidationError(RuntimeError):
    """Base class for validation pipeline failures."""


class ContentToolUnavailable(ContentValidationError):
    """Raised when a required parser is absent from the worker image."""


@dataclass(frozen=True, slots=True)
class ContentIssue:
    """One stable content-level validation finding."""

    code: str
    blocking: bool = True
    entry_index: int | None = None
    path: str | None = None
    details: tuple[tuple[str, int | float | str | bool], ...] = ()

    def __post_init__(self) -> None:
        if self.code not in CONTENT_ISSUE_CODES:
            raise ValueError(f"Unknown content issue code: {self.code}")

    @property
    def severity(self) -> str:
        return "ERROR" if self.blocking else "WARNING"

    @property
    def message_key(self) -> str:
        return f"zipImport.issue.{self.code.lower()}"


@dataclass(frozen=True, slots=True)
class ContentEntryResult:
    """Disposition, detected facts, and resource plan for one ZIP entry."""

    entry_index: int
    disposition: str
    detected_content: dict[str, Any] | None = None
    planned_resource: dict[str, Any] | None = None
    issues: tuple[ContentIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class ContentValidationResult:
    """Complete content evidence layered over structural extraction facts."""

    structural: ZipValidationResult
    entries: tuple[ContentEntryResult, ...]
    issues: tuple[ContentIssue, ...] = ()

    @property
    def accepted(self) -> bool:
        return not any(
            issue.blocking
            for issue in self.issues
            + tuple(issue for entry in self.entries for issue in entry.issues)
        )


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ImageLoader = Callable[..., Any]


class ContentValidator:
    """Validate each extracted entry sequentially against the MVP matrix."""

    def __init__(
        self,
        limits: ZipImportLimits | None = None,
        *,
        command_runner: CommandRunner = subprocess.run,
        heif_loader: ImageLoader | None = None,
    ) -> None:
        self.limits = limits or ZipImportLimits()
        self.command_runner = command_runner
        self.heif_loader = heif_loader

    @staticmethod
    def validate_runtime() -> None:
        """Fail startup when the production content toolchain is incomplete."""

        missing = [
            tool
            for tool in ("ffprobe", "pdfinfo", "prlimit", "qpdf", "verapdf")
            if shutil.which(tool) is None
        ]
        if missing:
            raise ContentToolUnavailable(
                f"Required content tools are missing: {', '.join(missing)}"
            )
        try:
            pyvips = importlib.import_module("pyvips")
            heif_available = bool(pyvips.type_find("VipsOperation", "heifload"))
        except (ImportError, OSError, AttributeError):
            heif_available = False
        if not heif_available:
            raise ContentToolUnavailable(
                "Required libvips HEIF/HEIC loader is missing."
            )

    def validate(self, structural: ZipValidationResult) -> ContentValidationResult:
        """Return a complete inventory without trusting extensions or MIME hints."""

        if not structural.accepted or structural.extraction_root is None:
            raise ValueError("Content validation requires successful extraction.")
        results: list[ContentEntryResult] = []
        for entry in structural.entries:
            if _is_packaging_artifact(entry.normalized_path):
                results.append(
                    ContentEntryResult(
                        entry_index=entry.index,
                        disposition="IGNORE",
                        issues=(
                            _entry_issue(
                                "PACKAGING_ARTIFACT_IGNORED", entry, blocking=False
                            ),
                        ),
                    )
                )
                continue
            if entry.entry_type == "directory":
                results.append(
                    ContentEntryResult(
                        entry_index=entry.index,
                        disposition="IMPORT",
                        planned_resource={
                            "kind": "folder",
                            "resourceClass": "shared:StagingFolder",
                            "name": entry.normalized_name,
                        },
                    )
                )
                continue
            source = structural.extraction_root / entry.normalized_path
            results.append(self._validate_file(entry, source))

        issues: tuple[ContentIssue, ...] = ()
        if not any(
            item.disposition == "IMPORT" and item.detected_content for item in results
        ):
            issues = (ContentIssue("NO_IMPORTABLE_CONTENT"),)
        return ContentValidationResult(
            structural=structural,
            entries=tuple(results),
            issues=issues,
        )

    def _validate_file(self, entry: ZipEntry, source: Path) -> ContentEntryResult:
        with source.open("rb") as handle:
            header = handle.read(4096)
        kind = _detect_kind(header)
        try:
            if kind in {"jpeg", "tiff", "png"}:
                facts, issues = self._probe_image(entry, source, kind)
            elif kind in {"heic", "heif"}:
                facts, issues = self._probe_heif(entry, source, kind)
            elif kind in {"wav", "flac", "mp3"}:
                facts, issues = self._probe_audio(entry, source, kind)
            elif kind == "mp4":
                facts, issues = self._probe_video(entry, source)
            elif kind == "pdf":
                facts, issues = self._probe_pdf(entry, source)
            elif kind == "nested-archive":
                facts = _unsupported("application/octet-stream", "ARCHIVE")
                issues = (_entry_issue("NESTED_ARCHIVE_NOT_ALLOWED", entry),)
            elif kind == "unsupported-binary":
                facts = _unsupported("application/octet-stream", "BINARY")
                issues = (_entry_issue("UNSUPPORTED_MEDIA_TYPE", entry),)
            else:
                facts, issues = self._probe_text(entry, source)
        except ContentToolUnavailable:
            raise
        except Exception:
            facts = _unsupported("application/octet-stream", kind.upper())
            issues = (_entry_issue("PARSER_FAILURE", entry),)

        issues = issues + _extension_issue(entry, facts)
        blocking = any(issue.blocking for issue in issues)
        return ContentEntryResult(
            entry_index=entry.index,
            disposition="REJECT" if blocking else "IMPORT",
            detected_content=facts,
            planned_resource=(None if blocking else _media_plan(entry, facts)),
            issues=issues,
        )

    def _probe_image(
        self, entry: ZipEntry, source: Path, kind: str
    ) -> tuple[dict[str, Any], tuple[ContentIssue, ...]]:
        issues: list[ContentIssue] = []
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(source) as image:
                    detected = (image.format or "").upper()
                    width, height = image.size
                    pages = int(getattr(image, "n_frames", 1))
                    image.verify()
                with Image.open(source) as image:
                    image.load()
        except (
            UnidentifiedImageError,
            OSError,
            SyntaxError,
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
        ):
            return _unsupported("application/octet-stream", kind.upper()), (
                _entry_issue("PARSER_FAILURE", entry),
            )
        expected = {"jpeg": "JPEG", "tiff": "TIFF", "png": "PNG"}[kind]
        if detected != expected:
            return _unsupported("application/octet-stream", detected or kind.upper()), (
                _entry_issue("UNSUPPORTED_MEDIA_TYPE", entry),
            )
        if (
            width > self.limits.max_image_axis_pixels
            or height > self.limits.max_image_axis_pixels
        ):
            issues.append(_entry_issue("IMAGE_AXIS_LIMIT", entry))
        if width * height > self.limits.max_image_pixels:
            issues.append(_entry_issue("IMAGE_PIXEL_LIMIT", entry))
        if kind == "tiff" and pages != 1:
            issues.append(_entry_issue("MULTIPAGE_TIFF_NOT_ALLOWED", entry))
        return (
            {
                "category": "image",
                "mimeType": {
                    "jpeg": "image/jpeg",
                    "tiff": "image/tiff",
                    "png": "image/png",
                }[kind],
                "format": expected,
                "width": width,
                "height": height,
                "pageCount": pages,
            },
            tuple(issues),
        )

    def _probe_heif(
        self, entry: ZipEntry, source: Path, kind: str
    ) -> tuple[dict[str, Any], tuple[ContentIssue, ...]]:
        """Decode one HEIF/HEIC still image through the production libvips path."""

        loader = self.heif_loader
        if loader is None:
            try:
                pyvips = importlib.import_module("pyvips")
                if not pyvips.type_find("VipsOperation", "heifload"):
                    raise ContentToolUnavailable(
                        "Required libvips HEIF/HEIC loader is missing."
                    )
                loader = pyvips.Image.new_from_file
            except (ImportError, OSError, AttributeError) as error:
                raise ContentToolUnavailable(
                    "Required libvips HEIF/HEIC loader is missing."
                ) from error

        image = loader(str(source), access="sequential")
        image_loader = _vips_metadata(image, "vips-loader")
        if image_loader and image_loader != "heifload":
            return _unsupported("application/octet-stream", kind.upper()), (
                _entry_issue("UNSUPPORTED_MEDIA_TYPE", entry),
            )
        width = _positive_int(getattr(image, "width", None)) or 0
        height = _positive_int(getattr(image, "height", None)) or 0
        pages = heif_page_count(image)
        issues: list[ContentIssue] = []
        if width <= 0 or height <= 0:
            return _unsupported("application/octet-stream", kind.upper()), (
                _entry_issue("PARSER_FAILURE", entry),
            )
        if (
            width > self.limits.max_image_axis_pixels
            or height > self.limits.max_image_axis_pixels
        ):
            issues.append(_entry_issue("IMAGE_AXIS_LIMIT", entry))
        if width * height > self.limits.max_image_pixels:
            issues.append(_entry_issue("IMAGE_PIXEL_LIMIT", entry))
        if pages != 1:
            issues.append(_entry_issue("MULTI_IMAGE_HEIF_NOT_ALLOWED", entry))
        if not issues:
            # libvips is lazy. Requesting a scalar over the image forces a full
            # decode without retaining a second uncompressed image in Python.
            image.avg()
        mime_type = "image/heic" if kind == "heic" else "image/heif"
        return (
            {
                "category": "image",
                "mimeType": mime_type,
                "format": kind.upper(),
                "width": width,
                "height": height,
                "pageCount": pages,
            },
            tuple(issues),
        )

    def _probe_audio(
        self, entry: ZipEntry, source: Path, kind: str
    ) -> tuple[dict[str, Any], tuple[ContentIssue, ...]]:
        payload = self._ffprobe(source)
        streams = payload.get("streams", [])
        audio = [stream for stream in streams if stream.get("codec_type") == "audio"]
        issues: list[ContentIssue] = []
        if len(audio) != 1 or len(streams) != 1:
            issues.append(_entry_issue("AUDIO_CODEC_UNSUPPORTED", entry))
        stream = audio[0] if audio else {}
        codec = str(stream.get("codec_name") or "")
        channels = _positive_int(stream.get("channels")) or 0
        sample_rate = _positive_int(stream.get("sample_rate")) or 0
        bits = _positive_int(stream.get("bits_per_raw_sample")) or _positive_int(
            stream.get("bits_per_sample")
        )
        allowed_codecs = {
            "wav": {"pcm_u8": 8, "pcm_s16le": 16, "pcm_s24le": 24, "pcm_s32le": 32},
            "flac": {"flac": bits or 0},
            "mp3": {"mp3": bits or 0},
        }
        if codec not in allowed_codecs[kind]:
            issues.append(_entry_issue("AUDIO_CODEC_UNSUPPORTED", entry))
        if channels < 1 or channels > self.limits.max_audio_channels:
            issues.append(_entry_issue("AUDIO_CHANNEL_LIMIT", entry))
        max_rate = {
            "wav": self.limits.max_wav_pcm_sample_rate_hz,
            "flac": self.limits.max_flac_sample_rate_hz,
            "mp3": self.limits.max_mp3_sample_rate_hz,
        }[kind]
        if not self.limits.min_audio_sample_rate_hz <= sample_rate <= max_rate:
            issues.append(_entry_issue("AUDIO_SAMPLE_RATE_UNSUPPORTED", entry))
        if kind == "wav":
            expected_bits = allowed_codecs[kind].get(codec)
            bits = bits or expected_bits
            if (
                bits not in self.limits.allowed_wav_pcm_bits_per_sample
                or bits != expected_bits
            ):
                issues.append(_entry_issue("AUDIO_BIT_DEPTH_UNSUPPORTED", entry))
        elif kind == "flac" and bits not in self.limits.allowed_flac_bits_per_sample:
            issues.append(_entry_issue("AUDIO_BIT_DEPTH_UNSUPPORTED", entry))
        facts: dict[str, Any] = {
            "category": "audio",
            "mimeType": {"wav": "audio/wav", "flac": "audio/flac", "mp3": "audio/mpeg"}[
                kind
            ],
            "container": kind.upper(),
            "codec": codec or "unknown",
            "channels": max(channels, 1),
            "sampleRateHz": max(sample_rate, 1),
            "durationMilliseconds": _duration_ms(payload, stream),
        }
        if bits:
            facts["bitsPerSample"] = bits
        return facts, _dedupe_issues(issues)

    def _probe_video(
        self, entry: ZipEntry, source: Path
    ) -> tuple[dict[str, Any], tuple[ContentIssue, ...]]:
        payload = self._ffprobe(source)
        streams = payload.get("streams", [])
        video = [stream for stream in streams if stream.get("codec_type") == "video"]
        audio = [stream for stream in streams if stream.get("codec_type") == "audio"]
        subtitle_count = sum(
            stream.get("codec_type") == "subtitle" for stream in streams
        )
        attachment_count = sum(
            stream.get("codec_type") == "attachment" for stream in streams
        )
        data_count = sum(stream.get("codec_type") == "data" for stream in streams)
        issues: list[ContentIssue] = []
        if (
            len(video) != 1
            or len(audio) > 1
            or subtitle_count
            or attachment_count
            or data_count
        ):
            issues.append(_entry_issue("VIDEO_STREAM_LAYOUT_UNSUPPORTED", entry))
        stream = video[0] if video else {}
        codec = str(stream.get("codec_name") or "")
        profile = str(stream.get("profile") or "")
        level_raw = _positive_int(stream.get("level"))
        level = (level_raw / 10) if level_raw else 0.0
        pix_fmt = str(stream.get("pix_fmt") or "")
        bits = _positive_int(stream.get("bits_per_raw_sample"))
        if (
            codec != "h264"
            or profile not in self.limits.allowed_h264_profiles
            or not 0 < level <= self.limits.max_h264_level
            or pix_fmt not in self.limits.allowed_video_pixel_formats
            or (bits is not None and bits != 8)
        ):
            issues.append(_entry_issue("VIDEO_CODEC_UNSUPPORTED", entry))
        width = _positive_int(stream.get("width")) or 0
        height = _positive_int(stream.get("height")) or 0
        if (
            width > self.limits.max_video_width
            or height > self.limits.max_video_height
            or not width
            or not height
        ):
            issues.append(_entry_issue("VIDEO_DIMENSION_LIMIT", entry))
        fps = _fraction(stream.get("avg_frame_rate") or stream.get("r_frame_rate"))
        if not 0 < fps <= self.limits.max_video_frames_per_second:
            issues.append(_entry_issue("VIDEO_FRAMERATE_LIMIT", entry))
        duration_ms = _duration_ms(payload, stream)
        if duration_ms > self.limits.max_video_duration_seconds * 1000:
            issues.append(_entry_issue("VIDEO_DURATION_LIMIT", entry))
        audio_stream = audio[0] if audio else {}
        if audio:
            audio_codec = str(audio_stream.get("codec_name") or "")
            audio_profile = str(audio_stream.get("profile") or "")
            audio_channels = _positive_int(audio_stream.get("channels")) or 0
            if (
                audio_codec != "aac"
                or audio_profile not in self.limits.allowed_aac_profiles
            ):
                issues.append(_entry_issue("VIDEO_AUDIO_CODEC_UNSUPPORTED", entry))
            if audio_channels < 1 or audio_channels > self.limits.max_audio_channels:
                issues.append(_entry_issue("AUDIO_CHANNEL_LIMIT", entry))
        facts: dict[str, Any] = {
            "category": "video",
            "mimeType": "video/mp4",
            "container": "MP4",
            "videoCodec": codec or "unknown",
            "videoStreamCount": len(video),
            "width": max(width, 1),
            "height": max(height, 1),
            "framesPerSecond": fps if fps > 0 else 0.001,
            "durationMilliseconds": duration_ms,
            "audioStreamCount": len(audio),
            "subtitleStreamCount": subtitle_count,
            "attachmentStreamCount": attachment_count,
        }
        if audio:
            facts["audioCodec"] = str(audio_stream.get("codec_name") or "unknown")
            facts["audioChannels"] = max(
                _positive_int(audio_stream.get("channels")) or 0, 1
            )
        return facts, _dedupe_issues(issues)

    def _probe_pdf(
        self, entry: ZipEntry, source: Path
    ) -> tuple[dict[str, Any], tuple[ContentIssue, ...]]:
        issues: list[ContentIssue] = []
        pdfinfo = self._run(["pdfinfo", str(source)], timeout=PDFINFO_TIMEOUT_SECONDS)
        info = _parse_pdfinfo(pdfinfo.stdout)
        if info.get("Encrypted", "no").lower() != "no":
            issues.append(_entry_issue("PDF_ENCRYPTED", entry))
        pages = _positive_int(info.get("Pages")) or 0
        if issues:
            return (
                {
                    "category": "document",
                    "mimeType": "application/pdf",
                    "format": "PDF",
                    **({"pageCount": pages} if pages else {}),
                },
                tuple(issues),
            )

        qpdf = self._run(
            ["qpdf", "--json", "--json-stream-data=none", str(source)],
            timeout=QPDF_TIMEOUT_SECONDS,
        )
        try:
            qpdf_payload = json.loads(qpdf.stdout)
        except json.JSONDecodeError:
            issues.append(_entry_issue("PARSER_FAILURE", entry))
            qpdf_payload = {}
        keys = _collect_pdf_keys(qpdf_payload)
        if keys & {"/JavaScript", "/JS", "/Launch", "/RichMedia"}:
            issues.append(_entry_issue("PDF_ACTIVE_CONTENT", entry))
        if keys & {"/EmbeddedFiles", "/Filespec", "/EF"}:
            issues.append(_entry_issue("PDF_ATTACHMENT_NOT_ALLOWED", entry))

        verapdf = self._run(
            [
                "verapdf",
                "--format",
                "xml",
                "--loglevel",
                "0",
                "--maxfailures",
                "100",
                "--maxfailuresdisplayed",
                "1",
                "--nonpdfext",
                str(source),
            ],
            timeout=VERAPDF_TIMEOUT_SECONDS,
            accepted_returncodes={0, 1},
        )
        part, conformance, compliant = _parse_verapdf(verapdf.stdout)
        if not compliant or part not in {1, 2} or conformance not in {"a", "b", "u"}:
            issues.append(_entry_issue("PDF_NOT_PDFA_1_OR_2", entry))
        facts: dict[str, Any] = {
            "category": "document",
            "mimeType": "application/pdf",
            "format": "PDF",
        }
        if pages:
            facts["pageCount"] = pages
        if part:
            facts["pdfaPart"] = part
        if conformance:
            facts["pdfaConformance"] = conformance
        return facts, _dedupe_issues(issues)

    def _probe_text(
        self, entry: ZipEntry, source: Path
    ) -> tuple[dict[str, Any], tuple[ContentIssue, ...]]:
        if source.stat().st_size > self.limits.max_text_bytes:
            return _unsupported("text/plain", "TEXT"), (
                _entry_issue("TEXT_SIZE_LIMIT", entry),
            )
        raw = source.read_bytes()
        stripped = raw.lstrip().lower()
        if (
            b"\x00" in raw
            or any(stripped.startswith(prefix) for prefix in STRUCTURED_TEXT_PREFIXES)
            or _looks_like_json(stripped)
            or _has_disallowed_controls(raw)
        ):
            return _unsupported("application/octet-stream", "STRUCTURED_TEXT"), (
                _entry_issue("UNSUPPORTED_MEDIA_TYPE", entry),
            )
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return _unsupported("text/plain", "TEXT"), (
                _entry_issue("TEXT_INVALID_UTF8", entry),
            )
        if _looks_like_xml(text) or _looks_like_csv(text) or _looks_like_script(text):
            return _unsupported("application/octet-stream", "STRUCTURED_TEXT"), (
                _entry_issue("UNSUPPORTED_MEDIA_TYPE", entry),
            )
        return (
            {
                "category": "document",
                "mimeType": "text/plain",
                "format": "TEXT",
                "charset": "US-ASCII" if raw.isascii() else "UTF-8",
            },
            (),
        )

    def _ffprobe(self, source: Path) -> dict[str, Any]:
        completed = self._run(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_streams",
                "-show_format",
                "-of",
                "json",
                str(source),
            ],
            timeout=FFPROBE_TIMEOUT_SECONDS,
        )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ValueError("ffprobe returned invalid JSON") from error
        if not isinstance(payload, dict) or not isinstance(
            payload.get("streams"), list
        ):
            raise ValueError("ffprobe returned no streams")
        return payload

    def _run(
        self,
        command: list[str],
        *,
        timeout: int,
        accepted_returncodes: set[int] = {0},
    ) -> subprocess.CompletedProcess[str]:
        if self.command_runner is subprocess.run:
            completed = _run_bounded_command(command, timeout=timeout)
        else:
            completed = self._run_injected(command, timeout=timeout)
        if completed.returncode not in accepted_returncodes:
            raise ValueError(f"Tool {command[0]} rejected the file.")
        if len(completed.stdout.encode("utf-8")) > MAX_TOOL_OUTPUT_BYTES:
            raise ValueError(f"Tool {command[0]} output exceeded its limit.")
        return completed

    def _run_injected(
        self, command: list[str], *, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        """Run an injected test adapter with the production call contract."""

        try:
            completed = self.command_runner(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                env=_tool_environment(),
            )
        except FileNotFoundError as error:
            raise ContentToolUnavailable(
                f"Required tool {command[0]} is missing."
            ) from error
        except subprocess.TimeoutExpired as error:
            raise ValueError(f"Tool {command[0]} exceeded its deadline.") from error
        return completed


def _detect_kind(header: bytes) -> str:
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff"
    if heif_variant := detect_heif_variant(header):
        return heif_variant[1].lower()
    if header.startswith(b"fLaC"):
        return "flac"
    if header.startswith(b"RIFF") and header[8:12] == b"WAVE":
        return "wav"
    if header.startswith(b"ID3") or (
        len(header) >= 2 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0
    ):
        return "mp3"
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "mp4"
    if b"%PDF-" in header[:1024]:
        return "pdf"
    if header.startswith(NESTED_ARCHIVE_SIGNATURES):
        return "nested-archive"
    if header.startswith((b"GIF8", b"BM", b"\x7fELF", b"MZ")) or (
        header.startswith(b"RIFF") and header[8:12] == b"WEBP"
    ):
        return "unsupported-binary"
    return "text-candidate"


def _is_packaging_artifact(path: str) -> bool:
    parts = path.split("/")
    return (
        "__MACOSX" in parts
        or parts[-1] in PACKAGING_NAMES
        or parts[-1].startswith("._")
    )


def _entry_issue(code: str, entry: ZipEntry, *, blocking: bool = True) -> ContentIssue:
    return ContentIssue(
        code,
        blocking=blocking,
        entry_index=entry.index,
        path=entry.normalized_path,
    )


def _unsupported(mime_type: str, format_name: str) -> dict[str, Any]:
    return {
        "category": "unsupported",
        "mimeType": mime_type,
        "format": format_name[:127],
    }


def _media_plan(entry: ZipEntry, facts: dict[str, Any]) -> dict[str, Any]:
    category = facts["category"]
    derivatives = {
        "image": "master.tif",
        "audio": "web.mp3",
        "video": "web.mp4",
        "document": "document.pdf" if facts.get("format") == "PDF" else "document.txt",
    }
    dcterms = {
        "image": "dcmitype:StillImage",
        "audio": "dcmitype:Sound",
        "video": "dcmitype:MovingImage",
        "document": "dcmitype:Text",
    }
    return {
        "kind": "media",
        "resourceClass": "shared:StagingMediaObject",
        "originalName": entry.normalized_name,
        "originalMimeType": facts["mimeType"],
        "dctermsType": dcterms[category],
        "protocol": "iiif" if category == "image" else "http",
        "derivativeName": derivatives[category],
    }


def _extension_issue(
    entry: ZipEntry, facts: dict[str, Any]
) -> tuple[ContentIssue, ...]:
    expected = {
        "image/jpeg": {".jpg", ".jpeg"},
        "image/tiff": {".tif", ".tiff"},
        "image/png": {".png"},
        "image/heic": {".heic", ".heif"},
        "image/heif": {".heic", ".heif"},
        "audio/wav": {".wav"},
        "audio/flac": {".flac"},
        "audio/mpeg": {".mp3"},
        "video/mp4": {".mp4"},
        "application/pdf": {".pdf"},
        "text/plain": {".txt", ".text"},
    }.get(facts.get("mimeType"))
    suffix = Path(entry.normalized_name).suffix.casefold()
    if expected is not None and suffix not in expected:
        return (_entry_issue("EXTENSION_CONTENT_MISMATCH", entry, blocking=False),)
    return ()


def _vips_metadata(image: Any, name: str) -> Any | None:
    """Read optional libvips metadata without treating absence as corruption."""

    try:
        if image.get_typeof(name):
            return image.get(name)
    except (AttributeError, TypeError):
        return None
    return None


def _positive_int(value: object) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _fraction(value: object) -> float:
    try:
        result = float(Fraction(str(value)))
    except (ValueError, ZeroDivisionError):
        return 0.0
    return result if math.isfinite(result) else 0.0


def _duration_ms(payload: dict[str, Any], stream: dict[str, Any]) -> int:
    raw = stream.get("duration") or payload.get("format", {}).get("duration") or 0
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, round(value * 1000)) if math.isfinite(value) else 0


def _parse_pdfinfo(value: str) -> dict[str, str]:
    return {
        key.strip(): item.strip()
        for line in value.splitlines()
        if ":" in line
        for key, item in [line.split(":", 1)]
    }


def _collect_pdf_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.startswith("/"):
                keys.add(key)
            keys.update(_collect_pdf_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.update(_collect_pdf_keys(item))
    elif isinstance(value, str) and value.startswith("/"):
        keys.add(value)
    return keys


def _parse_verapdf(value: str) -> tuple[int | None, str | None, bool]:
    try:
        root = ET.fromstring(value)
    except ET.ParseError:
        return None, None, False
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "validationReport":
            continue
        description = " ".join(
            str(element.attrib.get(key, ""))
            for key in ("profileName", "statement", "flavour")
        )
        match = PDFA_RE.search(description)
        compliant = str(element.attrib.get("isCompliant", "false")).lower() == "true"
        if match:
            return int(match.group(1)), match.group(2).lower(), compliant
    return None, None, False


def _looks_like_json(value: bytes) -> bool:
    if not value.startswith((b"{", b"[")):
        return False
    try:
        json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return True


def _looks_like_xml(value: str) -> bool:
    """Recognize well-formed XML even when it has no XML declaration."""

    stripped = value.lstrip()
    if not stripped.startswith("<"):
        return False
    try:
        ET.fromstring(stripped)
    except ET.ParseError:
        return False
    return True


def _looks_like_csv(value: str) -> bool:
    """Conservatively recognize repeated delimited records as structured data."""

    lines = [line for line in value.splitlines() if line.strip()][:50]
    if len(lines) < 2:
        return False
    for delimiter in ("\t", ";", ","):
        counts = [line.count(delimiter) for line in lines]
        if counts[0] >= 1 and len(set(counts)) == 1:
            return True
    return False


def _looks_like_script(value: str) -> bool:
    """Detect strong Python or shell syntax without rejecting ordinary notes."""

    python_signals = (
        r"^\s*(?:from\s+[\w.]+\s+import|import\s+[\w.]+)",
        r"^\s*(?:async\s+)?def\s+\w+\s*\(",
        r"^\s*class\s+\w+(?:\s*\([^)]*\))?\s*:",
        r"^\s*if\s+__name__\s*==",
    )
    shell_signals = (
        r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=\$\(",
        r"^\s*(?:if|while)\s+\[",
        r"^\s*for\s+\w+\s+in\s+",
        r"^\s*(?:set\s+-[a-zA-Z]+|case\s+.+\s+in)\s*$",
    )
    return any(
        re.search(pattern, value, re.MULTILINE) for pattern in python_signals
    ) or (
        sum(bool(re.search(pattern, value, re.MULTILINE)) for pattern in shell_signals)
        >= 2
    )


def _has_disallowed_controls(value: bytes) -> bool:
    return any(byte < 32 and byte not in {9, 10, 12, 13} for byte in value)


def _run_bounded_command(
    command: list[str], *, timeout: int
) -> subprocess.CompletedProcess[str]:
    """Run a parser with hard regular-file limits on stdout and stderr.

    Pipes can grow application memory before a post-run size check. Redirecting
    both streams to temporary files and applying ``RLIMIT_FSIZE`` through
    ``prlimit`` makes hostile parser output fail at the kernel boundary instead.
    """

    wrapped = [
        "prlimit",
        f"--fsize={MAX_TOOL_OUTPUT_BYTES}:{MAX_TOOL_OUTPUT_BYTES}",
        "--nofile=256:256",
        "--",
        *command,
    ]
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            completed = subprocess.run(
                wrapped,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=timeout,
                env=_tool_environment(),
                check=False,
            )
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_TOOL_OUTPUT_BYTES + 1).decode(
                "utf-8", errors="replace"
            )
            stderr = stderr_file.read(MAX_TOOL_OUTPUT_BYTES + 1).decode(
                "utf-8", errors="replace"
            )
    except FileNotFoundError as error:
        raise ContentToolUnavailable(
            f"Required tool {command[0]} or prlimit is missing."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"Tool {command[0]} exceeded its deadline.") from error
    if (
        len(stdout.encode("utf-8")) > MAX_TOOL_OUTPUT_BYTES
        or len(stderr.encode("utf-8")) > MAX_TOOL_OUTPUT_BYTES
    ):
        raise ValueError(f"Tool {command[0]} output exceeded its limit.")
    return subprocess.CompletedProcess(command, completed.returncode, stdout, stderr)


def _tool_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/tmp",
        "JAVA_TOOL_OPTIONS": "-Xms64m -Xmx1024m -XX:ActiveProcessorCount=2",
    }


def _dedupe_issues(issues: list[ContentIssue]) -> tuple[ContentIssue, ...]:
    return tuple(dict.fromkeys(issues))
