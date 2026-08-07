"""Typed media classification and lightweight content probes.

Legacy single-file upload classification intentionally preserves its existing
MIME/filename behavior. The resulting :class:`UploadClassification` is a routing
hint, not trusted proof of content. Content-derived facts such as audio stream
metadata and basic PDF structure are represented separately so future ZIP
validation cannot confuse client claims with parser evidence.
"""

from __future__ import annotations

import json
import mimetypes
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable


PDF_MIME_TYPE = "application/pdf"


class InvalidPdfError(ValueError):
    """Raised when a PDF fails the bounded structural upload probe."""


class MediaProbeError(RuntimeError):
    """Raised when an external media probe fails or returns invalid evidence."""


class MediaType(str, Enum):
    """Logical storage and delivery family used by the mediahelper."""

    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    DOCUMENT = "document"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class UploadClassification:
    """Routing metadata for the backward-compatible single-file upload.

    This classification is derived from request metadata and filename hints. It
    selects the existing processing route but must not be treated as a secure
    MIME determination by ZIP validation.
    """

    media_type: MediaType
    target_format: str
    original_mime_type: str
    dcterms_type: str
    protocol: str


@dataclass(frozen=True, slots=True)
class AudioStreamProbe:
    """Content-derived facts for the first readable audio stream."""

    index: int
    codec_name: str | None
    channels: int | None
    sample_rate_hz: int | None
    sample_format: str | None
    bits_per_sample: int | None


@dataclass(frozen=True, slots=True)
class PdfStructureProbe:
    """Bounded structural facts established before invoking Poppler."""

    size_bytes: int
    header_found: bool
    eof_found: bool


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def detect_upload_media_type(
    filename: str, declared_mime_type: str | None
) -> MediaType:
    """Classify a legacy upload from declared MIME and filename hints."""

    declared = (declared_mime_type or "").lower()
    detected = _media_type_from_mime(declared)
    if detected is not MediaType.OTHER:
        return detected

    guessed, _ = mimetypes.guess_type(filename or "")
    return _media_type_from_mime((guessed or "").lower())


def _media_type_from_mime(mime_type: str) -> MediaType:
    """Map one normalized MIME string to the mediahelper storage family."""

    if mime_type.startswith("image/"):
        return MediaType.IMAGE
    if mime_type.startswith("audio/"):
        return MediaType.AUDIO
    if mime_type.startswith("video/"):
        return MediaType.VIDEO
    if mime_type == PDF_MIME_TYPE:
        return MediaType.DOCUMENT
    return MediaType.OTHER


def validate_target_format(media_type: MediaType, raw: str | None) -> str:
    """Validate and normalize the existing derivative target contract."""

    requested = (raw or "").lower().strip()
    allowed_and_default = {
        MediaType.IMAGE: ({"tiff"}, "tiff"),
        MediaType.VIDEO: ({"mp4"}, "mp4"),
        MediaType.AUDIO: ({"m4a", "mp3"}, "mp3"),
        MediaType.DOCUMENT: ({"pdf"}, "pdf"),
    }
    try:
        allowed, default = allowed_and_default[media_type]
    except KeyError as exc:
        raise ValueError(f"Unsupported media type: {media_type}") from exc

    normalized = requested or default
    if normalized not in allowed:
        raise ValueError(
            f"Invalid targetFormat '{normalized}' (allowed: {sorted(allowed)})"
        )
    return normalized


def classify_upload(
    filename: str,
    declared_mime_type: str | None,
    requested_target_format: str | None,
) -> UploadClassification:
    """Build the typed routing contract for one legacy upload request."""

    media_type = detect_upload_media_type(filename, declared_mime_type)
    target_format = validate_target_format(media_type, requested_target_format)
    original_mime_type = (
        PDF_MIME_TYPE
        if media_type is MediaType.DOCUMENT
        else declared_mime_type or "application/octet-stream"
    )
    dcterms_types = {
        MediaType.IMAGE: "dcmitype:StillImage",
        MediaType.AUDIO: "dcmitype:Sound",
        MediaType.VIDEO: "dcmitype:MovingImage",
        MediaType.DOCUMENT: "dcmitype:Text",
    }
    protocols = {
        MediaType.IMAGE: "iiif",
        MediaType.AUDIO: "http",
        MediaType.VIDEO: "http",
        MediaType.DOCUMENT: "http",
    }
    return UploadClassification(
        media_type=media_type,
        target_format=target_format,
        original_mime_type=original_mime_type,
        dcterms_type=dcterms_types.get(media_type, "dcmitype:Dataset"),
        protocol=protocols.get(media_type, "custom"),
    )


def probe_pdf_structure(source: Path) -> PdfStructureProbe:
    """Perform the existing bounded PDF header/EOF validation.

    This probe is intentionally not PDF/A validation. Phase 4 will apply
    veraPDF and active-content checks for ZIP imports.
    """

    try:
        with source.open("rb") as handle:
            header = handle.read(1024)
            handle.seek(0, os.SEEK_END)
            size_bytes = handle.tell()
            handle.seek(max(size_bytes - 4096, 0), os.SEEK_SET)
            tail = handle.read()
    except OSError as exc:
        raise InvalidPdfError(f"Could not read uploaded PDF: {exc}") from exc

    result = PdfStructureProbe(
        size_bytes=size_bytes,
        header_found=b"%PDF-" in header,
        eof_found=b"%%EOF" in tail,
    )
    if not result.header_found:
        raise InvalidPdfError("Uploaded document is not a PDF file")
    if not result.eof_found:
        raise InvalidPdfError("Uploaded PDF is incomplete or malformed")
    return result


def probe_first_audio_stream(
    source: Path,
    *,
    command_runner: CommandRunner = subprocess.run,
) -> AudioStreamProbe:
    """Return typed ffprobe facts for the first readable audio stream.

    Args:
        source: Untrusted media bitstream in isolated work storage.
        command_runner: Injectable subprocess runner used by tests.

    Raises:
        MediaProbeError: If ffprobe is unavailable, fails, emits invalid JSON,
            or finds no readable audio stream.
    """

    command = [
        "ffprobe",
        "-v",
        "error",
        "-select_streams",
        "a:0",
        "-show_entries",
        (
            "stream=index,codec_name,codec_type,channels,sample_rate,"
            "sample_fmt,bits_per_raw_sample,bits_per_sample"
        ),
        "-of",
        "json",
        str(source),
    ]
    try:
        completed = command_runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise MediaProbeError(
            "ffprobe is required for audio validation but was not found"
        ) from exc

    if completed.returncode != 0:
        raise MediaProbeError(
            f"ffprobe audio validation failed (exit {completed.returncode}): "
            f"{completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout)
        streams = payload.get("streams", [])
        stream = streams[0]
    except (json.JSONDecodeError, AttributeError, IndexError, TypeError) as exc:
        raise MediaProbeError(
            "Uploaded audio file does not contain a readable audio stream"
        ) from exc
    if stream.get("codec_type") != "audio":
        raise MediaProbeError(
            "Uploaded audio file does not contain a readable audio stream"
        )

    return AudioStreamProbe(
        index=_optional_int(stream.get("index")) or 0,
        codec_name=_optional_string(stream.get("codec_name")),
        channels=_optional_int(stream.get("channels")),
        sample_rate_hz=_optional_int(stream.get("sample_rate")),
        sample_format=_optional_string(stream.get("sample_fmt")),
        bits_per_sample=(
            _optional_int(stream.get("bits_per_raw_sample"))
            or _optional_int(stream.get("bits_per_sample"))
        ),
    )


def _optional_int(value: object) -> int | None:
    """Normalize an optional ffprobe scalar integer."""

    if value in (None, "", "N/A"):
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def _optional_string(value: object) -> str | None:
    """Normalize an optional ffprobe string."""

    if value in (None, "", "N/A"):
        return None
    return str(value)
