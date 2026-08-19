"""Tests for typed upload classification and content-derived media probes."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from media import (  # noqa: E402
    InvalidPdfError,
    MediaProbeError,
    MediaType,
    classify_upload,
    detect_heif_variant,
    probe_first_audio_stream,
    probe_pdf_structure,
)


def _ftyp(major: bytes, *compatible: bytes) -> bytes:
    """Build a minimal ISO BMFF file-type box for classification tests."""

    size = 16 + 4 * len(compatible)
    return (
        size.to_bytes(4, "big")
        + b"ftyp"
        + major
        + b"\x00\x00\x00\x00"
        + b"".join(compatible)
    )


def test_upload_classification_is_explicitly_hint_based() -> None:
    """Legacy MIME and extension routing is preserved in a typed result."""

    by_mime = classify_upload("misleading.bin", "audio/flac", None)
    by_name = classify_upload("scan.pdf", "application/octet-stream", None)

    assert by_mime.media_type is MediaType.AUDIO
    assert by_mime.target_format == "mp3"
    assert by_mime.original_mime_type == "audio/flac"
    assert by_mime.dcterms_type == "dcmitype:Sound"
    assert by_mime.protocol == "http"
    assert by_name.media_type is MediaType.DOCUMENT
    assert by_name.original_mime_type == "application/pdf"


def test_heif_upload_hints_and_content_brands_are_normalized() -> None:
    """HEIF extensions work without a browser MIME while AVIF stays separate."""

    heic = classify_upload("IMG_0001.HEIC", "application/octet-stream", None)
    heif = classify_upload("scan.heif", "", None)

    assert heic.media_type is MediaType.IMAGE
    assert heic.original_mime_type == "image/heic"
    assert heif.original_mime_type == "image/heif"
    assert detect_heif_variant(_ftyp(b"heic", b"mif1")) == (
        "image/heic",
        "HEIC",
    )
    assert detect_heif_variant(_ftyp(b"mif1")) == ("image/heif", "HEIF")
    assert detect_heif_variant(_ftyp(b"avif", b"mif1")) is None


def test_audio_probe_returns_typed_content_facts(tmp_path: Path) -> None:
    """ffprobe JSON is normalized into stable optional scalar fields."""

    source = tmp_path / "audio.flac"
    source.write_bytes(b"fixture")
    payload = {
        "streams": [
            {
                "index": 2,
                "codec_name": "flac",
                "codec_type": "audio",
                "channels": 2,
                "sample_rate": "96000",
                "sample_fmt": "s32",
                "bits_per_raw_sample": "24",
            }
        ]
    }

    def successful_probe(command, **kwargs):
        assert command[0] == "ffprobe"
        assert command[-1] == str(source)
        assert kwargs["text"] is True
        return types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    result = probe_first_audio_stream(source, command_runner=successful_probe)

    assert result.index == 2
    assert result.codec_name == "flac"
    assert result.channels == 2
    assert result.sample_rate_hz == 96_000
    assert result.sample_format == "s32"
    assert result.bits_per_sample == 24


def test_audio_probe_rejects_missing_or_malformed_stream_evidence(
    tmp_path: Path,
) -> None:
    """Successful process exit without valid audio evidence is still rejected."""

    source = tmp_path / "not-audio.bin"
    source.write_bytes(b"fixture")

    with pytest.raises(MediaProbeError, match="readable audio stream"):
        probe_first_audio_stream(
            source,
            command_runner=lambda *args, **kwargs: types.SimpleNamespace(
                returncode=0,
                stdout="not-json",
                stderr="",
            ),
        )


def test_pdf_structure_probe_returns_facts_and_rejects_incomplete_file(
    tmp_path: Path,
) -> None:
    """The bounded PDF gate is reusable without Flask or derivative creation."""

    valid = tmp_path / "valid.pdf"
    valid.write_bytes(b"prefix%PDF-1.7\ncontent\n%%EOF\n")
    incomplete = tmp_path / "incomplete.pdf"
    incomplete.write_bytes(b"%PDF-1.7\ncontent")

    result = probe_pdf_structure(valid)

    assert result.size_bytes == valid.stat().st_size
    assert result.header_found is True
    assert result.eof_found is True
    with pytest.raises(InvalidPdfError, match="incomplete"):
        probe_pdf_structure(incomplete)
