"""Tests for Flask-independent derivative orchestration."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from derivatives import DerivativeProcessor  # noqa: E402
from media import MediaType, UploadClassification, classify_upload  # noqa: E402


def test_audio_derivative_uses_typed_probe_before_conversion(tmp_path: Path) -> None:
    """Audio generation probes content and returns its canonical output path."""

    source = tmp_path / "source.wav"
    source.write_bytes(b"audio")
    derived = tmp_path / "derived"
    derived.mkdir()
    commands: list[list[str]] = []

    def command_runner(command, **kwargs):
        commands.append(command)
        if command[0] == "ffprobe":
            return types.SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "streams": [
                            {
                                "index": 0,
                                "codec_name": "pcm_s16le",
                                "codec_type": "audio",
                                "channels": 1,
                                "sample_rate": "48000",
                                "bits_per_sample": 16,
                            }
                        ]
                    }
                ),
                stderr="",
            )
        Path(command[-1]).write_bytes(b"mp3 derivative")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    processor = DerivativeProcessor()
    processor.command_runner = command_runner

    result = processor.generate(
        source,
        derived,
        classify_upload("source.wav", "audio/wav", "mp3"),
    )

    assert [command[0] for command in commands] == ["ffprobe", "ffmpeg"]
    assert result.primary == derived / "web.mp3"
    assert result.primary.read_bytes() == b"mp3 derivative"
    assert result.thumbnails == ()


def test_video_derivative_reports_primary_and_bounded_thumbnails(
    tmp_path: Path,
) -> None:
    """Video orchestration returns every generated delivery artifact."""

    source = tmp_path / "source.mov"
    source.write_bytes(b"video")
    derived = tmp_path / "derived"
    derived.mkdir()

    def command_runner(command, **kwargs):
        Path(command[-1]).write_bytes(b"generated")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    processor = DerivativeProcessor()
    processor.command_runner = command_runner

    result = processor.generate(
        source,
        derived,
        classify_upload("source.mov", "video/quicktime", None),
    )

    assert result.primary == derived / "web.mp4"
    assert tuple(path.name for path in result.thumbnails) == (
        "thumb128.jpg",
        "thumb256.jpg",
    )
    assert all(path.read_bytes() == b"generated" for path in result.thumbnails)


def test_validated_text_is_copied_as_the_canonical_document_derivative(
    tmp_path: Path,
) -> None:
    """ZIP-import UTF-8 text bypasses PDF tooling and remains bit-identical."""

    source = tmp_path / "notiz.txt"
    source.write_text("Grüezi Fasnacht\n", encoding="utf-8")
    derived = tmp_path / "derived"
    derived.mkdir()

    result = DerivativeProcessor().generate(
        source,
        derived,
        UploadClassification(
            media_type=MediaType.DOCUMENT,
            target_format="txt",
            original_mime_type="text/plain",
            dcterms_type="dcmitype:Text",
            protocol="http",
        ),
    )

    assert result.primary == derived / "document.txt"
    assert result.primary.read_bytes() == source.read_bytes()
    assert result.thumbnails == ()
