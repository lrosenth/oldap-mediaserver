"""Content-signature, codec-matrix, PDF/A, and text validation tests."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from PIL import Image

MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from config import ZipImportLimits  # noqa: E402
import content_validation  # noqa: E402
from content_validation import CONTENT_ISSUE_CODES, ContentValidator  # noqa: E402
from zip_validation import ZipStructureValidator  # noqa: E402


def _extracted(tmp_path: Path, entries: list[tuple[str, bytes]]):
    tmp_path.mkdir(parents=True, exist_ok=True)
    sip = tmp_path / "sip.zip"
    with zipfile.ZipFile(sip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return ZipStructureValidator().validate_and_extract(sip, tmp_path / "extracted")


def _codes(result) -> set[str]:
    return {
        issue.code
        for issue in result.issues
        + tuple(issue for entry in result.entries for issue in entry.issues)
    }


def _png(width: int = 20, height: int = 10) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), "red").save(buffer, format="PNG")
    return buffer.getvalue()


def test_content_issue_codes_are_frozen_by_the_v1_contract() -> None:
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "zip-import"
            / "v1"
            / "common.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert CONTENT_ISSUE_CODES <= set(schema["$defs"]["IssueCode"]["enum"])


def test_image_is_detected_from_content_and_extension_mismatch_is_warning(
    tmp_path: Path,
) -> None:
    structural = _extracted(tmp_path, [("picture.bin", _png())])

    result = ContentValidator().validate(structural)

    assert result.accepted
    entry = result.entries[0]
    assert entry.detected_content == {
        "category": "image",
        "mimeType": "image/png",
        "format": "PNG",
        "width": 20,
        "height": 10,
        "pageCount": 1,
    }
    assert entry.planned_resource["protocol"] == "iiif"
    assert _codes(result) == {"EXTENSION_CONTENT_MISMATCH"}


def test_image_limits_and_unsupported_binary_are_blocking(tmp_path: Path) -> None:
    structural = _extracted(
        tmp_path,
        [("large.png", _png(20, 20)), ("animation.gif", b"GIF89a" + b"x" * 20)],
    )
    limits = replace(ZipImportLimits(), max_image_pixels=100, max_image_axis_pixels=15)

    result = ContentValidator(limits).validate(structural)

    assert not result.accepted
    assert {
        "IMAGE_PIXEL_LIMIT",
        "IMAGE_AXIS_LIMIT",
        "UNSUPPORTED_MEDIA_TYPE",
    } <= _codes(result)
    assert all(entry.disposition == "REJECT" for entry in result.entries)


def test_plain_utf8_packaging_artifacts_and_structured_text(tmp_path: Path) -> None:
    structural = _extracted(
        tmp_path,
        [
            ("notes.txt", "Grüesse\n".encode()),
            (".DS_Store", b"ignored"),
            ("data.txt", b'{"not": "plain text"}'),
            ("archive.docx", b"PK\x03\x04nested"),
        ],
    )

    result = ContentValidator().validate(structural)

    assert not result.accepted
    assert result.entries[0].detected_content["charset"] == "UTF-8"
    assert result.entries[1].disposition == "IGNORE"
    assert {
        "PACKAGING_ARTIFACT_IGNORED",
        "UNSUPPORTED_MEDIA_TYPE",
        "NESTED_ARCHIVE_NOT_ALLOWED",
    } <= _codes(result)


def test_xml_csv_and_python_are_not_accepted_as_plain_text(tmp_path: Path) -> None:
    structural = _extracted(
        tmp_path,
        [
            ("document.txt", "<root><value>1</value></root>".encode()),
            ("table.txt", b"name,year\nBMG,1911\nGB,1922\n"),
            ("program.txt", b"import pathlib\nprint(pathlib.Path.cwd())\n"),
        ],
    )

    result = ContentValidator().validate(structural)

    assert not result.accepted
    assert all(entry.disposition == "REJECT" for entry in result.entries)
    assert _codes(result) == {"NO_IMPORTABLE_CONTENT", "UNSUPPORTED_MEDIA_TYPE"}


@pytest.mark.skipif(shutil.which("prlimit") is None, reason="Linux worker runtime only")
def test_production_tool_output_is_kernel_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(content_validation, "MAX_TOOL_OUTPUT_BYTES", 1024)

    with pytest.raises(ValueError, match="rejected|output exceeded"):
        ContentValidator()._run([sys.executable, "-c", "print('x' * 4096)"], timeout=10)


class MediaRunner:
    """Return deterministic ffprobe/qpdf/veraPDF evidence by command name."""

    def __init__(self, ffprobe_payload=None, *, active_pdf: bool = False):
        self.ffprobe_payload = ffprobe_payload
        self.active_pdf = active_pdf
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append((command, kwargs))
        if command[0] == "ffprobe":
            stdout = json.dumps(self.ffprobe_payload)
        elif command[0] == "pdfinfo":
            stdout = "Pages: 2\nEncrypted: no\n"
        elif command[0] == "qpdf":
            stdout = json.dumps(
                {"objects": {"1 0 R": {"value": {"/JavaScript": {}}}}}
                if self.active_pdf
                else {"objects": {}}
            )
        elif command[0] == "verapdf":
            stdout = (
                '<report><validationReport profileName="PDF/A-2B validation profile" '
                'isCompliant="true"/></report>'
            )
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout, "")


def test_wav_pcm_and_mp4_h264_aac_matrix(tmp_path: Path) -> None:
    wav = _extracted(tmp_path / "audio", [("sound.wav", b"RIFFxxxxWAVE" + b"x" * 20)])
    audio_runner = MediaRunner(
        {
            "streams": [
                {
                    "codec_type": "audio",
                    "codec_name": "pcm_s24le",
                    "channels": 2,
                    "sample_rate": "48000",
                    "bits_per_sample": 24,
                    "duration": "1.5",
                }
            ],
            "format": {"duration": "1.5"},
        }
    )
    audio_result = ContentValidator(command_runner=audio_runner).validate(wav)
    assert audio_result.accepted
    assert audio_result.entries[0].detected_content["bitsPerSample"] == 24

    mp4_header = b"\x00\x00\x00\x18ftypisom" + b"x" * 32
    video = _extracted(tmp_path / "video", [("movie.mp4", mp4_header)])
    video_runner = MediaRunner(
        {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "h264",
                    "profile": "High",
                    "level": 52,
                    "pix_fmt": "yuv420p",
                    "width": 3840,
                    "height": 2160,
                    "avg_frame_rate": "60/1",
                    "duration": "7200",
                },
                {
                    "codec_type": "audio",
                    "codec_name": "aac",
                    "profile": "LC",
                    "channels": 2,
                },
            ],
            "format": {"duration": "7200"},
        }
    )
    video_result = ContentValidator(command_runner=video_runner).validate(video)
    assert video_result.accepted
    assert video_result.entries[0].detected_content["framesPerSecond"] == 60


def test_video_codec_violation_and_pdf_active_content(tmp_path: Path) -> None:
    video = _extracted(
        tmp_path / "video", [("movie.mp4", b"\x00\x00\x00\x18ftypisom" + b"x" * 32)]
    )
    runner = MediaRunner(
        {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "hevc",
                    "profile": "Main",
                    "level": 60,
                    "pix_fmt": "yuv420p10le",
                    "width": 1920,
                    "height": 1080,
                    "avg_frame_rate": "25/1",
                }
            ],
            "format": {"duration": "10"},
        }
    )
    assert "VIDEO_CODEC_UNSUPPORTED" in _codes(
        ContentValidator(command_runner=runner).validate(video)
    )

    pdf = _extracted(tmp_path / "pdf", [("record.pdf", b"%PDF-1.7\nbody\n%%EOF")])
    pdf_result = ContentValidator(command_runner=MediaRunner(active_pdf=True)).validate(
        pdf
    )
    assert "PDF_ACTIVE_CONTENT" in _codes(pdf_result)
    assert pdf_result.entries[0].detected_content["pdfaPart"] == 2
    assert pdf_result.entries[0].detected_content["pdfaConformance"] == "b"
