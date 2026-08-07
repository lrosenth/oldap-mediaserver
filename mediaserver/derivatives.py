"""Reusable derivative generation independent of Flask request handling.

The processor consumes a stored work-file plus a typed media classification and
returns the exact files it created. HTTP handlers and future batch workers can
therefore share conversion behavior without importing Flask globals.
"""

from __future__ import annotations

import logging
import importlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pdf2image import convert_from_path
from pdf2image.exceptions import (
    PDFInfoNotInstalledError,
    PDFPageCountError,
    PDFPopplerTimeoutError,
    PDFSyntaxError,
)
from PIL import Image, ImageOps

from media import (
    InvalidPdfError,
    MediaType,
    UploadClassification,
    probe_first_audio_stream,
)


DOCUMENT_DERIVATIVE_NAME = "document.pdf"
THUMBNAIL_SIZES = (128, 256)
PDF_RENDER_SIZE = 512
PDF_RENDER_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class DerivativeResult:
    """Paths created for delivery from one original media bitstream."""

    primary: Path
    thumbnails: tuple[Path, ...] = ()


class DerivativeProcessor:
    """Create current media derivatives using bounded native tools.

    Dependencies are assignable callables to make native-tool behavior directly
    testable. Production uses subprocess, libvips, and Poppler defaults.
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.command_runner: Callable[..., subprocess.CompletedProcess[str]] = (
            subprocess.run
        )
        # Resolve libvips lazily so non-image routes and lightweight tests do
        # not require an initialized native image loader at construction time.
        self.vips_loader: Callable[..., object] | None = None
        self.pdf_renderer = convert_from_path

    def generate(
        self,
        source: Path,
        derived_directory: Path,
        classification: UploadClassification,
    ) -> DerivativeResult:
        """Generate the canonical derivative set for one classified upload."""

        media_type = classification.media_type
        if media_type is MediaType.IMAGE:
            primary = derived_directory / "master.tif"
            self._create_pyramidal_tiff(source, primary)
            return DerivativeResult(primary=primary)

        if media_type is MediaType.VIDEO:
            primary = derived_directory / "web.mp4"
            thumbnails = self._thumbnail_paths(derived_directory)
            self._create_mp4(source, primary)
            for thumbnail in thumbnails:
                self._create_video_thumbnail(
                    source, thumbnail, self._thumbnail_size(thumbnail)
                )
            return DerivativeResult(primary=primary, thumbnails=thumbnails)

        if media_type is MediaType.AUDIO:
            probe_first_audio_stream(source, command_runner=self.command_runner)
            if classification.target_format == "mp3":
                primary = derived_directory / "web.mp3"
                self._create_mp3(source, primary)
            else:
                primary = derived_directory / "web.m4a"
                self._create_m4a(source, primary)
            return DerivativeResult(primary=primary)

        if media_type is MediaType.DOCUMENT:
            if classification.target_format == "txt":
                primary = derived_directory / "document.txt"
                shutil.copy2(source, primary)
                return DerivativeResult(primary=primary)
            primary = derived_directory / DOCUMENT_DERIVATIVE_NAME
            thumbnails = self._thumbnail_paths(derived_directory)
            shutil.copy2(source, primary)
            self._create_pdf_thumbnails(
                source,
                {self._thumbnail_size(path): path for path in thumbnails},
            )
            return DerivativeResult(primary=primary, thumbnails=thumbnails)

        raise ValueError(f"Unsupported media type: {media_type.value}")

    def _create_pyramidal_tiff(self, source: Path, destination: Path) -> None:
        if self.vips_loader is not None:
            loader = self.vips_loader
        else:
            pyvips = importlib.import_module("pyvips")
            loader = pyvips.Image.new_from_file
        image = loader(str(source), access="sequential")
        image.tiffsave(
            str(destination),
            tile=True,
            pyramid=True,
            compression="none",
            tile_width=256,
            tile_height=256,
            bigtiff=True,
        )

    def _create_mp4(self, source: Path, destination: Path) -> None:
        self._run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(source),
                "-c:v",
                "libx264",
                "-preset",
                "medium",
                "-crf",
                "22",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                "-b:a",
                "128k",
                "-ac",
                "2",
                "-movflags",
                "+faststart",
                str(destination),
            ],
            "ffmpeg mp4",
        )

    def _create_mp3(self, source: Path, destination: Path) -> None:
        self._run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(source),
                "-map",
                "0:a:0",
                "-vn",
                "-c:a",
                "libmp3lame",
                "-q:a",
                "2",
                str(destination),
            ],
            "ffmpeg mp3",
        )

    def _create_m4a(self, source: Path, destination: Path) -> None:
        self._run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(source),
                "-map",
                "0:a:0",
                "-vn",
                "-c:a",
                "aac",
                "-b:a",
                "128k",
                "-movflags",
                "+faststart",
                str(destination),
            ],
            "ffmpeg m4a",
        )

    def _create_video_thumbnail(
        self, source: Path, destination: Path, size: int
    ) -> None:
        scale_pad = (
            "thumbnail,"
            f"scale={size}:{size}:force_original_aspect_ratio=decrease,"
            f"pad={size}:{size}:(ow-iw)/2:(oh-ih)/2"
        )
        self._run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(source),
                "-vf",
                scale_pad,
                "-frames:v",
                "1",
                str(destination),
            ],
            f"ffmpeg thumbnail {size}",
        )

    def _create_pdf_thumbnails(
        self, source: Path, destinations: dict[int, Path]
    ) -> None:
        try:
            pages = self.pdf_renderer(
                source,
                first_page=1,
                last_page=1,
                fmt="png",
                size=PDF_RENDER_SIZE,
                single_file=True,
                thread_count=1,
                timeout=PDF_RENDER_TIMEOUT_SECONDS,
                strict=True,
            )
        except PDFInfoNotInstalledError as exc:
            raise RuntimeError("Poppler PDF rendering tools are not installed") from exc
        except (PDFPageCountError, PDFPopplerTimeoutError, PDFSyntaxError) as exc:
            raise InvalidPdfError(
                f"Could not render the first PDF page: {exc}"
            ) from exc

        if not pages:
            raise InvalidPdfError(
                "Uploaded PDF does not contain a renderable first page"
            )

        page = None
        try:
            page = pages[0].convert("RGB")
            for size, destination in destinations.items():
                thumbnail = ImageOps.contain(
                    page,
                    (size, size),
                    method=Image.Resampling.LANCZOS,
                )
                canvas = Image.new("RGB", (size, size), "white")
                try:
                    offset = (
                        (size - thumbnail.width) // 2,
                        (size - thumbnail.height) // 2,
                    )
                    canvas.paste(thumbnail, offset)
                    canvas.save(destination, format="JPEG", quality=85, optimize=True)
                finally:
                    thumbnail.close()
                    canvas.close()
        finally:
            if page is not None:
                page.close()
            for rendered_page in pages:
                rendered_page.close()

    def _run(self, command: list[str], label: str) -> None:
        self.logger.debug("Running %s: %s", label, " ".join(command))
        completed = self.command_runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"{label} failed (exit {completed.returncode}): {completed.stderr}"
            )

    @staticmethod
    def _thumbnail_paths(derived_directory: Path) -> tuple[Path, ...]:
        return tuple(derived_directory / f"thumb{size}.jpg" for size in THUMBNAIL_SIZES)

    @staticmethod
    def _thumbnail_size(path: Path) -> int:
        return int(path.stem.removeprefix("thumb"))
