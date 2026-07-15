import json
import os
import shutil
import subprocess
import mimetypes
import re
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests
from flask import Flask, request, jsonify, abort, logging

import pyvips  # make sure this is in requirements.txt
from flask_cors import CORS
from nanoid import generate
from pdf2image import convert_from_path
from pdf2image.exceptions import (
    PDFInfoNotInstalledError,
    PDFPageCountError,
    PDFPopplerTimeoutError,
    PDFSyntaxError,
)
from PIL import Image, ImageOps
from oldaplib.src.authentication import AuthorizationContext, TokenCodec
from oldaplib.src.enums.adminpermissions import AdminPermission
from oldaplib.src.enums.datapermissions import DataPermission
from oldaplib.src.helpers.oldaperror import OldapError, OldapErrorConfiguration
from oldaplib.src.xsd.iri import Iri
from oldaplib.src.xsd.xsd_qname import Xsd_QName

from oldap_client import OldapClient

imgdir  = os.environ.get("UPLOADER_IMGDIR", "/data/images").strip()
# For local dev, Cantaloupe is usually on host:8182
# In production, put your real hostname here
iiif_base_url = os.environ.get("IIIF_BASE_URL", "http://localhost:8088/iiif/3/").strip()

# Base URL for non-IIIF delivery (Caddy). Should end with a trailing slash.
media_base_url = os.environ.get("MEDIA_BASE_URL", "http://localhost:8088/").strip()
if not media_base_url.endswith('/'):
    media_base_url += '/'

oldap_api_url = os.environ.get("OLDAP_API_URL", "http://localhost:8000").strip()

IMAGE_ROOT = Path(imgdir)   # shared volume with Cantaloupe
IMAGE_ROOT.mkdir(parents=True, exist_ok=True)

DOCUMENT_DERIVATIVE_NAME = "document.pdf"
PDF_MIME_TYPE = "application/pdf"
PDF_THUMBNAIL_SIZES = (128, 256)
PDF_RENDER_SIZE = 512
PDF_RENDER_TIMEOUT_SECONDS = 30
ASSET_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


class InvalidPdfError(ValueError):
    """Raised when a PDF cannot be validated or rendered safely."""

class MediaType(str, Enum):
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    DOCUMENT = "document"
    OTHER = "other"

# ------------------------------------------------------------
# Storage layout helpers
# ------------------------------------------------------------

def safe_subpath(raw: str | None) -> Path:
    """Return a safe relative Path for user-provided subpaths (no absolute paths, no '..')."""
    if not raw:
        return Path()
    p = Path(raw)
    if p.is_absolute():
        raise ValueError("path must be a relative path")
    if any(part in ("..", "") for part in p.parts):
        raise ValueError("path contains invalid segments")
    return p


def validate_asset_path_segment(raw: str) -> str:
    """Return an existing asset identifier that is safe as one path segment.

    This structural check keeps legacy identifiers addressable while blocking
    filesystem traversal. New uploads additionally use the stricter
    URL-compatible validation in :func:`validate_asset_identifier`.
    """
    value = str(raw)
    if not value or value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError("asset identifier must be a single non-empty path segment")
    return value


def validate_asset_identifier(raw: str) -> str:
    """Return a new asset identifier that is safe in paths and generated URLs.

    Args:
        raw: Client-provided or generated asset identifier.

    Returns:
        The validated identifier without modification.

    Raises:
        ValueError: If the identifier is not a bounded URL-safe path segment.
    """
    value = validate_asset_path_segment(raw)
    if ASSET_IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(
            "identifier must contain 1-128 URL-safe characters "
            "(letters, digits, '.', '_', '~', or '-')"
        )
    return value


def build_asset_root(project_short: str, media_type: MediaType, subpath: str | None, identifier: str) -> Path:
    """Compute the root folder for a single asset according to storage layout.

    Layout:
      <IMAGE_ROOT>/<projectShortName>/<media_type>/<subpath>/<identifier>/
        original/
        derived/
    """
    rel = (
        Path(project_short)
        / media_type.value
        / safe_subpath(subpath)
        / validate_asset_identifier(identifier)
    )
    return IMAGE_ROOT / rel

# ------------------------------------------------------------
# Media-type detection + target format validation
# ------------------------------------------------------------

def detect_media_type(upload_file) -> MediaType:
    """Best-effort media type detection based on mimetype (preferred) and filename."""
    mt = (upload_file.mimetype or "").lower()
    if mt.startswith("image/"):
        return MediaType.IMAGE
    if mt.startswith("audio/"):
        return MediaType.AUDIO
    if mt.startswith("video/"):
        return MediaType.VIDEO
    if mt == PDF_MIME_TYPE:
        return MediaType.DOCUMENT

    # Fallback: guess from filename
    guessed, _ = mimetypes.guess_type(upload_file.filename or "")
    guessed = (guessed or "").lower()
    if guessed.startswith("image/"):
        return MediaType.IMAGE
    if guessed.startswith("audio/"):
        return MediaType.AUDIO
    if guessed.startswith("video/"):
        return MediaType.VIDEO
    if guessed == PDF_MIME_TYPE:
        return MediaType.DOCUMENT

    return MediaType.OTHER

def protocol_for_media(media_type: MediaType) -> str:
    if media_type == MediaType.IMAGE:
        return "iiif"
    if media_type in (MediaType.DOCUMENT, MediaType.AUDIO, MediaType.VIDEO):
        return "http"
    return "custom"

def validate_target_format(media_type: MediaType, raw: str | None) -> str:
    """Validate and normalize targetFormat per media type."""
    fmt = (raw or "").lower().strip()

    if media_type == MediaType.IMAGE:
        allowed = {"jp2", "tiff", "jpeg"}
        fmt = fmt or "jp2"
        if fmt not in allowed:
            raise ValueError(f"Invalid targetFormat '{fmt}' (allowed: {sorted(allowed)})")
        return fmt

    if media_type == MediaType.VIDEO:
        # Single, highly compatible web derivative.
        allowed = {"mp4"}
        fmt = fmt or "mp4"
        if fmt not in allowed:
            raise ValueError(f"Invalid targetFormat '{fmt}' (allowed: {sorted(allowed)})")
        return fmt

    if media_type == MediaType.AUDIO:
        # Default to the most broadly compatible browser delivery format.
        allowed = {"m4a", "mp3"}
        fmt = fmt or "mp3"
        if fmt not in allowed:
            raise ValueError(f"Invalid targetFormat '{fmt}' (allowed: {sorted(allowed)})")
        return fmt

    if media_type == MediaType.DOCUMENT:
        # For now: keep original; allow only pdf when we add conversions later.
        allowed = {"pdf"}
        fmt = fmt or "pdf"
        if fmt not in allowed:
            raise ValueError(f"Invalid targetFormat '{fmt}' (allowed: {sorted(allowed)})")
        return fmt

    raise ValueError(f"Unsupported media type: {media_type}")

# ------------------------------------------------------------
# Metadata helpers
# ------------------------------------------------------------

def require_valid_pdf(src: Path) -> None:
    """Validate that a stored upload looks like a PDF document.

    This is intentionally a lightweight upload gate rather than a repair or
    normalization step. It catches common MIME/extension spoofing mistakes
    before Poppler performs the full first-page render validation.

    Args:
        src: Path to the uploaded temporary file.

    Raises:
        InvalidPdfError: If the file does not contain a PDF header and EOF marker.
    """
    try:
        with src.open("rb") as handle:
            header = handle.read(1024)
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(size - 4096, 0), os.SEEK_SET)
            tail = handle.read()
    except OSError as exc:
        raise InvalidPdfError(f"Could not read uploaded PDF: {exc}") from exc

    if b"%PDF-" not in header:
        raise InvalidPdfError("Uploaded document is not a PDF file")
    if b"%%EOF" not in tail:
        raise InvalidPdfError("Uploaded PDF is incomplete or malformed")


def original_mime_type_for_media(media_type: MediaType, upload_file) -> str:
    """Return the MIME type recorded on the MediaObject for an upload."""
    if media_type == MediaType.DOCUMENT:
        return PDF_MIME_TYPE
    return upload_file.mimetype or "application/octet-stream"


def dcterms_type_for_media(media_type: MediaType) -> str:
    """Return a DCMI Type IRI (as QName string) suitable for dcterms:type."""
    if media_type == MediaType.IMAGE:
        return "dcmitype:StillImage"
    if media_type == MediaType.AUDIO:
        return "dcmitype:Sound"
    if media_type == MediaType.VIDEO:
        return "dcmitype:MovingImage"
    if media_type == MediaType.DOCUMENT:
        return "dcmitype:Text"
    return "dcmitype:Dataset"


def _read_version_from_makefile(makefile_path: Path) -> Optional[str]:
    """Read VERSION/Version assignment from a Makefile."""
    try:
        content = makefile_path.read_text(encoding="utf-8")
    except OSError:
        return None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?:VERSION|Version)\s*(?:\?=|:=|=)\s*(.+)$", line)
        if not match:
            continue
        value = match.group(1).split("#", 1)[0].strip()
        if value:
            return value
    return None


def detect_app_version() -> tuple[str, str]:
    """Resolve app version with env override, then Makefile fallback."""
    for env_name in ("MEDIAHELPER_VERSION", "MEDIASERVER_VERSION"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value, f"env:{env_name}"

    makefile_path = Path(__file__).resolve().parent / "Makefile"
    value = _read_version_from_makefile(makefile_path)
    if value:
        return value, f"makefile:{makefile_path}"

    return "unknown", "default"

def env_list(name: str, default: str = "") -> list[str]:
    value = os.environ.get(name, default)
    return [v.strip() for v in value.split(",") if v.strip()]

def content_disposition_header(disposition: str, filename: str) -> str:
    """Build a safe Content-Disposition value for Caddy-served assets."""
    cleaned = str(filename).replace("\r", "").replace("\n", "")
    quoted_filename = cleaned.replace("\\", "\\\\").replace('"', '\\"')
    return f'{disposition}; filename="{quoted_filename}"'

def create_app() -> Flask:
    app = Flask(__name__)
    # CORS: for uploads from the Svelte dev server (and later from production hosts).
    # Note: if supports_credentials=True, you MUST NOT use origins="*".
    # We do not rely on cookies here (we use Authorization: Bearer ...), so keep credentials disabled.
    app = Flask(__name__)

    cors_origins = env_list(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"
    )

    CORS(
        app,
        resources={
            r"/upload/*": {"origins": cors_origins},
            r"/delete/*": {"origins": cors_origins},
            r"/asset/*": {"origins": cors_origins, "methods": ["GET", "HEAD", "OPTIONS"]},
            r"/auth/asset/*": {"origins": cors_origins, "methods": ["GET", "HEAD", "OPTIONS"]},
            r"/health": {"origins": cors_origins},
        },
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Content-Disposition"],
        supports_credentials=False,
    )

    app.logger.setLevel("INFO")  # <— enable INFO

    logger = app.logger

    logger.info(f"Using image root: {IMAGE_ROOT}")
    logger.info(f"Using IIIF base URL: {iiif_base_url}")
    logger.info(f"Using Media base URL: {media_base_url}")
    logger.info(f"Using Oldap API URL: {oldap_api_url}")

    app_version, app_version_source = detect_app_version()
    app.config["APP_VERSION"] = app_version
    app.config["APP_VERSION_SOURCE"] = app_version_source
    logger.info(f"Using app version: {app_version} ({app_version_source})")

    token_codec = TokenCodec.from_environment()

    def allowed_cors_origin() -> Optional[str]:
        """Return the response origin for this request when CORS is allowed."""
        origin = request.headers.get("Origin", "").strip()
        if not origin:
            return None
        if "*" in cors_origins:
            return "*"
        if origin in cors_origins:
            return origin
        return None

    # ------------------------------------------------------------------
    # Access-token authentication for upload operations.
    # ------------------------------------------------------------------
    def require_access_token() -> tuple[str, AuthorizationContext]:
        """Validate a Bearer access token and return its authorization context."""
        auth = request.headers.get("Authorization", "")
        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            abort(401, description="Missing or invalid Authorization header")
        token = parts[1]
        try:
            return token, token_codec.decode_access_token(token)
        except OldapErrorConfiguration as error:
            app.logger.error("Access-token verification is not configured: %s", error)
            abort(503, description="Authentication service unavailable")
        except OldapError:
            abort(401, description="Invalid or expired access token")

    def decode_optional_query_token() -> Optional[dict]:
        """Decode optional JWT from `?token=` (HS256). Returns claims dict or None."""
        tok = request.args.get("token")
        if not tok:
            return None
        try:
            return token_codec.decode_media_token(tok)
        except OldapErrorConfiguration as error:
            app.logger.error("Media-token verification is not configured: %s", error)
            abort(503, description="Media authorization unavailable")
        except OldapError:
            return None

    # ------------------------------------------------------------------
    # Helper: run kdu_compress to JPEG2000
    # ------------------------------------------------------------------
    def convert_to_jp2_with_kakadu(src: Path, dst: Path) -> None:
        """
        Convert `src` (e.g. TIFF) to JPEG2000 using Kakadu's kdu_compress.
        Tune parameters as needed for your preservation / access profile.
        """
        cmd = [
            "/opt/kakadu/bin/kdu_compress",
            f"-i", str(src),
            f"-o", str(dst),
            # Example parameters – adjust to your liking:
            # "-rate", "8",             # visually lossless-ish, tune or remove
            "Clayers=8",
            "Clevels=6",
            "Cprecincts={256,256}",
            "Cblk={64,64}",
            "Corder=RLCP",
            "Cuse_precincts=yes",
            "ORGgen_plt=yes",
            "ORGtparts=R",
            "Stiles={1024,1024}"
        ]
        app.logger.debug("Running kdu_compress: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"kdu_compress failed (exit {result.returncode}): "
                f"{result.stderr}"
            )

    # ------------------------------------------------------------------
    # Helper: make pyramidal tiled TIFF with vips (no compression)
    # ------------------------------------------------------------------
    def convert_to_pyramidal_tiff_with_vips(src: Path, dst: Path) -> None:
        """
        Use pyvips to create a pyramidal tiled TIFF *without compression*.
        """
        image = pyvips.Image.new_from_file(str(src), access="sequential")
        image.tiffsave(
            str(dst),
            tile=True,
            pyramid=True,
            compression="none",   # no compression, as requested
            tile_width=256,
            tile_height=256,
            bigtiff=True          # safer for large CH images
        )

    # ------------------------------------------------------------------
    # Helper: make JPEG with vips
    # ------------------------------------------------------------------
    def convert_to_jpeg_with_vips(src: Path, dst: Path) -> None:
        """Create a JPEG derivative with vips.

        Note: JPEG is *lossy* by default. If you want near-lossless, pass a high `Q` (quality)
        and/or use JPEG-LS/JPEG2000 instead.
        """
        image = pyvips.Image.new_from_file(str(src), access="sequential")
        image.jpegsave(str(dst))

    # ------------------------------------------------------------------
    # Helper: make MP4 (H.264 + AAC) with ffmpeg
    # ------------------------------------------------------------------
    def convert_to_mp4_with_ffmpeg(src: Path, dst: Path) -> None:
        """Create a broadly compatible MP4 derivative.

        H.264 video + AAC audio, with faststart for progressive download.
        """
        cmd = [
            "ffmpeg",
            "-y",
            "-i", str(src),
            "-c:v", "libx264",
            "-preset", "medium",
            "-crf", "22",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-b:a", "128k",
            "-ac", "2",
            "-movflags", "+faststart",
            str(dst),
        ]
        app.logger.debug("Running ffmpeg (mp4): %s", " ".join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg mp4 failed (exit {result.returncode}): {result.stderr}")


    # ------------------------------------------------------------------
    # Helpers: validate and transcode audio with ffprobe/ffmpeg
    # ------------------------------------------------------------------
    def require_audio_stream_with_ffprobe(src: Path) -> None:
        """Verify that `src` contains at least one readable audio stream.

        This protects the audio upload path from relying only on MIME type or
        filename extension detection, both of which can be supplied by clients.

        Raises:
            RuntimeError: If ffprobe is missing, fails, or finds no audio stream.
        """
        cmd = [
            "ffprobe",
            "-v", "error",
            "-select_streams", "a:0",
            "-show_entries", "stream=codec_type",
            "-of", "csv=p=0",
            str(src),
        ]
        app.logger.debug("Running ffprobe (audio stream): %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError("ffprobe is required for audio validation but was not found") from exc

        if result.returncode != 0:
            raise RuntimeError(f"ffprobe audio validation failed (exit {result.returncode}): {result.stderr}")
        if "audio" not in {line.strip().lower() for line in result.stdout.splitlines()}:
            raise RuntimeError("Uploaded audio file does not contain a readable audio stream")

    def convert_to_mp3_with_ffmpeg(src: Path, dst: Path) -> None:
        """Create an MP3 derivative for broad browser delivery.

        The first audio stream is mapped explicitly and encoded with LAME VBR
        quality level 2, which is a practical access-copy setting for speech
        and music while keeping file sizes reasonable.
        """
        cmd = [
            "ffmpeg",
            "-y",
            "-i", str(src),
            "-map", "0:a:0",
            "-vn",
            "-c:a", "libmp3lame",
            "-q:a", "2",
            str(dst),
        ]
        app.logger.debug("Running ffmpeg (mp3): %s", " ".join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg mp3 failed (exit {result.returncode}): {result.stderr}")

    def convert_to_m4a_with_ffmpeg(src: Path, dst: Path) -> None:
        """Create an AAC-in-M4A derivative for clients that prefer AAC."""
        cmd = [
            "ffmpeg",
            "-y",
            "-i", str(src),
            "-map", "0:a:0",
            "-vn",
            "-c:a", "aac",
            "-b:a", "128k",
            "-movflags", "+faststart",
            str(dst),
        ]
        app.logger.debug("Running ffmpeg (m4a): %s", " ".join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg m4a failed (exit {result.returncode}): {result.stderr}")

    # ------------------------------------------------------------------
    # Helper: make square video thumbnail with ffmpeg
    # ------------------------------------------------------------------
    def create_video_thumbnail_with_ffmpeg(src: Path, dst: Path, size: int) -> None:
        """Create a square thumbnail from a representative video frame.

        Uses ffmpeg's `thumbnail` filter and pads the result to a square canvas
        while preserving aspect ratio.
        """
        scale_pad = (
            f"thumbnail,"
            f"scale={size}:{size}:force_original_aspect_ratio=decrease,"
            f"pad={size}:{size}:(ow-iw)/2:(oh-ih)/2"
        )
        cmd = [
            "ffmpeg",
            "-y",
            "-i", str(src),
            "-vf", scale_pad,
            "-frames:v", "1",
            str(dst),
        ]
        app.logger.debug("Running ffmpeg (video thumbnail %s): %s", size, " ".join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"ffmpeg thumbnail {size} failed (exit {result.returncode}): {result.stderr}"
            )

    def create_pdf_thumbnails_with_poppler(src: Path, destinations: dict[int, Path]) -> None:
        """Render the first PDF page and create square JPEG thumbnails.

        Poppler renders at a bounded intermediate size. Pillow then preserves
        the page aspect ratio and centers it on a white square canvas.

        Args:
            src: Validated PDF upload.
            destinations: Mapping from thumbnail edge length to output path.

        Raises:
            InvalidPdfError: If Poppler cannot parse or render the first page.
            RuntimeError: If the Poppler runtime is missing from the container.
        """
        try:
            pages = convert_from_path(
                src,
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
            raise InvalidPdfError(f"Could not render the first PDF page: {exc}") from exc

        if not pages:
            raise InvalidPdfError("Uploaded PDF does not contain a renderable first page")

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
                    offset = ((size - thumbnail.width) // 2, (size - thumbnail.height) // 2)
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

    def copy_file(src: Path, dst: Path) -> None:
        shutil.copy2(src, dst)

    @app.get("/health")
    @app.get("/status")
    def health_status():
        return jsonify(
            {
                "status": "ok",
                "service": "oldap-mediahelper",
                "version": app.config.get("APP_VERSION", "unknown"),
                "versionSource": app.config.get("APP_VERSION_SOURCE", "default"),
            }
        ), 200


    @app.get("/auth/asset/<asset_id>")
    @app.get("/auth/asset/<asset_id>/<which>")
    def auth_asset(asset_id: str, which: str = "derived"):
        """
        Authorize + resolve an opaque asset URL to an internal on-disk path.

        Intended for Caddy `auth_request`. On success returns 204 with:
          - X-OLDAP-Internal-Path: absolute path to the file on disk
          - X-OLDAP-Content-Type: best-effort MIME type
          - X-OLDAP-Content-Disposition: inline; filename="..."

        Public URL shape (served by Caddy):
          /asset/<assetId>            -> derived
          /asset/<assetId>/derived     -> derived
          /asset/<assetId>/original    -> original
        """
        try:
            asset_id = validate_asset_path_segment(asset_id)
        except ValueError:
            abort(403, description="Invalid asset identifier")

        which = (which or "derived").lower().strip()
        if which == "":
            which = "derived"
        if which not in ("derived", "original"):
            abort(404, description="Invalid asset variant")

        claims = decode_optional_query_token()

        resolved_path = None
        derivative_name = None
        original_name = None
        protocol = None
        requested_derivative = request.args.get("derivative", "").strip()

        if claims:
            def _first_claim(v):
                return v[0] if isinstance(v, list) and v else v

            resolved_path = _first_claim(claims.get("path"))
            derivative_name = _first_claim(claims.get("derivativeName"))
            original_name = _first_claim(claims.get("originalName"))
            protocol = _first_claim(claims.get("protocol"))
            tok_id = claims.get("id") or claims.get("assetId")
            if tok_id and tok_id != asset_id:
                claims = None

        if not claims:
            try:
                mo_client = OldapClient(oldap_api_url=oldap_api_url, projectId=None, token=None)
                mo = mo_client.get_mediaobject_by_assetid_unknown(asset_id)
            except requests.exceptions.HTTPError as exc:
                if getattr(exc.response, "status_code", None) == 404:
                    abort(404, description="MediaObject not found")
                app.logger.error(f"OLDAP lookup HTTP error for asset_id={asset_id}: {exc}")
                abort(502, description="Upstream OLDAP API error")
            except Exception as exc:
                app.logger.error(f"OLDAP lookup failed for asset_id={asset_id}: {exc}")
                abort(502, description="Upstream OLDAP API error")

            if mo is None:
                abort(404, description="MediaObject not found")

            # Some OLDAP endpoints may return single values as 1-element lists; normalize.
            def _first(v):
                if isinstance(v, list):
                    return v[0] if v else None
                return v

            resolved_path = _first(mo.get("shared:path") or mo.get("path"))
            derivative_name = _first(mo.get("shared:derivativeName") or mo.get("derivativeName"))
            original_name = _first(mo.get("shared:originalName") or mo.get("originalName"))
            protocol = _first(mo.get("shared:protocol") or mo.get("protocol"))

        # IIIF media may expose the uploaded original through /asset/.../original
        # for download, while derived IIIF delivery stays delegated to Cantaloupe.
        if protocol and str(protocol).lower() == "iiif" and which != "original":
            abort(403, description="IIIF derivatives are not served via /asset")
        if protocol and str(protocol).lower() not in ("http", "iiif"):
            abort(403, description="Asset not served via HTTP")

        if not resolved_path:
            abort(404, description="Missing path information")

        try:
            base_rel = safe_subpath(str(resolved_path))
        except ValueError:
            abort(403, description="Invalid stored path")

        if which == "derived":
            if requested_derivative:
                filename = Path(requested_derivative).name
                if filename != requested_derivative:
                    abort(403, description="Invalid derivative filename")
            else:
                if not derivative_name:
                    abort(404, description="Missing derivativeName")
                filename = Path(str(derivative_name)).name
            internal = (IMAGE_ROOT / base_rel / asset_id / "derived" / filename).resolve()
        else:
            if not original_name:
                abort(404, description="Missing originalName")
            filename = Path(str(original_name)).name
            internal = (IMAGE_ROOT / base_rel / asset_id / "original" / filename).resolve()

        # Ensure the resolved file is within IMAGE_ROOT (no traversal)
        try:
            internal.relative_to(IMAGE_ROOT.resolve())
        except Exception:
            abort(403, description="Resolved path escapes media root")

        app.logger.info(
            "auth_asset asset_id=%s which=%s requested_derivative=%s resolved=%s",
            asset_id,
            which,
            requested_derivative or "<default>",
            internal,
        )
        if not internal.exists() or not internal.is_file():
            abort(404, description="Asset file not found")

        mime, _ = mimetypes.guess_type(str(internal))
        mime = mime or "application/octet-stream"

        resp = app.response_class(status=204)
        resp.headers["X-OLDAP-Internal-Path"] = str(internal)
        resp.headers["X-OLDAP-Content-Type"] = mime
        disposition = "attachment" if request.args.get("download") == "1" else "inline"
        resp.headers["X-OLDAP-Content-Disposition"] = content_disposition_header(disposition, filename)
        if cors_origin := allowed_cors_origin():
            resp.headers["X-OLDAP-Cors-Allow-Origin"] = cors_origin
        return resp

    # ------------------------------------------------------------------
    # /upload endpoint
    # ------------------------------------------------------------------
    @app.post("/upload")
    def upload():
        required_form_fields = {
            'resourceClass',
            'projectId',
            'path',
            'identifier',
            'targetFormat',
            'attachedToRole',
        }

        #
        # Validate the access token and use its minimal authorization context.
        #
        token, authorization = require_access_token()

        resource_class = request.form.get("resourceClass", "shared:MediaObject")

        # get the projectID from the query parameters. It's needed for the OldapClient...
        if (projectId := request.form.get('projectId', None)) is None:
            return jsonify({"message": "Missing projectId field"}), 400

        # create the OldapClient which make the connection to the oldap server and reads the project data
        try:
            client = OldapClient(oldap_api_url=oldap_api_url, projectId=projectId, token=token)
        except Exception as exc:
            return jsonify({"message": f"Could not connect to oldap: {exc}"}), 400

        # get the projectIri and projectShortName from the project data
        if (projectIri := client.project.get('projectIri')) is None:
            return jsonify({"message": "Could not find project"}), 404
        if (projectShortName := client.project.get('projectShortName')) is None:
            return jsonify({"message": "Could not find projectShortName"}), 404

        # check if the user has the permission to upload images (ADMIN_CREATE permission)
        try:
            permissions = authorization.inProject.get(
                Iri(projectIri, validate=True)
            ) or set()
        except OldapError:
            return jsonify({"message": f'problem with projectIri "{projectIri}"'}), 404
        if AdminPermission.ADMIN_CREATE not in permissions:
            return jsonify({"message": "You don't have permission to upload images"}), 403

        if "file" not in request.files:
            return jsonify({"message": "Missing file field"}), 400

        # Check if the post request has the file part
        upload_file = request.files["file"]
        if not upload_file.filename:
            return jsonify({"message": "No file selected for uploading"}), 400

        fpath = request.form.get('path', None)

        # User-provided subpath (relative)
        try:
            _ = safe_subpath(fpath)  # validates; actual Path building happens later
        except ValueError as exc:
            return jsonify({"message": str(exc)}), 400

        # Decide media type + output format
        media_type = detect_media_type(upload_file)
        try:
            target_format = validate_target_format(media_type, request.form.get("targetFormat"))
        except ValueError as exc:
            return jsonify({"message": str(exc)}), 400

        # Identifier to be used for IIIF
        identifier = request.form.get("identifier")
        if not identifier:
            # If none provided, just generate a UUID – you may want to use
            # an OLDAP resource ID instead.
            identifier = str(generate(size=12))
        try:
            identifier = validate_asset_identifier(identifier)
        except ValueError as exc:
            return jsonify({"message": str(exc)}), 400

        roles = {}
        roles_json = request.form.get("attachedToRole")
        if roles_json:
            roles = json.loads(roles_json)

        # Temporary location
        tmp_dir = IMAGE_ROOT / "_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Build storage layout for this asset
        asset_base_rel = Path(projectShortName) / media_type.value / safe_subpath(fpath)
        asset_base_dir = (IMAGE_ROOT / asset_base_rel).resolve()
        try:
            asset_base_dir.relative_to(IMAGE_ROOT.resolve())
        except ValueError:
            return jsonify({"message": "Asset path escapes media root"}), 403
        try:
            asset_base_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return jsonify({"error": f"Could not initialize asset base directory: {exc}"}), 500
        asset_root = asset_base_dir / identifier
        try:
            asset_root.mkdir()
        except FileExistsError:
            return jsonify({"message": f'Asset identifier "{identifier}" already exists'}), 409
        except OSError as exc:
            return jsonify({"error": f"Could not reserve asset directory: {exc}"}), 500

        original_dir = asset_root / "original"
        derived_dir = asset_root / "derived"

        try:
            for d in (original_dir, derived_dir):
                d.mkdir()
        except OSError as exc:
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"error": f"Could not initialize asset directory: {exc}"}), 500

        # Keep original extension for tmp and store original as received
        orig_ext = Path(upload_file.filename).suffix or ".dat"
        tmp_path = tmp_dir / f"{identifier}{orig_ext}"
        tmp_path2: Optional[Path] = None
        thumb128_path: Optional[Path] = None
        thumb256_path: Optional[Path] = None

        # Store original file (as received), sanitized for filename
        original_name = Path(upload_file.filename).name if upload_file.filename else f"{identifier}{orig_ext}"
        original_path = original_dir / original_name

        # Decide where the produced file goes
        if media_type == MediaType.IMAGE:
            if target_format == "jp2":
                out_ext = ".jp2"
                out_path = derived_dir / f"iiif{out_ext}"
            elif target_format == "jpeg":
                out_ext = ".jpg"
                out_path = derived_dir / f"preview{out_ext}"
            else:
                out_ext = ".tif"
                out_path = derived_dir / f"master{out_ext}"

        elif media_type == MediaType.VIDEO:
            # Single web-friendly derivative
            out_ext = ".mp4"
            out_path = derived_dir / f"web{out_ext}"
            thumb128_path = derived_dir / "thumb128.jpg"
            thumb256_path = derived_dir / "thumb256.jpg"

        elif media_type == MediaType.AUDIO:
            if target_format == "mp3":
                out_ext = ".mp3"
                out_path = derived_dir / f"web{out_ext}"
            else:
                out_ext = ".m4a"
                out_path = derived_dir / f"web{out_ext}"

        elif media_type == MediaType.DOCUMENT:
            # PDF documents are not transformed for now; the derivative is a
            # stable access copy with a canonical name for frontend consumers.
            out_path = derived_dir / DOCUMENT_DERIVATIVE_NAME
            thumb128_path = derived_dir / "thumb128.jpg"
            thumb256_path = derived_dir / "thumb256.jpg"

        else:
            # Fallback: just store a derived copy
            out_ext = Path(upload_file.filename).suffix or ".dat"
            out_path = derived_dir / f"asset{out_ext}"

        # This is the filename inside <imageId>/derived/ that the delegate should serve
        derivative_name = out_path.name

        # Save uploaded file (tmp), validate document uploads, and store original.
        try:
            upload_file.save(tmp_path)
            if media_type == MediaType.DOCUMENT:
                require_valid_pdf(tmp_path)
            copy_file(tmp_path, original_path)
        except InvalidPdfError as exc:
            tmp_path.unlink(missing_ok=True)
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"message": str(exc)}), 400
        except Exception as exc:
            tmp_path.unlink(missing_ok=True)
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"error": f"Could not store uploaded file: {exc}"}), 500

        try:
            if media_type == MediaType.IMAGE:
                if target_format == "jp2":
                    src_for_kakadu = tmp_path
                    if upload_file.mimetype != "image/tiff":
                        # Kakadu can only read TIFF
                        tmp_path2 = tmp_dir / f"{identifier}.tif"
                        image = pyvips.Image.new_from_file(str(tmp_path), access="sequential")
                        image.tiffsave(str(tmp_path2), bigtiff=True)
                        src_for_kakadu = tmp_path2
                    convert_to_jp2_with_kakadu(src_for_kakadu, out_path)
                elif target_format == "jpeg":
                    # simple JPEG – if input is already JPEG, just copy the file
                    if upload_file.mimetype == "image/jpeg":
                        copy_file(tmp_path, out_path)
                    else:
                        convert_to_jpeg_with_vips(tmp_path, out_path)
                else:
                    # pyramidal tiled TIFF (no compression)
                    convert_to_pyramidal_tiff_with_vips(tmp_path, out_path)

            elif media_type == MediaType.VIDEO:
                # Always create a web MP4 derivative for now.
                convert_to_mp4_with_ffmpeg(tmp_path, out_path)
                create_video_thumbnail_with_ffmpeg(tmp_path, thumb128_path, 128)
                create_video_thumbnail_with_ffmpeg(tmp_path, thumb256_path, 256)

            elif media_type == MediaType.AUDIO:
                require_audio_stream_with_ffprobe(tmp_path)
                if target_format == "mp3":
                    convert_to_mp3_with_ffmpeg(tmp_path, out_path)
                else:
                    convert_to_m4a_with_ffmpeg(tmp_path, out_path)

            elif media_type == MediaType.DOCUMENT:
                # Keep a PDF access copy in derived/ so /asset/<assetId>
                # behaves exactly like the other HTTP-delivered media types.
                copy_file(tmp_path, out_path)
                create_pdf_thumbnails_with_poppler(
                    tmp_path,
                    {
                        PDF_THUMBNAIL_SIZES[0]: thumb128_path,
                        PDF_THUMBNAIL_SIZES[1]: thumb256_path,
                    },
                )

            else:
                raise ValueError(f"Unsupported media type: {media_type.value}")
        except InvalidPdfError as exc:
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"message": str(exc)}), 400
        except Exception as exc:
            # Clean up on failure
            if out_path.exists():
                out_path.unlink(missing_ok=True)
            if thumb128_path is not None and thumb128_path.exists():
                thumb128_path.unlink(missing_ok=True)
            if thumb256_path is not None and thumb256_path.exists():
                thumb256_path.unlink(missing_ok=True)
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"error": str(exc)}), 500
        finally:
            # Remove temp file
            tmp_path.unlink(missing_ok=True)
            if tmp_path2 is not None:
                tmp_path2.unlink(missing_ok=True)

        # Cantaloupe identifier is the relative path from IMAGE_ROOT
        iiif_id = identifier
        # iiif_base_url is expected to already end with /iiif/3/ (see env default)
        iiif_info_url = f"{iiif_base_url}{iiif_id}/info.json"
        asset_url = f"{media_base_url}asset/{identifier}"
        thumb128_url = f"{asset_url}?derivative=thumb128.jpg"
        thumb256_url = f"{asset_url}?derivative=thumb256.jpg"

        resource_data : dict[str, str | list[str]] = {
            'dcterms:type': dcterms_type_for_media(media_type),
            'shared:originalName': upload_file.filename,
            'shared:originalMimeType': original_mime_type_for_media(media_type, upload_file),
            # For images, serverUrl is the IIIF base; for other media, it is the Caddy base.
            'shared:serverUrl': iiif_base_url if media_type == MediaType.IMAGE else media_base_url,
            # New canonical key
            'shared:assetId': identifier,
            'shared:protocol': protocol_for_media(media_type),
            'shared:derivativeName': derivative_name,
            # Store the logical folder (relative to IMAGE_ROOT) for later retrieval / housekeeping
            'shared:path': asset_base_rel.as_posix(),
            'shared:mediaAccessMode': "local",
        }
        if roles:
            resource_data['attachedToRole'] = roles
        for key in request.form.keys():
            if key not in required_form_fields:
                resource_data[key] = request.form.getlist(key)
        try:
            response = client.create_resource(resource=resource_class, resource_data=resource_data)
        except Exception as exc:
            # The directory is exclusively owned by this upload, so failed
            # registration must not leave an unaddressable partial asset.
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"error": f"Failed to create OLDAP resource: {exc}"}), 500

        return jsonify(
            {
                "identifier": identifier,
                "assetId": identifier,
                "imageId": identifier,  # backwards compatibility
                "iri": response['iri'],
                "originalName": upload_file.filename,
                "originalMimeType": original_mime_type_for_media(media_type, upload_file),
                "derivativeName": derivative_name,
                "mediaType": media_type.value,
                "dctermsType": dcterms_type_for_media(media_type),
                "protocol": protocol_for_media(media_type),
                "iiifInfoUrl": iiif_info_url,
                "assetUrl": asset_url,
                "storedPath": asset_base_rel.as_posix(),
                "thumb128Name": thumb128_path.name if thumb128_path is not None else None,
                "thumb256Name": thumb256_path.name if thumb256_path is not None else None,
                "thumb128Url": thumb128_url if thumb128_path is not None else None,
                "thumb256Url": thumb256_url if thumb256_path is not None else None,
            }        )

    @app.delete("/upload/<asset_id>")
    def delete(asset_id):
        # we can only delete if we have a bearer token
        token = require_bearer_token()
        try:
            asset_id = validate_asset_path_segment(asset_id)
        except ValueError:
            return jsonify({"error": "Invalid asset identifier"}), 400

        #
        # now let's retieve the MediaObject from the OLDAP-API
        #
        id_esc = quote(str(asset_id), safe="")
        url = f"{oldap_api_url}/data/mediaobject/id/{id_esc}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=10)
        except requests.exceptions.Timeout as exc:
            return jsonify({"error": f"Timeout: Failed to fetch OLDAP resource: {exc}"}), 500
        except requests.exceptions.RequestException as exc:
            return jsonify({"error": f"Failed to fetch OLDAP resource: {exc}"}), 500
        res = response.json()

        #
        # we need the project id (aka projectShortName) which is the prefix of the graph
        #
        graph = res.get("graph", "")
        try:
            graph_qname = Xsd_QName(graph)
        except OldapError:
            return jsonify({"error": f"Invalid graph: {graph}"}), 400
        project_id = graph_qname.prefix  # The graph QName for data is "<projectid>:data"

        #
        # now let's check if the user has the permission to delete the asset
        #
        permval = res.get("permval")
        if permval < DataPermission.DATA_DELETE.numeric:
            return jsonify({"error": f"Insufficient permissions: {permval}"}), 403

        iri = res.get("iri")

        url = f"{oldap_api_url}/data/{project_id}/{iri}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.delete(url, headers=headers, timeout=10)
        except requests.exceptions.Timeout as exc:
            return jsonify({"error": f"Timeout: Failed to fetch OLDAP resource: {exc}"}), 500
        except requests.exceptions.RequestException as exc:
            return jsonify({"error": f"Failed to fetch OLDAP resource: {exc}"}), 500
        if response.status_code < 200 or response.status_code >= 300:
            return jsonify({"error": f"Failed to delete OLDAP resource: {response.text}"}), 500

        raw_asset_basepath = res.get("shared:path", "")
        if isinstance(raw_asset_basepath, list):
            asset_basepath = raw_asset_basepath[0] if raw_asset_basepath else ""
        else:
            asset_basepath = raw_asset_basepath or ""

        try:
            safe_basepath = safe_subpath(str(asset_basepath))
            asset_root = (IMAGE_ROOT / safe_basepath / asset_id).resolve()
            asset_root.relative_to(IMAGE_ROOT.resolve())
        except ValueError as exc:
            return jsonify({"error": f"Invalid stored path: {exc}"}), 400
        except Exception:
            return jsonify({"error": "Resolved path escapes media root"}), 403

        if asset_root.exists():
            shutil.rmtree(asset_root)

        return jsonify({"message": f"Deleted asset {asset_id} at {asset_root}"}), 200


    return app


# For gunicorn: `gunicorn -b 0.0.0.0:8000 app:app`
app = create_app()
