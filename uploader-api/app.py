import json
import os
import shutil
import uuid
import subprocess
import mimetypes
from enum import Enum
from pathlib import Path
from typing import Optional

import jwt
from flask import Flask, request, jsonify, abort, logging

import pyvips  # make sure this is in requirements.txt
from flask_cors import CORS
from nanoid import generate
from oldaplib.src.enums.adminpermissions import AdminPermission
from oldaplib.src.helpers.observable_dict import ObservableDict
from oldaplib.src.helpers.oldaperror import OldapError
from oldaplib.src.helpers.serializer import serializer
from oldaplib.src.userdataclass import UserData
from oldaplib.src.xsd.iri import Iri

from oldap_client import OldapClient

imgdir  = os.environ.get("UPLOADER_IMGDIR", "/data/images")
# For local dev, Cantaloupe is usually on host:8182
# In production, put your real hostname here
iiif_base_url = os.environ.get("IIIF_BASE_URL", "http://localhost:8182/iiif/3/")

oldap_api_url = os.environ.get("OLDAP_API_URL", "http://localhost:8000")

IMAGE_ROOT = Path(imgdir)   # shared volume with Cantaloupe
IMAGE_ROOT.mkdir(parents=True, exist_ok=True)

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


def build_asset_root(project_short: str, media_type: MediaType, subpath: str | None, identifier: str) -> Path:
    """Compute the root folder for a single asset according to storage layout.

    Layout:
      <IMAGE_ROOT>/<projectShortName>/<media_type>/<subpath>/<identifier>/
        original/
        derived/
    """
    rel = Path(project_short) / media_type.value / safe_subpath(subpath) / identifier
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
    if mt == "application/pdf":
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
    if guessed == "application/pdf":
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
    # For now we only support the image pipeline; other media types will be added next.
    if media_type != MediaType.IMAGE:
        raise ValueError(f"Unsupported media type: {media_type}")

    allowed = {"jp2", "tiff", "jpeg"}
    fmt = (raw or "jp2").lower().strip()
    if fmt not in allowed:
        raise ValueError(f"Invalid targetFormat '{fmt}' (allowed: {sorted(allowed)})")
    return fmt

# ------------------------------------------------------------
# Metadata helpers
# ------------------------------------------------------------

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

def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app,
         resources={r"/*": {"origins": "*"}},
         supports_credentials=True,
         expose_headers=["Content-Disposition"])

    app.logger.setLevel("INFO")  # <— enable INFO

    logger = app.logger

    logger.info(f"Using image root: {IMAGE_ROOT}")
    logger.info(f"Using IIIF base URL: {iiif_base_url}")
    logger.info(f"Using Oldap API URL: {oldap_api_url}")

    jwt_secret = os.getenv("OLDAP_JWT_SECRET", "You have to change this!!! +D&RWG+")

    # ------------------------------------------------------------------
    # Simple auth helper (Bearer <token>)
    # Here we just check presence; you will plug in real validation
    # against oldap-api or a JWKS later.
    # ------------------------------------------------------------------
    def require_bearer_token():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            abort(401, description="Missing or invalid Authorization header")
        token = auth[7:]
        if not token:
            abort(401, description="Empty Bearer token")

        # TODO: call oldap-api or verify JWT here
        return token

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

    def copy_file(src: Path, dst: Path) -> None:
        shutil.copy2(src, dst)

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
        # extract the baerer token and the userinformation therein
        #
        token = require_bearer_token()
        tokendata = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        userdata: UserData = json.loads(tokendata.get("userdata", "{}"), object_hook=serializer.decoder_hook)

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
            permissions =  userdata.inProject.get(Iri(projectIri, validate=True))
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

        roles = request.form.getlist("attachedToRole")

        # Temporary location
        tmp_dir = IMAGE_ROOT / "_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Build storage layout for this asset
        asset_base_rel = Path(projectShortName) / media_type.value / safe_subpath(fpath)
        asset_root = IMAGE_ROOT / asset_base_rel / identifier

        original_dir = asset_root / "original"
        derived_dir = asset_root / "derived"

        for d in (original_dir, derived_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Keep original extension for tmp and store original as received
        orig_ext = Path(upload_file.filename).suffix or ".dat"
        tmp_path = tmp_dir / f"{identifier}{orig_ext}"
        tmp_path2: Optional[Path] = None

        # Store original file (as received), sanitized for filename
        original_name = Path(upload_file.filename).name if upload_file.filename else f"{identifier}{orig_ext}"
        original_path = original_dir / original_name

        # Decide where the produced file goes
        if target_format == "jp2":
            out_ext = ".jp2"
            out_path = derived_dir / f"iiif{out_ext}"
        elif target_format == "jpeg":
            out_ext = ".jpg"
            out_path = derived_dir / f"preview{out_ext}"
        else:
            out_ext = ".tif"
            out_path = derived_dir / f"master{out_ext}"

        # This is the filename inside <imageId>/derived/ that the delegate should serve
        derivative_name = out_path.name

        # Save uploaded file (tmp) and store original
        upload_file.save(tmp_path)
        copy_file(tmp_path, original_path)

        try:
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
        except Exception as exc:
            # Clean up on failure
            if out_path.exists():
                out_path.unlink(missing_ok=True)
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

        resource_data = {
            'dcterms:type': dcterms_type_for_media(media_type),
            'shared:originalName': upload_file.filename,
            'shared:originalMimeType': upload_file.mimetype,
            'shared:serverUrl': iiif_base_url,
            'shared:imageId': identifier,
            'shared:protocol': protocol_for_media(media_type),
            'shared:derivativeName': derivative_name,
            # Store the logical folder (relative to IMAGE_ROOT) for later retrieval / housekeeping
            'shared:path': asset_base_rel.as_posix(),
        }
        if (roles):
            resource_data['attachedToRole'] = roles
        for key, value in request.form.items():
            if key not in required_form_fields:
                resource_data[key] = value
        try:
            response = client.create_resource(resource=resource_class, resource_data=resource_data)
        except Exception as exc:
            # Keep the original, but remove the derived/master file to avoid orphaned derivatives
            out_path.unlink(missing_ok=True)
            return jsonify({"error": f"Failed to create OLDAP resource: {exc}"}), 500


        return jsonify(
            {
                "identifier": identifier,
                "iri": response['iri'],
                "originalName": upload_file.filename,
                "mediaType": media_type.value,
                "iiifInfoUrl": iiif_info_url,
                "imageId": identifier,
                "storedPath": asset_base_rel.as_posix(),
            }
        )

    return app


# For gunicorn: `gunicorn -b 0.0.0.0:8000 app:app`
app = create_app()