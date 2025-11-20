import os
import uuid
import subprocess
from pathlib import Path
from typing import Literal

from flask import Flask, request, jsonify, abort

import pyvips  # make sure this is in requirements.txt
from flask_cors import CORS

IMAGE_ROOT = Path("/data/images")   # shared volume with Cantaloupe
IMAGE_ROOT.mkdir(parents=True, exist_ok=True)

# For local dev, Cantaloupe is usually on host:8182
# In production, put your real hostname here
CANTALOUPE_BASE_URL = os.environ.get(
    "CANTALOUPE_BASE_URL",
    "http://localhost:8182"  # change in deployment
)


def create_app() -> Flask:
    app = Flask(__name__)

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
    # /upload endpoint
    # ------------------------------------------------------------------
    @app.post("/upload")
    def upload():
        """
        Accepts:
          - Multipart file "file"
          - Optional form field "identifier" (if you want explicit IIIF id)
          - Optional form field "target_format": "jp2" or "tiff"
            (default: "jp2")

        Stores the derivative directly in /data/images/<identifier>.<ext>
        and returns the IIIF URL for Cantaloupe.
        """
        require_bearer_token()

        if "file" not in request.files:
            abort(400, description="Missing file field")

        upload_file = request.files["file"]
        if not upload_file.filename:
            abort(400, description="Uploaded file has no filename")

        # Decide output format
        target_format: Literal["jp2", "tiff"]
        target_format = request.form.get("target_format", "jp2").lower()  # default jp2
        if target_format not in ("jp2", "tiff"):
            abort(400, description="target_format must be 'jp2' or 'tiff'")

        # Identifier to be used for IIIF
        identifier = request.form.get("identifier")
        if not identifier:
            # If none provided, just generate a UUID – you may want to use
            # an OLDAP resource ID instead.
            identifier = str(uuid.uuid4())

        # Decide on extensions
        if target_format == "jp2":
            out_ext = ".jp2"
        else:
            out_ext = ".tif"

        # Temporary location & final output location
        tmp_dir = IMAGE_ROOT / "_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Try to keep original extension for tmp
        orig_ext = Path(upload_file.filename).suffix or ".dat"
        tmp_path = tmp_dir / f"{identifier}{orig_ext}"

        out_path = IMAGE_ROOT / f"{identifier}{out_ext}"

        # Save uploaded file
        upload_file.save(tmp_path)

        try:
            if target_format == "jp2":
                # Option 1: if the upload is already TIFF, we compress directly.
                # If it is JPEG or something else, you may want an additional
                # conversion step here (e.g. vips -> TIFF -> kdu_compress).
                convert_to_jp2_with_kakadu(tmp_path, out_path)
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

        # Build an IIIF URL for convenience
        # For IIIF 3:
        iiif_id = f"{identifier}{out_ext}"
        iiif_info_url = f"{CANTALOUPE_BASE_URL}/iiif/3/{iiif_id}/info.json"

        return jsonify(
            {
                "identifier": identifier,
                "target_format": target_format,
                "filename": iiif_id,
                "iiif_info_url": iiif_info_url,
            }
        )

    CORS(app,
         resources={r"/*": {"origins": "*"}},
         supports_credentials=True,
         expose_headers=["Content-Disposition"])

    return app


# For gunicorn: `gunicorn -b 0.0.0.0:8000 app:app`
app = create_app()