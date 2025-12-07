import json
import os
import shutil
import uuid
import subprocess
from pathlib import Path
from typing import Literal, get_args, cast

import jwt
from flask import Flask, request, jsonify, abort, logging

import pyvips  # make sure this is in requirements.txt
from flask_cors import CORS
from nanoid import generate
from oldaplib.src.enums.adminpermissions import AdminPermission
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



def create_app() -> Flask:
    app = Flask(__name__)

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
    # Helper: make JPEG with vips (no compression)
    # ------------------------------------------------------------------
    def convert_to_jpeg_with_vips(src: Path, dst: Path) -> None:
        """
        Use pyvips to create a pyramidal tiled TIFF *without compression*.
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
        """
        Accepts:
          - Multipart file "file"
          - Form field "projectId"
          - Optional form field "identifier" (if you want explicit IIIF id)
          - Optional form field "target_format": "jp2" or "tiff"
            (default: "jp2")

        Stores the derivative directly in /data/images/<identifier>.<ext>
        and returns the IIIF URL for Cantaloupe.
        """
        token = require_bearer_token()
        tokendata = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        userdata: UserData = json.loads(tokendata.get("userdata", "{}"), object_hook=serializer.decoder_hook)

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

        # Decide output format
        TargetFormat = Literal["jp2", "tiff", "jpeg"]
        raw_format = request.form.get("targetFormat", "jp2").lower()  # default jp2
        if raw_format not in get_args(TargetFormat):
            return jsonify({"message": "Invalid target_format"}), 400
        target_format = cast(TargetFormat, raw_format)

        # Identifier to be used for IIIF
        identifier = request.form.get("identifier")
        if not identifier:
            # If none provided, just generate a UUID – you may want to use
            # an OLDAP resource ID instead.
            identifier = str(generate(size=12))

        if (permission_sets := request.form.getlist("permissionSets")) is None:
            return jsonify({"message": "No permission sets provided"}), 400

        # Decide on extensions
        if target_format == "jp2":
            out_ext = ".jp2"
        elif target_format == "jpeg":
            out_ext = ".jpg"
        else:
            out_ext = ".tif"

        # Temporary location & final output location
        tmp_dir = IMAGE_ROOT / "_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # Try to keep original extension for tmp
        orig_ext = Path(upload_file.filename).suffix or ".dat"
        tmp_path = tmp_dir / f"{identifier}{orig_ext}"
        tmp_path2 = ''

        pdir = IMAGE_ROOT / f"{projectId}"
        pdir.mkdir(parents=True, exist_ok=True)
        if fpath:
            ppdir = IMAGE_ROOT / f"{projectId}/{fpath}"
            out_path = IMAGE_ROOT / f"{projectShortName}/{fpath}/{identifier}{out_ext}"
        else:
            out_path = IMAGE_ROOT / f"{projectShortName}/{identifier}{out_ext}"

        # Save uploaded file
        upload_file.save(tmp_path)

        try:
            if target_format == "jp2":
                if (upload_file.mimetype != "image/tiff"):
                    # kakadu can only read TIFF's
                    tmp_path2 = tmp_dir / f"{identifier}.tif"
                    image = pyvips.Image.new_from_file(str(tmp_path), access="sequential")
                    image.tiffsave(str(tmp_path2), bigtiff=True)
                    tmp_path = tmp_path2
                convert_to_jp2_with_kakadu(tmp_path, out_path)
            elif target_format == "jpeg":
                # simple JPEG – if input is JPEG, just copy the file...
                if upload_file.mimetype != "image/jpeg":
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
            if tmp_path2:
                tmp_path2.unlink(missing_ok=True)

        # Build an IIIF URL for convenience
        # For IIIF 3:
        iiif_id = f"{identifier}{out_ext}"
        iiif_info_url = f"{iiif_base_url}/iiif/3/{iiif_id}/info.json"

        try:
            response = client.create_resource(resource="shared:MediaObject", resource_data={
                'shared:originalName': upload_file.filename,
                'shared:originalMimeType': upload_file.mimetype,
                'shared:serverUrl': iiif_base_url,
                'shared:imageId': f"{identifier}{out_ext}",
                'shared:protocol': 'iiif',
                'shared:path': f"{projectId}/{fpath}" if fpath else projectId,
                'grantsPermission': permission_sets
            })
        except Exception as exc:
            out_path.unlink(missing_ok=True)
            return jsonify({"error": f"Failed to create OLDAP resource: {exc}"}), 500


        return jsonify(
            {
                "identifier": identifier,
                "iri": response['iri']
            }
        )

    CORS(app,
         resources={r"/*": {"origins": "*"}},
         supports_credentials=True,
         expose_headers=["Content-Disposition"])

    return app


# For gunicorn: `gunicorn -b 0.0.0.0:8000 app:app`
app = create_app()