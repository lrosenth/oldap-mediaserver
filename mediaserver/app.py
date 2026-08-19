import json
import os
import shutil
import mimetypes
from dataclasses import replace
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from uuid import UUID, uuid4

import requests
from flask import Flask, request, jsonify, abort, logging, Response

from flask_cors import CORS
from nanoid import generate
from oldaplib.src.authentication import AuthorizationContext, TokenCodec
from oldaplib.src.enums.adminpermissions import AdminPermission
from oldaplib.src.enums.datapermissions import DataPermission
from oldaplib.src.helpers.oldaperror import OldapError, OldapErrorConfiguration
from oldaplib.src.xsd.iri import Iri
from oldaplib.src.xsd.xsd_qname import Xsd_QName

from oldap_client import OldapClient
from config import MediahelperSettings, ZipImportLimits
from derivatives import DerivativeProcessor
from media import (
    InvalidHeifError,
    InvalidPdfError,
    HEIF_EXTENSION_MIME_TYPES,
    MediaType,
    classify_upload,
    detect_heif_variant,
    probe_heif_page_count,
    probe_pdf_structure,
    validate_target_format,
)
from ingest_auth import (
    InvalidUploadCapability,
    UploadAuthenticationUnavailable,
    UploadCapabilityMismatch,
    decode_upload_capability,
)
from export_sources import (
    ExportSourceAuthenticationUnavailable,
    ExportSourceAuthorizationError,
    ExportSourceConflictError,
    ExportSourceNotFoundError,
    ExportSourceRequestError,
    authorize_export_source_token,
    parse_export_source_request,
    resolve_export_sources,
)
from export_artifacts import (
    ExportArtifactError,
    ExportArtifactStore,
    ExportDownloadAuthenticationUnavailable,
    ExportDownloadAuthorizationError,
    authorize_export_download,
    digest_header as export_digest_header,
)
from ingest_callback import (
    CallbackError,
    ImportApiNotifier,
    PeriodicCallbackReconciler,
    deliver_pending_receipt,
)
from import_records import (
    ImportRecordAuthorizationError,
    ImportRecordError,
    ImportRecordStore,
    authorize_record_token,
    digest_header,
)
from quarantine import (
    FinalizedUploadConflict,
    InvalidZipContent,
    QuarantineStore,
    UploadLengthMismatch,
    UploadTooLarge,
)
from storage_capacity import (
    PhysicalCapacityInsufficient,
    StorageCapacityGuard,
    potential_extracted_bytes,
)
from storage import (
    AssetAlreadyExistsError,
    StoragePathEscapeError,
    operation_workspace,
    reserve_asset_layout,
    safe_subpath,
    store_original_with_sha256,
    validate_asset_identifier,
    validate_asset_path_segment,
)

SETTINGS = MediahelperSettings.from_environment()
iiif_base_url = SETTINGS.iiif_base_url
media_base_url = SETTINGS.media_base_url
oldap_api_url = SETTINGS.oldap_api_url

IMAGE_ROOT = SETTINGS.media_root  # shared volume with Cantaloupe
IMAGE_ROOT.mkdir(parents=True, exist_ok=True)
INGEST_ROOT = SETTINGS.ingest_root  # private: never mounted into delivery services
CAPACITY_GUARD = StorageCapacityGuard(SETTINGS.storage_absolute_reserve_bytes)
QUARANTINE_STORE = QuarantineStore(INGEST_ROOT, capacity_guard=CAPACITY_GUARD)
IMPORT_RECORD_STORE = ImportRecordStore(SETTINGS.import_records_root)
EXPORT_ARTIFACT_STORE = ExportArtifactStore(
    SETTINGS.export_root,
    IMAGE_ROOT,
    capacity_guard=CAPACITY_GUARD,
)

DERIVATIVE_PROCESSOR = DerivativeProcessor()


def deliver_import_receipt(receipt):
    """Deliver one retained callback and persist its acknowledgement."""
    notifier = ImportApiNotifier.from_environment()
    return deliver_pending_receipt(QUARANTINE_STORE, notifier, receipt)


def _read_version_file(version_path: Path) -> Optional[str]:
    """Return a non-empty component version from a plain text file.

    Args:
        version_path: Path to the component ``VERSION`` file.

    Returns:
        The stripped version string, or ``None`` when the file is unavailable
        or empty.
    """
    try:
        value = version_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def detect_app_version() -> tuple[str, str]:
    """Resolve the runtime version from the image environment or VERSION file.

    Returns:
        A tuple containing the component version and a diagnostic source name.
        Container builds set ``MEDIAHELPER_VERSION`` explicitly; direct local
        runs fall back to the checked-in component ``VERSION`` file.
    """
    for env_name in ("MEDIAHELPER_VERSION", "MEDIASERVER_VERSION"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value, f"env:{env_name}"

    version_path = Path(__file__).resolve().parent / "VERSION"
    value = _read_version_file(version_path)
    if value:
        return value, f"file:{version_path}"

    return "unknown", "default"


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

    cors_origins = list(SETTINGS.cors_origins)

    CORS(
        app,
        resources={
            r"/upload/*": {"origins": cors_origins},
            r"/delete/*": {"origins": cors_origins},
            r"/asset/*": {"origins": cors_origins, "methods": ["GET", "HEAD", "OPTIONS"]},
            r"/auth/asset/*": {"origins": cors_origins, "methods": ["GET", "HEAD", "OPTIONS"]},
            r"/health": {"origins": cors_origins},
            r"/imports/*": {
                "origins": cors_origins,
                "methods": ["PUT", "OPTIONS"],
            },
            r"/auth/exports/*": {
                "origins": cors_origins,
                "methods": ["GET", "HEAD", "OPTIONS"],
            },
        },
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Upload-Request-Id"],
        expose_headers=["Content-Disposition", "Location"],
        supports_credentials=False,
    )

    app.logger.setLevel("INFO")  # <— enable INFO

    logger = app.logger

    logger.info(f"Using image root: {IMAGE_ROOT}")
    logger.info(f"Using private ingest root: {INGEST_ROOT}")
    logger.info(f"Using retained import records root: {SETTINGS.import_records_root}")
    logger.info(f"Using private export root: {SETTINGS.export_root}")
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

    def import_error(status: int, code: str, message: str):
        """Return the closed media-ingest error contract without sensitive data."""
        supplied = request.headers.get("X-Upload-Request-Id", "")
        try:
            request_id = str(UUID(supplied)) if supplied else str(uuid4())
        except ValueError:
            request_id = str(uuid4())
        response = jsonify(
            {"code": code, "message": message[:500], "requestId": request_id}
        )
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        if status == 401:
            response.headers["WWW-Authenticate"] = "Bearer"
        return response

    @app.get("/internal/imports/<import_id>/records/<record_type>")
    def get_import_record(import_id: str, record_type: str):
        """Return exact immutable validation JSON to authenticated oldap-api."""

        try:
            authorize_record_token(request.headers.get("Authorization"), import_id)
        except (ImportRecordAuthorizationError, ValueError):
            response = jsonify({"message": "Import records authorization required."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Bearer"
            response.headers["Cache-Control"] = "no-store"
            return response
        try:
            content, digest = IMPORT_RECORD_STORE.read(import_id, record_type)
        except ValueError:
            return jsonify({"message": "Unknown import record type."}), 404
        except FileNotFoundError:
            return jsonify({"message": "Import record not found."}), 404
        except ImportRecordError:
            app.logger.error("import_record_inconsistent importId=%s", import_id)
            return jsonify({"message": "Import record unavailable."}), 409
        response = Response(content, status=200, content_type="application/json")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Digest"] = digest_header(digest)
        return response

    @app.post("/internal/export-sources/resolve")
    def resolve_export_source_originals():
        """Resolve a bounded batch of API-authorized local media originals."""

        try:
            authorize_export_source_token(request.headers.get("Authorization"))
        except ExportSourceAuthenticationUnavailable:
            app.logger.error("Export source authentication is not safely configured.")
            response = jsonify({"message": "Export source service unavailable."})
            response.status_code = 503
            response.headers["Cache-Control"] = "no-store"
            return response
        except ExportSourceAuthorizationError:
            response = jsonify({"message": "Export source authorization required."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Bearer"
            response.headers["Cache-Control"] = "no-store"
            return response

        try:
            references = parse_export_source_request(request.get_json(silent=True))
            sources = resolve_export_sources(IMAGE_ROOT, references)
        except ExportSourceRequestError:
            response = jsonify({"message": "Invalid export source request."})
            response.status_code = 400
        except ExportSourceNotFoundError:
            response = jsonify({"message": "Export source original not found."})
            response.status_code = 404
        except ExportSourceConflictError:
            response = jsonify({"message": "Export source identity conflict."})
            response.status_code = 409
        else:
            app.logger.info("export_sources_resolved itemCount=%d", len(sources))
            response = jsonify({"items": [source.to_dict() for source in sources]})
            response.status_code = 200
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/auth/exports/<export_id>/archive", methods=["GET", "HEAD"])
    def authorize_export_archive(export_id: str):
        """Authorize Caddy to serve one exact immutable finalized ZIP."""

        try:
            authorize_export_download(request.args.get("token"), export_id)
        except ExportDownloadAuthenticationUnavailable:
            app.logger.error(
                "Export download authentication is not safely configured."
            )
            response = jsonify({"message": "Export download unavailable."})
            response.status_code = 503
            response.headers["Cache-Control"] = "no-store"
            return response
        except (ExportDownloadAuthorizationError, ValueError):
            response = jsonify({"message": "Export download authorization required."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Bearer"
            response.headers["Cache-Control"] = "no-store"
            return response
        try:
            artifact = EXPORT_ARTIFACT_STORE.resolve(export_id)
        except FileNotFoundError:
            response = jsonify({"message": "Export artifact not found."})
            response.status_code = 404
            response.headers["Cache-Control"] = "no-store"
            return response
        except ExportArtifactError:
            app.logger.error("export_artifact_inconsistent exportId=%s", export_id)
            response = jsonify({"message": "Export artifact unavailable."})
            response.status_code = 409
            response.headers["Cache-Control"] = "no-store"
            return response

        response = Response(status=200)
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["X-Oldap-Internal-Path"] = str(
            artifact.archive_path.resolve(strict=True)
        )
        response.headers["X-Oldap-Content-Type"] = "application/zip"
        response.headers["X-Oldap-Content-Disposition"] = (
            content_disposition_header(
                "attachment", f"oldap-export-{export_id}.zip"
            )
        )
        response.headers["X-Oldap-Digest"] = export_digest_header(
            artifact.evidence.archive_sha256
        )
        response.headers["X-Oldap-Cors-Allow-Origin"] = allowed_cors_origin() or ""
        return response

    def upload_bearer_token() -> str | None:
        """Parse a strict Authorization Bearer header for SIP upload only."""
        parts = request.headers.get("Authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            return None
        return parts[1]

    @app.put("/imports/<import_id>/sip")
    def put_import_sip(import_id: str):
        """Stream one authorized ZIP into atomically finalized quarantine."""
        token = upload_bearer_token()
        if token is None:
            return import_error(401, "UPLOAD_AUTH_REQUIRED", "Upload authorization required.")
        try:
            capability = decode_upload_capability(token, import_id)
        except UploadAuthenticationUnavailable:
            app.logger.error("ZIP upload authentication is not safely configured.")
            return import_error(503, "UPLOAD_AUTH_UNAVAILABLE", "Upload service unavailable.")
        except InvalidUploadCapability:
            return import_error(401, "UPLOAD_AUTH_INVALID", "Invalid or expired upload authorization.")
        except UploadCapabilityMismatch:
            return import_error(403, "UPLOAD_AUTH_MISMATCH", "Upload authorization does not match this import.")
        except ValueError:
            return import_error(400, "IMPORT_ID_INVALID", "importId must be a canonical UUID.")

        if request.mimetype != "application/zip":
            return import_error(415, "ZIP_MEDIA_TYPE_REQUIRED", "Content-Type must be application/zip.")
        raw_length = request.headers.get("Content-Length")
        raw_request_id = request.headers.get("X-Upload-Request-Id")
        try:
            declared_size = int(raw_length or "")
            if str(UUID(str(raw_request_id))) != str(raw_request_id).lower():
                raise ValueError
        except (TypeError, ValueError):
            return import_error(400, "UPLOAD_HEADERS_INVALID", "Valid Content-Length and X-Upload-Request-Id headers are required.")
        if not 1 <= declared_size <= capability.max_bytes:
            return import_error(413, "UPLOAD_SIZE_LIMIT", "Upload exceeds its authorized byte limit.")

        try:
            validation_bytes = potential_extracted_bytes(
                declared_size,
                maximum_bytes=ZipImportLimits().max_extracted_bytes,
            )
            receipt, replay = QUARANTINE_STORE.store(
                import_id,
                str(raw_request_id).lower(),
                request.stream,
                declared_size_bytes=declared_size,
                max_bytes=capability.max_bytes,
                required_capacity_bytes=declared_size + validation_bytes,
            )
        except UploadTooLarge:
            return import_error(413, "UPLOAD_SIZE_LIMIT", "Upload exceeds its authorized byte limit.")
        except InvalidZipContent:
            return import_error(415, "ZIP_CONTENT_INVALID", "Uploaded content is not a supported ZIP.")
        except UploadLengthMismatch:
            return import_error(400, "UPLOAD_LENGTH_MISMATCH", "Uploaded bytes differ from Content-Length.")
        except FinalizedUploadConflict:
            return import_error(409, "UPLOAD_ALREADY_FINALIZED", "Import SIP is already finalized.")
        except PhysicalCapacityInsufficient as error:
            facts = error.snapshot
            app.logger.warning(
                "import_capacity_rejected importId=%s phase=UPLOAD "
                "requiredBytes=%d freeBytes=%d reserveBytes=%d",
                import_id,
                facts.required_bytes,
                facts.free_bytes,
                facts.reserve_bytes,
            )
            return import_error(
                507,
                "IMPORT_PHYSICAL_CAPACITY_INSUFFICIENT",
                "The import cannot be stored while the required disk reserve is maintained.",
            )
        except OSError as error:
            app.logger.error(
                "Could not finalize import SIP importId=%s error=%s",
                import_id,
                type(error).__name__,
            )
            return import_error(500, "UPLOAD_STORAGE_FAILED", "SIP could not be durably stored.")

        if receipt.state_notification == "PENDING":
            try:
                receipt = deliver_import_receipt(receipt)
            except CallbackError as error:
                app.logger.warning(
                    "import_callback_pending importId=%s error=%s",
                    import_id,
                    type(error).__name__,
                )

        app.logger.info(
            "import_upload importId=%s sizeBytes=%d replay=%s requestId=%s",
            import_id,
            receipt.size_bytes,
            replay,
            receipt.upload_request_id,
        )
        response = jsonify(receipt.to_dict())
        response.status_code = 200 if replay else 201
        response.headers["Cache-Control"] = "no-store"
        if not replay:
            response.headers["Location"] = f"/imports/{import_id}/sip"
        return response


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

        # Preserve legacy request routing while representing it explicitly as
        # untrusted MIME/filename classification rather than content evidence.
        try:
            classification = classify_upload(
                upload_file.filename,
                upload_file.mimetype,
                request.form.get("targetFormat"),
            )
        except ValueError as exc:
            return jsonify({"message": str(exc)}), 400
        media_type = classification.media_type

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

        # Reserve a create-only asset directory before writing any bitstreams.
        try:
            layout = reserve_asset_layout(
                IMAGE_ROOT,
                projectShortName,
                media_type.value,
                fpath,
                identifier,
            )
        except StoragePathEscapeError as exc:
            return jsonify({"message": str(exc)}), 403
        except AssetAlreadyExistsError:
            return jsonify({"message": f'Asset identifier "{identifier}" already exists'}), 409
        except OSError as exc:
            return jsonify({"error": f"Could not initialize asset directory: {exc}"}), 500

        asset_base_rel = layout.base_relative
        asset_root = layout.root
        original_dir = layout.original
        derived_dir = layout.derived

        # Keep original extension for tmp and store original as received
        orig_ext = Path(upload_file.filename).suffix or ".dat"

        # Store original file (as received), sanitized for filename
        original_name = Path(upload_file.filename).name if upload_file.filename else f"{identifier}{orig_ext}"
        original_path = original_dir / original_name

        try:
            # Each operation gets an unpredictable directory. Concurrent jobs
            # can therefore never share a temporary filename.
            with operation_workspace(IMAGE_ROOT / "_tmp", identifier) as workspace:
                tmp_path = workspace / f"source{orig_ext}"

                # Save once, validate from quarantine-like work storage, then
                # copy the original while calculating its integrity metadata.
                try:
                    upload_file.save(tmp_path)
                    with tmp_path.open("rb") as source_handle:
                        heif_variant = detect_heif_variant(source_handle.read(4096))
                    heif_claimed = (
                        Path(upload_file.filename).suffix.casefold()
                        in HEIF_EXTENSION_MIME_TYPES
                        or upload_file.mimetype.lower() in {"image/heic", "image/heif"}
                    )
                    if heif_claimed and heif_variant is None:
                        shutil.rmtree(asset_root, ignore_errors=True)
                        return jsonify(
                            {
                                "message": (
                                    "The uploaded file is not a supported "
                                    "HEIF/HEIC still image."
                                )
                            }
                        ), 400
                    if heif_variant is not None:
                        if media_type is not MediaType.IMAGE:
                            shutil.rmtree(asset_root, ignore_errors=True)
                            return jsonify(
                                {"message": "HEIF/HEIC content must be uploaded as an image."}
                            ), 400
                        if (
                            probe_heif_page_count(
                                tmp_path,
                                image_loader=DERIVATIVE_PROCESSOR.vips_loader,
                            )
                            != 1
                        ):
                            raise InvalidHeifError(
                                "Multi-image HEIF files are not supported."
                            )
                        classification = replace(
                            classification, original_mime_type=heif_variant[0]
                        )
                    if media_type == MediaType.DOCUMENT:
                        probe_pdf_structure(tmp_path)
                    stored_original = store_original_with_sha256(tmp_path, original_path)
                except InvalidPdfError as exc:
                    shutil.rmtree(asset_root, ignore_errors=True)
                    return jsonify({"message": str(exc)}), 400
                except InvalidHeifError as exc:
                    shutil.rmtree(asset_root, ignore_errors=True)
                    return jsonify({"message": str(exc)}), 400
                except Exception as exc:
                    shutil.rmtree(asset_root, ignore_errors=True)
                    return jsonify({"error": f"Could not store uploaded file: {exc}"}), 500

                try:
                    DERIVATIVE_PROCESSOR.logger = app.logger
                    derivative_result = DERIVATIVE_PROCESSOR.generate(
                        tmp_path,
                        derived_dir,
                        classification,
                    )
                except InvalidPdfError as exc:
                    shutil.rmtree(asset_root, ignore_errors=True)
                    return jsonify({"message": str(exc)}), 400
                except Exception as exc:
                    # The directory is owned exclusively by this upload, so a
                    # failed derivative can be removed without touching others.
                    shutil.rmtree(asset_root, ignore_errors=True)
                    return jsonify({"error": str(exc)}), 500
        except OSError as exc:
            shutil.rmtree(asset_root, ignore_errors=True)
            return jsonify({"error": f"Could not initialize upload workspace: {exc}"}), 500

        out_path = derivative_result.primary
        derivative_name = out_path.name
        thumbnail_by_name = {path.name: path for path in derivative_result.thumbnails}
        thumb128_path = thumbnail_by_name.get("thumb128.jpg")
        thumb256_path = thumbnail_by_name.get("thumb256.jpg")

        # Cantaloupe identifier is the relative path from IMAGE_ROOT
        iiif_id = identifier
        # iiif_base_url is expected to already end with /iiif/3/ (see env default)
        iiif_info_url = f"{iiif_base_url}{iiif_id}/info.json"
        asset_url = f"{media_base_url}asset/{identifier}"
        thumb128_url = f"{asset_url}?derivative=thumb128.jpg"
        thumb256_url = f"{asset_url}?derivative=thumb256.jpg"

        resource_data : dict[str, str | list[str]] = {
            'dcterms:type': classification.dcterms_type,
            'shared:originalName': upload_file.filename,
            'shared:originalMimeType': classification.original_mime_type,
            # For images, serverUrl is the IIIF base; for other media, it is the Caddy base.
            'shared:serverUrl': iiif_base_url if media_type == MediaType.IMAGE else media_base_url,
            # New canonical key
            'shared:assetId': identifier,
            'shared:protocol': classification.protocol,
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
        # Integrity metadata is always server-managed. Assign it after optional
        # client metadata so a multipart field can never spoof the digest.
        resource_data['shared:checksum'] = stored_original.sha256
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
                "originalMimeType": classification.original_mime_type,
                "checksum": stored_original.sha256,
                "derivativeName": derivative_name,
                "mediaType": media_type.value,
                "dctermsType": classification.dcterms_type,
                "protocol": classification.protocol,
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
        """Delete an OLDAP media resource and its local asset files."""
        # Deletion is a mutating upload operation and therefore accepts only a
        # strictly validated OLDAP access token, never a media capability.
        token, _ = require_access_token()
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


    try:
        reconcile_seconds = int(
            os.getenv("OLDAP_IMPORT_CALLBACK_RECONCILE_SECONDS", "0")
        )
    except ValueError:
        reconcile_seconds = 0
        app.logger.error("Import callback reconciliation interval is invalid.")
    if reconcile_seconds > 0:
        try:
            notifier = ImportApiNotifier.from_environment()
            notifier.validate_configuration()
            reconciler = PeriodicCallbackReconciler(
                QUARANTINE_STORE,
                notifier,
                app.logger,
                interval_seconds=reconcile_seconds,
                part_max_age_seconds=int(
                    os.getenv("OLDAP_INGEST_PART_MAX_AGE_SECONDS", "86400")
                ),
            )
            reconciler.start()
            app.extensions["import_callback_reconciler"] = reconciler
            app.logger.info(
                "Import callback reconciliation enabled intervalSeconds=%d",
                reconcile_seconds,
            )
        except (CallbackError, ValueError) as error:
            app.logger.error(
                "Import callback reconciliation unavailable error=%s",
                type(error).__name__,
            )

    return app


# For gunicorn: `gunicorn -b 0.0.0.0:8000 app:app`
app = create_app()
