"""Flask transport for the additive, unrouted mobile media upload v1 API."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from flask import Blueprint, Flask, Response, g, jsonify, request
from werkzeug.exceptions import BadRequest

from mobile_staging import OldapMobileStagingVerifier
from mobile_upload_domain import (
    MobileAccessIdentity,
    MobileUploadError,
    MobileUploadInvariantError,
    canonical_uuid,
    has_control,
    parse_commit_upload,
    parse_initialize_upload,
)
from mobile_upload_registry import MobileUploadRegistry


MAX_JSON_BYTES = 64 * 1024


def register_mobile_upload_routes(
    app: Flask,
    registry: MobileUploadRegistry,
    authenticate: Callable[[str], MobileAccessIdentity],
    verifier: OldapMobileStagingVerifier,
) -> None:
    """Register `/media/v1` without changing legacy upload or public routing."""

    blueprint = Blueprint("mobile_upload_v1", __name__, url_prefix="/media/v1")

    @blueprint.before_request
    def establish_trace() -> None:
        g.mobile_upload_trace_id = str(uuid4())

    @blueprint.errorhandler(MobileUploadError)
    def mobile_problem(error: MobileUploadError):
        return _problem_response(error)

    @blueprint.errorhandler(MobileUploadInvariantError)
    @blueprint.errorhandler(sqlite3.Error)
    @blueprint.errorhandler(OSError)
    def mobile_service_failure(error: Exception):
        app.logger.error(
            "mobile_upload_failure traceId=%s error=%s",
            _trace_id(),
            type(error).__name__,
        )
        return _problem_response(
            MobileUploadError(
                503,
                "upload_service_unavailable",
                "Upload service is temporarily unavailable",
                retryable=True,
            )
        )

    @blueprint.post("/uploads")
    def initialize_upload():
        token, owner = _authenticate(authenticate)
        _require_client_headers()
        idempotency_key = _required_header("Idempotency-Key")
        canonical_uuid(idempotency_key, "Idempotency-Key")
        value = _json_body()
        parsed = parse_initialize_upload(
            value, max_original_bytes=registry.limits.max_original_bytes
        )
        destination = verifier.verify(token, owner.user_id, parsed.staging_area_id)
        status, created = registry.initialize(
            owner, parsed, destination, idempotency_key
        )
        response = jsonify(status.to_dict())
        response.status_code = 201 if created else 200
        if created:
            response.headers["Location"] = f"/media/v1/uploads/{status.upload_id}"
        return _no_store(response)

    @blueprint.get("/uploads/<upload_id>")
    def upload_status(upload_id: str):
        _, owner = _authenticate(authenticate)
        _require_client_headers()
        status = registry.get_status(upload_id, owner)
        return _no_store(jsonify(status.to_dict()))

    @blueprint.patch("/uploads/<upload_id>")
    def append_upload_chunk(upload_id: str):
        token, owner = _authenticate(authenticate)
        _require_client_headers()
        if request.mimetype != "application/offset+octet-stream":
            raise MobileUploadError(
                415,
                "chunk_media_type_required",
                "Content-Type must be application/offset+octet-stream",
            )
        offset = _non_negative_header("Upload-Offset")
        upload_length = _non_negative_header("Upload-Length", minimum=1)
        current = registry.get_status(upload_id, owner)
        destination = verifier.verify(token, owner.user_id, current.staging_area_id)
        chunk = _bounded_chunk(registry.limits.chunk_bytes)
        status = registry.append_chunk(
            upload_id,
            owner,
            expected_offset=offset,
            upload_length=upload_length,
            chunk=chunk,
            destination=destination,
        )
        response = Response(status=204)
        response.headers["Upload-Offset"] = str(status.offset)
        return _no_store(response)

    @blueprint.post("/uploads/<upload_id>/commit")
    def commit_upload(upload_id: str):
        token, owner = _authenticate(authenticate)
        _require_client_headers()
        idempotency_key = _required_header("Idempotency-Key")
        canonical_uuid(idempotency_key, "Idempotency-Key")
        parsed = parse_commit_upload(
            _json_body(), max_original_bytes=registry.limits.max_original_bytes
        )
        current = registry.get_status(upload_id, owner)
        destination = verifier.verify(token, owner.user_id, current.staging_area_id)
        status, committed = registry.request_commit(
            upload_id, owner, parsed, destination, idempotency_key
        )
        if committed:
            response = jsonify(status.committed_result())
            response.status_code = 200
        else:
            response = jsonify(status.to_dict())
            response.status_code = 202
            response.headers["Retry-After"] = "2"
        return _no_store(response)

    @blueprint.delete("/uploads/<upload_id>")
    def cancel_upload(upload_id: str):
        _, owner = _authenticate(authenticate)
        _require_client_headers()
        registry.cancel(upload_id, owner)
        return _no_store(Response(status=204))

    app.register_blueprint(blueprint)


def _authenticate(
    authenticate: Callable[[str], MobileAccessIdentity],
) -> tuple[str, MobileAccessIdentity]:
    header = request.headers.get("Authorization", "")
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise MobileUploadError(
            401,
            "authentication_required",
            "Bearer access token is required",
        )
    return parts[1], authenticate(parts[1])


def _require_client_headers() -> None:
    app_version = _required_header("X-App-Version")
    if len(app_version) > 100 or has_control(app_version):
        raise MobileUploadError(400, "invalid_app_version", "Invalid X-App-Version")
    if _required_header("X-Platform") not in {"ios", "android"}:
        raise MobileUploadError(400, "invalid_platform", "Invalid X-Platform")
    canonical_uuid(_required_header("X-Device-Id"), "X-Device-Id")


def _required_header(name: str) -> str:
    value = request.headers.get(name, "").strip()
    if not value:
        raise MobileUploadError(
            400,
            "missing_required_header",
            f"{name} header is required",
        )
    return value


def _non_negative_header(name: str, *, minimum: int = 0) -> int:
    raw = _required_header(name)
    code = f"invalid_{name.lower().replace('-', '_')}"
    if len(raw) > 20 or not raw.isascii() or not raw.isdigit():
        raise MobileUploadError(400, code, f"Invalid {name}")
    value = int(raw)
    if value < minimum:
        raise MobileUploadError(400, code, f"Invalid {name}")
    return value


def _json_body() -> Any:
    if request.mimetype != "application/json":
        raise MobileUploadError(
            415,
            "json_media_type_required",
            "Content-Type must be application/json",
        )
    if request.content_length is not None and request.content_length > MAX_JSON_BYTES:
        raise MobileUploadError(413, "request_too_large", "JSON request is too large")
    try:
        raw = request.stream.read(MAX_JSON_BYTES + 1)
    except (BadRequest, OSError) as error:
        raise MobileUploadError(
            400, "invalid_json", "Request body is not valid JSON"
        ) from error
    if len(raw) > MAX_JSON_BYTES:
        raise MobileUploadError(413, "request_too_large", "JSON request is too large")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MobileUploadError(
            400, "invalid_json", "Request body is not valid JSON"
        ) from error


def _bounded_chunk(maximum_bytes: int) -> bytes:
    if request.content_length is not None and request.content_length > maximum_bytes:
        raise MobileUploadError(
            413, "chunk_too_large", "Chunk exceeds the v1 chunk size"
        )
    try:
        chunk = request.stream.read(maximum_bytes + 1)
    except (BadRequest, OSError) as error:
        raise MobileUploadError(
            400,
            "chunk_read_failed",
            "Chunk body could not be read",
            retryable=True,
        ) from error
    if len(chunk) > maximum_bytes:
        raise MobileUploadError(
            413, "chunk_too_large", "Chunk exceeds the v1 chunk size"
        )
    return chunk


def _problem_response(error: MobileUploadError):
    value: dict[str, object] = {
        "type": f"https://oldap.org/problems/mobile/{error.code.replace('_', '-')}",
        "title": error.title,
        "status": error.status,
        "code": error.code,
        "traceId": _trace_id(),
        "retryable": error.retryable,
    }
    if error.detail:
        value["detail"] = error.detail
    if error.retry_after_seconds is not None:
        value["retryAfterSeconds"] = error.retry_after_seconds
    if error.upload_offset is not None:
        value["uploadOffset"] = error.upload_offset
    if error.field_errors:
        value["fieldErrors"] = error.field_errors
    response = jsonify(value)
    response.status_code = error.status
    response.content_type = "application/problem+json"
    response.headers["Cache-Control"] = "no-store"
    if error.status == 401:
        response.headers["WWW-Authenticate"] = "Bearer"
    if error.retry_after_seconds is not None:
        response.headers["Retry-After"] = str(error.retry_after_seconds)
    if error.upload_offset is not None:
        response.headers["Upload-Offset"] = str(error.upload_offset)
    return response


def _trace_id() -> str:
    return str(getattr(g, "mobile_upload_trace_id", uuid4()))


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response
