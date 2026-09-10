"""Purpose-bound transport for OLDAP mobile-media lifecycle outbox work."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Protocol

import jwt
import requests

from mobile_upload_domain import canonical_checksum, canonical_uuid, parse_timestamp

TOKEN_TYPE = "mobile-media-service"
TOKEN_PURPOSE = "mobile-media-lifecycle"
TOKEN_AUDIENCE = "oldap-api-mobile-media-lifecycle"
TOKEN_SUBJECT = "oldap-mediaserver"
TOKEN_LIFETIME_SECONDS = 120
WORKER_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
LIFECYCLE_KINDS = frozenset({"moved", "staging_deleted", "archived"})


class HttpSession(Protocol):
    def post(self, url: str, **kwargs: Any) -> Any: ...


class MobileMediaLifecycleTransportError(RuntimeError):
    """Keep an outbox claim pending after an unavailable or invalid response."""


@dataclass(frozen=True, slots=True)
class MobileMediaLifecycleEvent:
    """Closed immutable event leased from the authoritative OLDAP outbox."""

    event_id: str
    claim_id: str
    worker_id: str
    kind: str
    upload_id: str
    client_asset_id: str
    owner_user_iri: str
    staging_area_id: str
    resource_iri: str
    checksum: str
    occurred_at: datetime
    lease_expires_at: datetime


class OldapMobileMediaLifecycleClient:
    """Claim and acknowledge lifecycle events with a short-lived purpose JWT."""

    def __init__(
        self,
        oldap_api_url: str,
        signing_secret: str,
        *,
        issuer: str = "https://oldap.org",
        session: HttpSession | None = None,
        timeout_seconds: float = 30.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(signing_secret.encode("utf-8")) < 32:
            raise RuntimeError(
                "OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET must contain at least 32 bytes."
            )
        self.oldap_api_url = oldap_api_url.rstrip("/")
        self.signing_secret = signing_secret
        self.issuer = issuer
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    @classmethod
    def from_environment(cls) -> "OldapMobileMediaLifecycleClient":
        return cls(
            os.getenv("OLDAP_API_URL", "http://localhost:8000"),
            os.getenv("OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET", ""),
            issuer=os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
        )

    def claim(self, worker_id: str) -> MobileMediaLifecycleEvent | None:
        if WORKER_ID_RE.fullmatch(worker_id) is None:
            raise ValueError("Lifecycle workerId is invalid.")
        response = self._post(
            "/internal/mobile-media/v1/lifecycle-events/claims",
            payload={"workerId": worker_id},
        )
        if response.status_code == 204:
            return None
        if response.status_code != 200:
            raise MobileMediaLifecycleTransportError("Lifecycle claim failed.")
        try:
            return _event(response.json(), expected_worker_id=worker_id)
        except (KeyError, TypeError, ValueError) as error:
            raise MobileMediaLifecycleTransportError(
                "Lifecycle claim response is invalid."
            ) from error

    def complete(self, event: MobileMediaLifecycleEvent) -> None:
        response = self._post(
            f"/internal/mobile-media/v1/lifecycle-events/{event.event_id}/complete",
            payload={"claimId": event.claim_id, "workerId": event.worker_id},
        )
        if response.status_code != 200:
            raise MobileMediaLifecycleTransportError(
                "Lifecycle completion acknowledgement failed."
            )
        try:
            value = response.json()
        except (TypeError, ValueError) as error:
            raise MobileMediaLifecycleTransportError(
                "Lifecycle completion response is invalid."
            ) from error
        if value != {"eventId": event.event_id, "state": "delivered"}:
            raise MobileMediaLifecycleTransportError(
                "Lifecycle completion response is contradictory."
            )

    def _post(self, path: str, *, payload: dict[str, str]):
        try:
            return self.session.post(
                f"{self.oldap_api_url}{path}",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self._token()}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as error:
            raise MobileMediaLifecycleTransportError(
                "Lifecycle transport is unavailable."
            ) from error

    def _token(self) -> str:
        now = self._clock().astimezone(UTC)
        return jwt.encode(
            {
                "typ": TOKEN_TYPE,
                "purpose": TOKEN_PURPOSE,
                "sub": TOKEN_SUBJECT,
                "aud": TOKEN_AUDIENCE,
                "iss": self.issuer,
                "iat": int(now.timestamp()),
                "exp": int(
                    (now + timedelta(seconds=TOKEN_LIFETIME_SECONDS)).timestamp()
                ),
            },
            self.signing_secret,
            algorithm="HS256",
        )


def _event(value: Any, *, expected_worker_id: str) -> MobileMediaLifecycleEvent:
    required = {
        "eventId",
        "claimId",
        "workerId",
        "kind",
        "uploadId",
        "clientAssetId",
        "ownerUserIri",
        "stagingAreaId",
        "resourceIri",
        "checksum",
        "occurredAt",
        "leaseExpiresAt",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Lifecycle event fields are invalid.")
    event = MobileMediaLifecycleEvent(
        event_id=canonical_uuid(value["eventId"], "eventId"),
        claim_id=canonical_uuid(value["claimId"], "claimId"),
        worker_id=str(value["workerId"]),
        kind=str(value["kind"]),
        upload_id=canonical_uuid(value["uploadId"], "uploadId"),
        client_asset_id=canonical_uuid(value["clientAssetId"], "clientAssetId"),
        owner_user_iri=str(value["ownerUserIri"]),
        staging_area_id=str(value["stagingAreaId"]),
        resource_iri=str(value["resourceIri"]),
        checksum=canonical_checksum(value["checksum"]),
        occurred_at=parse_timestamp(value["occurredAt"]),
        lease_expires_at=parse_timestamp(value["leaseExpiresAt"]),
    )
    if (
        event.worker_id != expected_worker_id
        or event.kind not in LIFECYCLE_KINDS
        or not event.owner_user_iri
        or not event.staging_area_id
        or not event.resource_iri
        or event.lease_expires_at <= event.occurred_at
    ):
        raise ValueError("Lifecycle event is contradictory.")
    return event
