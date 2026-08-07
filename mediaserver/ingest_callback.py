"""Durable SIP-stored callback delivery from mediahelper to oldap-api."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from typing import Any, Protocol
from uuid import uuid4

import jwt
import requests

from quarantine import QuarantineStore, UploadReceipt

SERVICE_TOKEN_TYPE = "import-service"
SERVICE_TOKEN_AUDIENCE = "oldap-api-import-service"
DEFAULT_TOKEN_TTL_SECONDS = 60


class CallbackError(RuntimeError):
    """Base class for retryable or rejected callback delivery."""


class CallbackConfigurationError(CallbackError):
    """Raised when service authentication is not safely configured."""


class CallbackUnavailable(CallbackError):
    """Raised when oldap-api cannot be reached or returns an invalid response."""


class CallbackRejected(CallbackError):
    """Raised when oldap-api rejects the retained event."""


class CallbackLogger(Protocol):
    """Minimal privacy-preserving logger boundary used by reconciliation."""

    def info(self, message: str, *args: object) -> None: ...

    def warning(self, message: str, *args: object) -> None: ...


@dataclass(frozen=True, slots=True)
class ImportApiNotifier:
    """Issue a short service JWT and deliver one immutable SIP receipt event."""

    api_base_url: str
    secret: str
    issuer: str = "https://oldap.org"
    subject: str = "media.oldap.org"
    timeout_seconds: float = 10.0
    token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS

    @classmethod
    def from_environment(cls) -> "ImportApiNotifier":
        """Build the notifier from purpose-specific deployment settings."""
        return cls(
            api_base_url=os.getenv("OLDAP_API_URL", "http://localhost:8000").rstrip(
                "/"
            ),
            secret=os.getenv("OLDAP_IMPORT_SERVICE_JWT_SECRET", ""),
            issuer=os.getenv("OLDAP_JWT_ISSUER", "https://oldap.org"),
            subject=os.getenv("OLDAP_IMPORT_SERVICE_SUBJECT", "media.oldap.org"),
            timeout_seconds=float(
                os.getenv("OLDAP_IMPORT_CALLBACK_TIMEOUT_SECONDS", "10")
            ),
        )

    def deliver(
        self,
        receipt: UploadReceipt,
        *,
        session: Any = requests,
        now: datetime | None = None,
    ) -> None:
        """Deliver one retained event and validate API acknowledgement.

        The bearer token is generated per attempt and is never stored. The
        event ID and payload come exclusively from the durable local receipt,
        so retries are byte-for-byte idempotent at the API boundary.
        """
        self.validate_configuration()
        current = now or datetime.now(UTC)
        token = jwt.encode(
            {
                "typ": SERVICE_TOKEN_TYPE,
                "sub": self.subject,
                "jti": str(uuid4()),
                "iat": current,
                "exp": current + timedelta(seconds=self.token_ttl_seconds),
                "iss": self.issuer,
                "aud": SERVICE_TOKEN_AUDIENCE,
            },
            self.secret,
            algorithm="HS256",
        )
        payload = {
            "eventId": receipt.event_id,
            "storedAt": receipt.stored_at.isoformat().replace("+00:00", "Z"),
            "sizeBytes": receipt.size_bytes,
            "sha256": receipt.sha256,
            "uploadRequestId": receipt.upload_request_id,
        }
        try:
            response = session.post(
                f"{self.api_base_url}/internal/imports/{receipt.import_id}/sip-stored",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as error:
            raise CallbackUnavailable("oldap-api callback is unavailable.") from error
        if not 200 <= response.status_code < 300:
            raise CallbackRejected(
                f"oldap-api rejected the callback with HTTP {response.status_code}."
            )
        try:
            acknowledgement = response.json()
        except (TypeError, ValueError) as error:
            raise CallbackUnavailable(
                "oldap-api returned an invalid acknowledgement."
            ) from error
        if (
            not isinstance(acknowledgement, dict)
            or acknowledgement.get("importId") != receipt.import_id
            or acknowledgement.get("state") == "UPLOADING"
        ):
            raise CallbackUnavailable(
                "oldap-api returned a mismatched acknowledgement."
            )

    def validate_configuration(self) -> None:
        """Fail closed when credentials, key separation, or transport are unsafe."""
        if len(self.secret.encode("utf-8")) < 32:
            raise CallbackConfigurationError(
                "OLDAP_IMPORT_SERVICE_JWT_SECRET must contain at least 32 bytes."
            )
        other_secrets = {
            os.getenv("OLDAP_ACCESS_JWT_SECRET"),
            os.getenv("OLDAP_MEDIA_JWT_SECRET"),
            os.getenv("OLDAP_IMPORT_UPLOAD_JWT_SECRET"),
            os.getenv("OLDAP_IMPORT_RECORDS_JWT_SECRET"),
        }
        if self.secret in {value for value in other_secrets if value}:
            raise CallbackConfigurationError(
                "The import service JWT secret must be purpose-specific."
            )
        if not self.api_base_url or not self.subject or self.timeout_seconds <= 0:
            raise CallbackConfigurationError("Import callback settings are invalid.")


def deliver_pending_receipt(
    store: QuarantineStore,
    notifier: ImportApiNotifier,
    receipt: UploadReceipt,
) -> UploadReceipt:
    """Deliver PENDING once and atomically retain DELIVERED afterwards."""
    if receipt.state_notification == "DELIVERED":
        return receipt
    notifier.deliver(receipt)
    return store.mark_notification_delivered(receipt.import_id, receipt.event_id)


def reconcile_pending_receipts(
    store: QuarantineStore,
    notifier: ImportApiNotifier,
    logger: CallbackLogger,
    *,
    limit: int = 100,
) -> tuple[int, int]:
    """Attempt a bounded pending snapshot and return delivered/failed counts."""
    delivered = 0
    failed = 0
    for receipt in store.pending_receipts(limit=limit):
        try:
            deliver_pending_receipt(store, notifier, receipt)
        except CallbackError as error:
            failed += 1
            logger.warning(
                "import_callback_failed importId=%s error=%s",
                receipt.import_id,
                type(error).__name__,
            )
        else:
            delivered += 1
            logger.info(
                "import_callback_delivered importId=%s",
                receipt.import_id,
            )
    return delivered, failed


class PeriodicCallbackReconciler:
    """Small daemon loop for bounded callback retry without a message broker."""

    def __init__(
        self,
        store: QuarantineStore,
        notifier: ImportApiNotifier,
        logger: CallbackLogger,
        *,
        interval_seconds: int,
        part_max_age_seconds: int = 24 * 60 * 60,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("interval_seconds must be positive.")
        if part_max_age_seconds < 1:
            raise ValueError("part_max_age_seconds must be positive.")
        self._store = store
        self._notifier = notifier
        self._logger = logger
        self._interval_seconds = interval_seconds
        self._part_max_age_seconds = part_max_age_seconds
        self._stopped = Event()
        self._thread = Thread(
            target=self._run,
            name="import-callback-reconciler",
            daemon=True,
        )

    def start(self) -> None:
        """Start one daemon thread for this application process."""
        self._thread.start()

    def stop(self) -> None:
        """Request loop termination; primarily useful for controlled tests."""
        self._stopped.set()

    def _run(self) -> None:
        while not self._stopped.wait(self._interval_seconds):
            try:
                reconcile_pending_receipts(
                    self._store,
                    self._notifier,
                    self._logger,
                )
            except Exception as error:
                self._logger.warning(
                    "import_callback_reconciliation_failed error=%s",
                    type(error).__name__,
                )
            try:
                removed = self._store.cleanup_abandoned_parts(
                    max_age_seconds=self._part_max_age_seconds,
                    limit=100,
                )
                if removed:
                    self._logger.info(
                        "import_abandoned_parts_removed count=%d",
                        removed,
                    )
            except Exception as error:
                self._logger.warning(
                    "import_part_cleanup_failed error=%s",
                    type(error).__name__,
                )
