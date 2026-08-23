"""Current OLDAP authorization and protected-inbox verification for mobile uploads."""

from __future__ import annotations

import re
from collections.abc import Mapping
from threading import local
from typing import Any, Protocol
from urllib.parse import quote, unquote

import requests

from mobile_upload_domain import MobileUploadError, ResolvedMobileInbox


PROJECT = "fasnacht"
PROJECT_IDENTIFIERS = frozenset({"fasnacht", "https://fasnacht.digital"})
STAGING_AREA_CLASSES = frozenset(
    {"fasnacht:StagingArea", "http://oldap.org/fasnacht#StagingArea"}
)
STAGING_FOLDER_CLASS = "shared:StagingFolder"
MEMBERSHIP_PROPERTY = "fasnacht:memberOfOrganisation"
LANGUAGE_SUFFIX_RE = re.compile(r"@[A-Za-z][A-Za-z0-9-]*$")


class HttpSession(Protocol):
    """Minimal requests-compatible client surface used by the verifier."""

    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


class OldapMobileStagingVerifier:
    """Resolve one currently permitted, read-only ``top/Mobile`` destination.

    The verifier forwards the user's access token to existing permission-filtered
    OLDAP endpoints. It stores no token and accepts no folder from the mobile
    client. Every initialization, accepted chunk, and commit request invokes this
    boundary so a current permission loss blocks new durable progress.
    """

    def __init__(
        self,
        oldap_api_url: str,
        *,
        session: HttpSession | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.oldap_api_url = oldap_api_url.rstrip("/")
        self._provided_session = session
        self._thread_sessions = local()
        self.timeout_seconds = timeout_seconds

    def verify(
        self, access_token: str, owner_user_id: str, staging_area_id: str
    ) -> ResolvedMobileInbox:
        """Return current destination facts or fail before accepting bytes."""

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        user = self._json(
            "GET", f"/admin/user/{quote(owner_user_id, safe='')}", headers=headers
        )
        self._assert_active_user(user, owner_user_id)

        area = self._json(
            "GET",
            f"/data/{PROJECT}/{quote(staging_area_id, safe='')}",
            headers=headers,
        )
        default_role = self._assert_permitted_area(user, area, staging_area_id)

        folders = self._json(
            "POST",
            f"/data/search/{PROJECT}/class/{quote(STAGING_FOLDER_CLASS, safe='')}",
            headers={**headers, "Content-Type": "application/json"},
            json={
                "includeProperties": [
                    "schema:name",
                    "shared:inStagingArea",
                    "shared:inStagingFolder",
                ],
                "limit": 5000,
                "sortBy": ["schema:name|asc"],
            },
        )
        mobile_folder = self._resolve_mobile_folder(folders, staging_area_id)
        mobile = self._json(
            "GET",
            f"/data/{PROJECT}/{quote(mobile_folder, safe='')}",
            headers=headers,
        )
        self._assert_read_only_policy(mobile, default_role)
        return ResolvedMobileInbox(
            staging_area_id=staging_area_id,
            mobile_folder_id=mobile_folder,
            default_role_id=default_role,
        )

    def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._http_session().request(
                method,
                f"{self.oldap_api_url}{path}",
                timeout=self.timeout_seconds,
                **kwargs,
            )
        except requests.RequestException as error:
            raise MobileUploadError(
                503,
                "oldap_unavailable",
                "OLDAP authorization is temporarily unavailable",
                retryable=True,
            ) from error
        status = int(response.status_code)
        if status == 401:
            raise MobileUploadError(
                401,
                "authentication_invalid",
                "Access token is invalid or expired",
            )
        if status in {403, 404}:
            raise self._destination_unavailable()
        if status < 200 or status >= 300:
            raise MobileUploadError(
                503,
                "oldap_unavailable",
                "OLDAP authorization is temporarily unavailable",
                retryable=True,
            )
        try:
            return response.json()
        except (TypeError, ValueError) as error:
            raise MobileUploadError(
                503,
                "oldap_contract_invalid",
                "OLDAP returned an invalid authorization response",
                retryable=True,
            ) from error

    def _http_session(self) -> HttpSession:
        if self._provided_session is not None:
            return self._provided_session
        session = getattr(self._thread_sessions, "session", None)
        if session is None:
            session = requests.Session()
            self._thread_sessions.session = session
        return session

    @staticmethod
    def _assert_active_user(value: Any, owner_user_id: str) -> None:
        user = _object(value)
        if (
            user is None
            or user.get("userId") != owner_user_id
            or user.get("isActive") is not True
            or user.get("userclass") != "fasnacht:FasnachtUser"
            or not _has_create_permission(user)
        ):
            raise OldapMobileStagingVerifier._destination_unavailable()

    @staticmethod
    def _assert_permitted_area(
        user_value: Any, area_value: Any, staging_area_id: str
    ) -> str:
        user = _object(user_value)
        area = _object(area_value)
        if user is None or area is None:
            raise OldapMobileStagingVerifier._destination_unavailable()
        resource_types = set(_values(area, "rdf:type"))
        if not resource_types.intersection(STAGING_AREA_CLASSES):
            raise OldapMobileStagingVerifier._destination_unavailable()
        returned_id = _first(area, "iri")
        if returned_id and not _same_identifier(returned_id, staging_area_id):
            raise OldapMobileStagingVerifier._destination_unavailable()
        organisation = _first(area, "fasnacht:depositingOrganisation")
        default_role = _first(area, "shared:stagingDefaultRole")
        additional = _object(user.get("additionalProperties")) or {}
        memberships = _values(additional, MEMBERSHIP_PROPERTY)
        roles = _object(user.get("hasRole")) or {}
        if (
            not organisation
            or not default_role
            or not _matches_any(organisation, memberships)
            or not _mapping_has_identifier(roles, default_role)
        ):
            raise OldapMobileStagingVerifier._destination_unavailable()
        return default_role

    @staticmethod
    def _resolve_mobile_folder(value: Any, staging_area_id: str) -> str:
        if not isinstance(value, list):
            raise MobileUploadError(
                503,
                "oldap_contract_invalid",
                "OLDAP returned an invalid folder response",
                retryable=True,
            )
        folders = [folder for folder in (_object(item) for item in value) if folder]
        area_folders = [
            folder
            for folder in folders
            if _same_identifier(_first(folder, "shared:inStagingArea"), staging_area_id)
        ]
        top: list[Mapping[str, Any]] = []
        for folder in area_folders:
            name = _literal_text(_first(folder, "schema:name"))
            parent = _first(folder, "shared:inStagingFolder")
            if name.casefold() == "top":
                if name != "top" or parent:
                    raise OldapMobileStagingVerifier._destination_unavailable()
                top.append(folder)
        if len(top) != 1:
            raise OldapMobileStagingVerifier._destination_unavailable()
        top_id = _first(top[0], "iri")
        if not top_id:
            raise OldapMobileStagingVerifier._destination_unavailable()

        mobile: list[Mapping[str, Any]] = []
        for folder in area_folders:
            name = _literal_text(_first(folder, "schema:name"))
            if name.casefold() != "mobile":
                continue
            if name != "Mobile" or not _same_identifier(
                _first(folder, "shared:inStagingFolder"), top_id
            ):
                raise OldapMobileStagingVerifier._destination_unavailable()
            mobile.append(folder)
        if len(mobile) != 1:
            raise OldapMobileStagingVerifier._destination_unavailable()
        mobile_id = _first(mobile[0], "iri")
        if not mobile_id:
            raise OldapMobileStagingVerifier._destination_unavailable()
        return mobile_id

    @staticmethod
    def _assert_read_only_policy(value: Any, default_role: str) -> None:
        folder = _object(value)
        if folder is None:
            raise OldapMobileStagingVerifier._destination_unavailable()
        roles = _object(
            folder.get("oldap:attachedToRole", folder.get("attachedToRole"))
        )
        if roles is None or len(roles) != 1:
            raise OldapMobileStagingVerifier._destination_unavailable()
        role, permission = next(iter(roles.items()))
        if (
            not _same_identifier(str(role), default_role)
            or _permission(permission) != "DATA_VIEW"
        ):
            raise OldapMobileStagingVerifier._destination_unavailable()

    @staticmethod
    def _destination_unavailable() -> MobileUploadError:
        return MobileUploadError(
            403,
            "mobile_destination_unavailable",
            "The protected mobile destination is unavailable",
        )


def _object(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _values(value: Mapping[str, Any], key: str) -> list[str]:
    raw = value.get(key)
    values = raw if isinstance(raw, list) else [raw]
    return [
        str(item).strip() for item in values if item is not None and str(item).strip()
    ]


def _first(value: Mapping[str, Any], key: str) -> str:
    return (_values(value, key) or [""])[0]


def _literal_text(value: str) -> str:
    return LANGUAGE_SUFFIX_RE.sub("", value).strip()


def _comparable(value: str) -> tuple[str, ...]:
    stripped = value.strip()
    decoded = unquote(stripped)
    return (stripped,) if decoded == stripped else (stripped, decoded)


def _same_identifier(left: str, right: str) -> bool:
    return bool(set(_comparable(left)).intersection(_comparable(right)))


def _matches_any(value: str, candidates: list[str]) -> bool:
    return any(_same_identifier(value, candidate) for candidate in candidates)


def _mapping_has_identifier(value: Mapping[str, Any], identifier: str) -> bool:
    matches = [key for key in value if _same_identifier(str(key), identifier)]
    return len(matches) == 1


def _permission(value: Any) -> str:
    return str(value or "").split(":")[-1].upper()


def _has_create_permission(user: Mapping[str, Any]) -> bool:
    projects = user.get("inProjects")
    if not isinstance(projects, list):
        return False
    for raw in projects:
        project = _object(raw)
        if project is None or not _matches_any(
            str(project.get("project", "")), list(PROJECT_IDENTIFIERS)
        ):
            continue
        permissions = project.get("permissions")
        if isinstance(permissions, list) and any(
            _permission(permission) == "ADMIN_CREATE" for permission in permissions
        ):
            return True
    return False
