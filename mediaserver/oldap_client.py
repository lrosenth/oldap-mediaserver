from urllib.parse import quote

import os, time, threading
import jwt
import requests


class OldapClient:
    # ------------------------------------------------------------------
    # Unknown-user token cache (process-local)
    # ------------------------------------------------------------------
    _unknown_token: str | None = None
    _unknown_token_exp: float = 0.0  # unix timestamp (seconds)
    _unknown_token_lock = threading.Lock()

    @classmethod
    def _get_unknown_token(cls, oldap_api_url: str) -> str:
        """Login as the configured unknown user and return a Bearer token.

        Endpoint: POST {oldap_api_url}/admin/auth/{userId}
        Body: {"password": "..."}
        Response: {"token": "..."}  (plus optional message)
        """
        now = time.time()
        with cls._unknown_token_lock:
            # 1) If we already have a token and it is still valid -> reuse it.
            if cls._unknown_token is not None:
                if cls._unknown_token_exp > now:
                    return cls._unknown_token
                # Token is present but expired -> clear and re-login.
                cls._unknown_token = None
                cls._unknown_token_exp = 0.0

            userid = os.environ.get("OLDAP_UNKNOWN_USERID", "unknown")
            password = os.environ.get("OLDAP_UNKNOWN_PASSWORD", "")

            login_url = f"{oldap_api_url}/admin/auth/{quote(userid)}"
            resp = requests.post(login_url, json={"password": password}, timeout=10)
            resp.raise_for_status()

            data = resp.json()
            if not isinstance(data, dict) or "token" not in data:
                raise RuntimeError("oldap-api login returned unexpected payload (expected JSON with 'token')")

            token = str(data["token"]).strip()
            if not token:
                raise RuntimeError("oldap-api login returned empty token")

            # Determine cache expiry
            exp_ts = now + 300.0  # default: 5 minutes
            try:
                claims = jwt.decode(token, options={"verify_signature": False})
                exp = claims.get("exp")
                if isinstance(exp, (int, float)):
                    exp_ts = float(exp) - 30.0  # refresh a bit early
            except Exception:
                pass

            cls._unknown_token = token
            cls._unknown_token_exp = exp_ts
            return token

    @classmethod
    def clear_unknown_token_cache(cls) -> None:
        with cls._unknown_token_lock:
            cls._unknown_token = None
            cls._unknown_token_exp = 0.0

    def __init__(self, oldap_api_url: str, projectId: str | None = None, token: str | None = None):
        self.oldap_api_url = oldap_api_url
        self.token = token
        self.projectId = projectId

        if self.token is None:
            self.token = self._get_unknown_token(self.oldap_api_url)

        self.project = None
        if self.projectId is not None:
            headers = {'Authorization': f'Bearer {self.token}'} if self.token else {}
            try:
                response = requests.get(f'{oldap_api_url}/admin/project/{self.projectId}',
                                        headers=headers,
                                        timeout=5)
            except requests.exceptions.Timeout as exc:
                raise RuntimeError(f"Could not connect to oldap: {exc}") from exc
            except requests.exceptions.RequestException as exc:
                raise RuntimeError(f"Could not connect to oldap: {exc}") from exc
            response.raise_for_status()
            self.project = response.json()

    def create_resource(self, resource: str, resource_data: dict) -> dict:
        headers = {'Authorization': f'Bearer {self.token}'} if self.token else {}
        response = requests.put(f'{self.oldap_api_url}/data/{self.projectId}/{resource}',
                                json=resource_data,
                                headers=headers,
                                timeout=5)
        response.raise_for_status()
        return response.json()

    def get_mediaobject_by_assetid_unknown(self, asset_id: str) -> dict:
        """Resolve a MediaObject by assetId using the cached unknown-user token."""
        id_esc = quote(str(asset_id), safe="")
        url = f"{self.oldap_api_url}/data/mediaobject/id/{id_esc}"

        def _do_get() -> requests.Response:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            return requests.get(url, headers=headers, timeout=10)

        try:
            response = _do_get()
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(f"Could not connect to oldap: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Could not connect to oldap: {exc}") from exc

        # If the cached unknown-token expired (or was revoked), refresh once and retry.
        if response.status_code == 401:
            OldapClient.clear_unknown_token_cache()
            self.token = self._get_unknown_token(self.oldap_api_url)
            try:
                response = _do_get()
            except requests.exceptions.Timeout as exc:
                raise RuntimeError(f"Could not connect to oldap: {exc}") from exc
            except requests.exceptions.RequestException as exc:
                raise RuntimeError(f"Could not connect to oldap: {exc}") from exc

        if response.status_code == 404:
            return None

        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError("oldap-api returned unexpected payload")
        return data