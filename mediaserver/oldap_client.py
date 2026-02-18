from urllib.parse import quote

import requests


class OldapClient:

    def __init__(self, oldap_api_url: str, projectId: str | None = None, token: str | None = None):
        self.oldap_api_url = oldap_api_url
        self.token = token
        self.projectId = projectId

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
        """Resolve a MediaObject by assetId as user 'unknown' (no Authorization header)."""
        id_esc = quote(str(asset_id), safe="")
        url = f"{self.oldap_api_url}/data/mediaobject/id/{id_esc}"

        try:
            response = requests.get(url, timeout=10)
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