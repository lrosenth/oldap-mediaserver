import requests


class OldapClient:

    def __init__(self, oldap_api_url: str, projectId: str, token: str | None = None):
        self.oldap_api_url = oldap_api_url
        self.token = token
        self.projectId = projectId
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