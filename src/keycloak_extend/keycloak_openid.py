from keycloak.exceptions import KeycloakPostError, raise_error_from_response
from keycloak.urls_patterns import URL_TOKEN
from keycloak import KeycloakOpenID as KOpenID
from keycloak.uma_permissions import build_permission_param


class KeycloakOpenID(KOpenID):
    def __init__(
        self,
        server_url,
        realm_name,
        client_id,
        client_secret_key=None,
        verify=True,
        custom_headers=None,
        proxies=None,
    ):
        super().__init__(
            server_url,
            realm_name,
            client_id,
            client_secret_key,
            verify,
            custom_headers,
            proxies,
        )

    def get_rpt(
        self,
        permission="",
        token="",
    ):
        permission = build_permission_param(permission)

        params_path = {"realm-name": self.realm_name}
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "permission": permission,
            "response_mode": "decision",
            "audience": self.client_id,
        }

        self.connection.add_param_headers("Authorization", "Bearer " + token)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)
