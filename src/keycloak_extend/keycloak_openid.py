from keycloak.exceptions import KeycloakGetError, raise_error_from_response
from keycloak.urls_patterns import URL_TOKEN
from keycloak import KeycloakOpenID as KOpenID


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
        audience="",
        grant_type="urn:ietf:params:oauth:grant-type:uma-ticket",
        permission="",
        token="",
        response_mode="",
        **extra,
    ):
        if token:
            self.connection.add_param_headers("Authorization", token)
        params_path = {"realm-name": self.realm_name}
        payload = {
            "audience": audience,
            "permission": permission,
            "response_mode": response_mode,
            "client_id": self.client_id,
            "grant_type": grant_type,
        }
        if extra:
            payload.update(extra)

        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)
