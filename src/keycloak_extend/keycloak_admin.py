import json
from keycloak.exceptions import KeycloakGetError, raise_error_from_response
from keycloak import KeycloakAdmin as KAdmin
from keycloak.urls_patterns import (
    URL_ADMIN_CLIENT_ROLES,
    URL_ADMIN_USER_CLIENT_ROLES,
)

from keycloak_extend.url_patterns import (
    URL_ADMIN_CLIENT_RESOURCE,
    URL_ADMIN_CLIENT_RESOURCE_SCOPE,
    URL_ADMIN_CLIENT_ROLE_POLICY,
    URL_ADMIN_CLIENT_SETTINGS,
    URL_ADMIN_PERMISSION,
    URL_ADMIN_PERMISSION_ASSOCIATED_POLICIES,
    URL_ADMIN_POLICY,
    URL_ADMIN_POLICY_PERMISSIONS,
    URL_ADMIN_RESOURCE_PERMISSION,
    URL_ADMIN_SCOPE_PERMISSION,
    URL_ADMIN_USER_POLICY,
)


class KeycloakAdmin(KAdmin):
    def __init__(
        self,
        server_url,
        username=None,
        password=None,
        realm_name="master",
        client_id="admin-cli",
        verify=True,
        client_secret_key=None,
        custom_headers=None,
        user_realm_name=None,
        auto_refresh_token=None,
    ):
        auto_refresh_token = ["get", "put", "post", "delete"]
        super().__init__(
            server_url=server_url,
            username=username,
            password=password,
            realm_name=realm_name,
            client_id=client_id,
            verify=verify,
            client_secret_key=client_secret_key,
            custom_headers=custom_headers,
            user_realm_name=user_realm_name,
            auto_refresh_token=auto_refresh_token,
        )

    def update_client_auth_settings(self, client_id, payload):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_put(URL_ADMIN_CLIENT_SETTINGS.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def update_client_resource(self, client_id, resource_id, payload, skip_exists=False):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_put(
            URL_ADMIN_CLIENT_RESOURCE.format(**params_path) + f"/{resource_id}",
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204], skip_exists=skip_exists)

    def delete_client_resource(self, client_id, resource_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_CLIENT_RESOURCE.format(**params_path) + f"/{resource_id}")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_client_resource_scope(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_post(
            URL_ADMIN_CLIENT_RESOURCE_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def create_client_role_policy(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_post(URL_ADMIN_CLIENT_ROLE_POLICY.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def create_user_policy(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_post(URL_ADMIN_USER_POLICY.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def delete_policy(self, client_id, policy_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_POLICY.format(**params_path) + f"/{policy_id}")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_scope_permission(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_post(URL_ADMIN_SCOPE_PERMISSION.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_scope_permission(self, client_id, permission_id, payload):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_put(
            URL_ADMIN_SCOPE_PERMISSION.format(**params_path) + f"/{permission_id}",
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def create_resource_permission(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_post(
            URL_ADMIN_RESOURCE_PERMISSION.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def delete_permission(self, client_id, permission_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_PERMISSION.format(**params_path) + f"/{permission_id}")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_policies_by_name(self, client_id, name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(
            URL_ADMIN_POLICY.format(**params_path) + f"?first=0&max=20&name={name}&permission=false"
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_policies(self, client_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_USER_POLICY.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_policy_id(self, client_id, policy_name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(
            URL_ADMIN_USER_POLICY.format(**params_path) + f"?first=0&max=1&name={policy_name}&permission=false"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_role_policies(self, client_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_ROLE_POLICY.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_role_policy_id(self, client_id, policy_name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(
            URL_ADMIN_CLIENT_ROLE_POLICY.format(**params_path) + f"?first=0&max=1&name={policy_name}&permission=false"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_client_resource_scopes(self, client_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_RESOURCE_SCOPE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_resource_scope_id(self, client_id, scope_name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(
            URL_ADMIN_CLIENT_RESOURCE_SCOPE.format(**params_path) + f"?first=0&max=1&name={scope_name}"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_client_resources(self, client_id):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_CLIENT_RESOURCE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_resource_id(self, client_id, resource_name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(
            URL_ADMIN_CLIENT_RESOURCE.format(**params_path) + f"?first=0&max=1&name={resource_name}"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("_id")
        else:
            data_raw = None
        return data_raw

    def get_policy_dependent_permissions(self, client_id, policy_id):
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.raw_get(URL_ADMIN_POLICY_PERMISSIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_permissions_associated_policies(self, client_id, permission_id):
        params_path = {
            "realm-name": self.realm_name,
            "id": client_id,
            "permission-id": permission_id,
        }
        data_raw = self.raw_get(URL_ADMIN_PERMISSION_ASSOCIATED_POLICIES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_permissions_by_name(self, client_id, name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_PERMISSION.format(**params_path) + f"?first=0&max=20&name={name}")
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_permission_id(self, client_id, name):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        data_raw = self.raw_get(URL_ADMIN_PERMISSION.format(**params_path) + f"?first=0&max=1&name={name}")
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_client_roles(self, client_id, name, max=20, first=0, limit=True):
        params_path = {"realm-name": self.realm_name, "id": client_id}
        query = f"?first={first}&max={max}&search={name}" if limit else f"?search={name}"
        data_raw = self.raw_get(URL_ADMIN_CLIENT_ROLES.format(**params_path) + query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_assign_client_role(self, user_id, client_id, roles):
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = self.raw_delete(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_client_role_payload(self, name):
        return {"name": name}

    def create_affirmative_positive_role_policy_payload(self, name, role_id):
        return {
            "type": "role",
            "decisionStrategy": "AFFIRMATIVE",
            "logic": "POSITIVE",
            "name": name,
            "roles": [{"id": role_id, "required": True}],
        }

    def create_affirmative_positive_user_policy_payload(self, name, user_id):
        return {
            "type": "user",
            "decisionStrategy": "AFFIRMATIVE",
            "logic": "POSITIVE",
            "name": name,
            "users": [user_id],
        }

    def create_resource_payload(self, name, scopes=[]):
        return {"scopes": scopes, "name": name, "displayName": name}

    def create_resource_scope_payload(self, name):
        return {"name": name}

    def create_affirmative_positive_scope_permission_payload(self, name, resources=[], scopes=[], policies=[]):
        policies = [policy for policy in policies if policy is not None]
        return {
            "type": "scope",
            "logic": "POSITIVE",
            "decisionStrategy": "AFFIRMATIVE",
            "name": name,
            "scopes": scopes,
            "policies": policies,
            **({"resources": resources} if resources is not None and len(resources) != 0 else {}),
        }
