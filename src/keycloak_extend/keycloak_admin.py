import json
import logging
from typing import Any, Dict, Optional
from keycloak.exceptions import KeycloakGetError, KeycloakError, raise_error_from_response
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

from .exceptions import (
    AuthError,
    UserExistsError,
    UsernameExistsError,
    EmailExistsError,
    ValidationError,
    ClientConfigurationError,
    AccountLockedError,
)


def parse_keycloak_error(keycloak_error: KeycloakError, user_payload: dict) -> AuthError:
    """
    Translates a raw KeycloakError into a specific, structured AuthError.
    
    This function centralizes all error parsing logic.
    """
    response_code = keycloak_error.response_code
    response_body = keycloak_error.response_body
    
    try:
        data = json.loads(response_body)
        error_message = data.get('errorMessage') or data.get('error_description') or str(keycloak_error)
        error_code = data.get('errorMessage') or data.get('error')
    except (json.JSONDecodeError, AttributeError):
        data = {}
        error_message = str(keycloak_error)
        error_code = None

    # 409 Conflict -> UserExistsError
    if response_code == 409:
        msg_lower = error_message.lower()
        if 'username' in msg_lower:
            return UsernameExistsError(
                username=user_payload.get('username'),
                message=error_message,
                original_error=keycloak_error
            )
        if 'email' in msg_lower:
            return EmailExistsError(
                email=user_payload.get('email'),
                message=error_message,
                original_error=keycloak_error
            )
        # Fallback for generic 409
        return UserExistsError(error_message, original_error=keycloak_error)

    # 400 Bad Request -> ValidationError
    if response_code == 400:
        return ValidationError(
            message=error_message,
            field=data.get('field'),
            error_code=error_code,
            params=data.get('params', []),
            original_error=keycloak_error
        )

    # 401/403 -> Client Configuration Error
    if response_code in [401, 403]:
        return ClientConfigurationError(
            f"Client configuration or permission error: {error_message}",
            original_error=keycloak_error
        )

    # Default to a generic AuthError for anything else
    return AuthError(
        f"An unexpected Keycloak error occurred (Status: {response_code}): {error_message}",
        original_error=keycloak_error
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
        logger=None,
    ):
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
        )

        if logger is None:
            logger = logging.getLogger(__file__)

        self.logger = logger

    # --- Enhanced user creation with domain error translation ---
    def create_user(self, payload, exist_ok: bool = False):  # type: ignore[override]
        try:
            # Delegate exist_ok handling directly to the parent class.
            # The parent will swallow the 409 error and return None if exist_ok is True.
            return super().create_user(payload, exist_ok=exist_ok)
        except KeycloakError as e:
            # If an error still occurs (i.e., not a 409 that was swallowed),
            # translate it into our specific domain error and raise it.
            self.logger.error(e)
            auth_error = parse_keycloak_error(e, payload)
            raise auth_error from e

    def check_account_locked(self, username: str) -> None:
        """
        Check if an account is locked due to brute force protection and raise AccountLockedError if so.

        Args:
            username: The username to check
            
        Raises:
            AccountLockedError: If the account is locked due to brute force protection
        """
        try:
            user_id = self.get_user_id(username)
            print(f"DEBUG: User ID for {username}: {user_id}")
            if user_id:
                brute_force_status = self.get_bruteforce_detection_status(user_id)
                print(f"DEBUG: Brute force status: {brute_force_status}")
                if brute_force_status and brute_force_status.get('disabled', False):
                    print(f"DEBUG: Account {username} is locked, raising AccountLockedError")
                    raise AccountLockedError(
                        username=username,
                        message=f"Account '{username}' is temporarily locked due to too many failed login attempts"
                    )
                else:
                    print(f"DEBUG: Account {username} is not locked")
            else:
                print(f"DEBUG: User {username} not found")
        except AccountLockedError:
            # Re-raise the AccountLockedError
            print(f"DEBUG: Caught AccountLockedError, re-raising")
            raise
        except Exception as e:
            # If we can't check the brute force status, we don't want to fail the authentication
            # The regular Keycloak error handling will take care of it
            print(f"DEBUG: Caught other exception: {type(e).__name__}: {e}")
            pass

    def update_client_auth_settings(self, client_id, payload):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(URL_ADMIN_CLIENT_SETTINGS.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def update_client_resource(self, client_id, resource_id, payload, skip_exists=False):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            URL_ADMIN_CLIENT_RESOURCE.format(**params_path) + f"/{resource_id}",
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204], skip_exists=skip_exists)

    def delete_client_resource(self, client_id, resource_id):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_CLIENT_RESOURCE.format(**params_path) + f"/{resource_id}")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_client_resource_scope(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(
            URL_ADMIN_CLIENT_RESOURCE_SCOPE.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def create_client_role_policy(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_CLIENT_ROLE_POLICY.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def create_user_policy(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_USER_POLICY.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def delete_policy(self, client_id, policy_id):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_POLICY.format(**params_path) + f"/{policy_id}")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_scope_permission(self, client_id, payload, skip_exists=False):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_post(URL_ADMIN_SCOPE_PERMISSION.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_scope_permission(self, client_id, permission_id, payload):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            URL_ADMIN_SCOPE_PERMISSION.format(**params_path) + f"/{permission_id}",
            data=json.dumps(payload),
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def delete_permission(self, client_id, permission_id):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_delete(URL_ADMIN_PERMISSION.format(**params_path) + f"/{permission_id}")
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_policies_by_name(self, client_id, name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            URL_ADMIN_POLICY.format(**params_path) + f"?first=0&max=20&name={name}&permission=false"
        )
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_policies(self, client_id):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_USER_POLICY.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_policy_id(self, client_id, policy_name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            URL_ADMIN_USER_POLICY.format(**params_path) + f"?first=0&max=1&name={policy_name}&permission=false"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_role_policies(self, client_id):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ROLE_POLICY.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_role_policy_id(self, client_id, policy_name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            URL_ADMIN_CLIENT_ROLE_POLICY.format(**params_path) + f"?first=0&max=1&name={policy_name}&permission=false"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_client_resource_scope_id(self, client_id, scope_name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            URL_ADMIN_CLIENT_RESOURCE_SCOPE.format(**params_path) + f"?first=0&max=1&name={scope_name}"
        )
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_client_resource_id(self, client_id, resource_name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
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
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "policy-id": policy_id,
        }
        data_raw = self.connection.raw_get(URL_ADMIN_POLICY_PERMISSIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_permissions_associated_policies(self, client_id, permission_id):
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": client_id,
            "permission-id": permission_id,
        }
        data_raw = self.connection.raw_get(URL_ADMIN_PERMISSION_ASSOCIATED_POLICIES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_permissions_by_name(self, client_id, name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_PERMISSION.format(**params_path) + f"?first=0&max=20&name={name}")
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_permission_id(self, client_id, name):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(URL_ADMIN_PERMISSION.format(**params_path) + f"?first=0&max=1&name={name}")
        data_raw = raise_error_from_response(data_raw, KeycloakGetError)
        if len(data_raw) > 0:
            data_raw = data_raw[0].get("id")
        else:
            data_raw = None
        return data_raw

    def get_client_roles_by_name(self, client_id, name, max=20, first=0, limit=True):
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        query = f"?first={first}&max={max}&search={name}" if limit else f"?search={name}"
        data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_ROLES.format(**params_path) + query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_assign_client_role(self, user_id, client_id, roles):
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {
            "realm-name": self.connection.realm_name,
            "id": user_id,
            "client-id": client_id,
        }
        data_raw = self.connection.raw_delete(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path), data=json.dumps(payload))
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
