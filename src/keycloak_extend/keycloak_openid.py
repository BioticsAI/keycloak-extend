import logging
from keycloak.exceptions import KeycloakPostError, raise_error_from_response, KeycloakAuthenticationError, KeycloakOperationError
from keycloak.urls_patterns import URL_TOKEN
from keycloak import KeycloakOpenID as KOpenID
from keycloak.uma_permissions import build_permission_param
from .exceptions import AccountLockedError, ActionRequired


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
        logger=None,
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
        self._keycloak_admin = None
        self.logger = logger or logging.getLogger(__file__)

    def set_keycloak_admin(self, keycloak_admin):
        """
        Set the KeycloakAdmin instance to use for checking account lockout status.
        
        Args:
            keycloak_admin: KeycloakAdmin instance
        """
        self._keycloak_admin = keycloak_admin

    def token(self, username='', password='', grant_type='password', code='', redirect_uri='', totp=None, scope='openid', **extra):
        """
        Override token method to check for account lockout due to brute force protection
        and detect when password is correct but needs updating.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            grant_type: Grant type (default: 'password')
            code: Authorization code (for authorization code flow)
            redirect_uri: Redirect URI
            totp: Time-based one-time password
            scope: OAuth2 scope (default: 'openid')
            **extra: Additional parameters
            
        Raises:
            AccountLockedError: If account is locked due to brute force protection
            ActionRequired: If account is authenticated but requires password update
            KeycloakAuthenticationError: For other authentication failures
        """
        self.logger.debug(f"KeycloakOpenID.token called with username={username}")
        try:
            # Attempt normal authentication
            tokens = super().token(username, password, grant_type, code, redirect_uri, totp, scope, **extra)
            return tokens
        except (KeycloakAuthenticationError, KeycloakPostError) as e:
            self.logger.debug(f"KeycloakAuthenticationError or KeycloakPostError caught: {e}")
            # Check if this is the specific "Account is not fully set up" error
            error_description = str(e)
            if "Account is not fully set up" in error_description:
                # This indicates the password is correct but user has required actions
                self.logger.debug(f"Detected 'Account is not fully set up' error, raising ActionRequired")
                raise ActionRequired(
                    action="update_password",
                    message="Password authentication successful but update required",
                    original_error=e
                )
            
            # Check if this authentication failure resulted in account lockout
            if self._keycloak_admin:
                self.logger.debug(f"Checking account lockout status for {username}")
                try:
                    self._keycloak_admin.check_account_locked(username)
                except AccountLockedError:
                    # Account was locked due to this authentication attempt
                    self.logger.debug(f"AccountLockedError raised, re-raising")
                    raise
                except Exception as lock_check_error:
                    self.logger.debug(f"Error checking lockout status: {lock_check_error}")
                    # If we can't check, re-raise the original authentication error
                    raise
            # Re-raise the original authentication error
            self.logger.debug(f"Re-raising original KeycloakAuthenticationError or KeycloakPostError")
            raise

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
