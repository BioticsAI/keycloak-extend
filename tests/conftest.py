"""Fixtures for tests."""

import ipaddress
import os
import uuid
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from keycloak_extend import KeycloakAdmin, KeycloakOpenID
from dotenv import load_dotenv

load_dotenv()


class KeycloakTestEnv(object):
    """Wrapper for test Keycloak connection configuration.

    :param host: Hostname
    :type host: str
    :param port: Port
    :type port: str
    :param username: Admin username
    :type username: str
    :param password: Admin password
    :type password: str
    """

    def __init__(
        self,
        host: str = os.environ["KEYCLOAK_HOST"],
        port: str = os.environ["KEYCLOAK_PORT"],
        username: str = os.environ["KEYCLOAK_ADMIN"],
        password: str = os.environ["KEYCLOAK_ADMIN_PASSWORD"],
    ):
        """Init method.

        :param host: Hostname
        :type host: str
        :param port: Port
        :type port: str
        :param username: Admin username
        :type username: str
        :param password: Admin password
        :type password: str
        """
        self.KEYCLOAK_HOST = host
        self.KEYCLOAK_PORT = port
        self.KEYCLOAK_ADMIN = username
        self.KEYCLOAK_ADMIN_PASSWORD = password

    @property
    def KEYCLOAK_HOST(self):
        """Hostname getter.

        :returns: Keycloak host
        :rtype: str
        """
        return self._KEYCLOAK_HOST

    @KEYCLOAK_HOST.setter
    def KEYCLOAK_HOST(self, value: str):
        """Hostname setter.

        :param value: Keycloak host
        :type value: str
        """
        self._KEYCLOAK_HOST = value

    @property
    def KEYCLOAK_PORT(self):
        """Port getter.

        :returns: Keycloak port
        :rtype: str
        """
        return self._KEYCLOAK_PORT

    @KEYCLOAK_PORT.setter
    def KEYCLOAK_PORT(self, value: str):
        """Port setter.

        :param value: Keycloak port
        :type value: str
        """
        self._KEYCLOAK_PORT = value

    @property
    def KEYCLOAK_ADMIN(self):
        """Admin username getter.

        :returns: Admin username
        :rtype: str
        """
        return self._KEYCLOAK_ADMIN

    @KEYCLOAK_ADMIN.setter
    def KEYCLOAK_ADMIN(self, value: str):
        """Admin username setter.

        :param value: Admin username
        :type value: str
        """
        self._KEYCLOAK_ADMIN = value

    @property
    def KEYCLOAK_ADMIN_PASSWORD(self):
        """Admin password getter.

        :returns: Admin password
        :rtype: str
        """
        return self._KEYCLOAK_ADMIN_PASSWORD

    @KEYCLOAK_ADMIN_PASSWORD.setter
    def KEYCLOAK_ADMIN_PASSWORD(self, value: str):
        """Admin password setter.

        :param value: Admin password
        :type value: str
        """
        self._KEYCLOAK_ADMIN_PASSWORD = value


@pytest.fixture
def env():
    """Fixture for getting the test environment configuration object.

    :returns: Keycloak test environment object
    :rtype: KeycloakTestEnv
    """
    return KeycloakTestEnv()


@pytest.fixture
def admin(env: KeycloakTestEnv):
    """Fixture for initialized KeycloakAdmin class.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :returns: Keycloak admin
    :rtype: KeycloakAdmin
    """
    return KeycloakAdmin(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        username=env.KEYCLOAK_ADMIN,
        password=env.KEYCLOAK_ADMIN_PASSWORD,
    )


@pytest.fixture
def oid(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    """Fixture for initialized KeycloakOpenID class.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :param realm: Keycloak realm
    :type realm: str
    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak OpenID client
    :rtype: KeycloakOpenID
    """
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    client_id = admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": True,
            "protocol": "openid-connect",
        }
    )
    # Return OID
    yield KeycloakOpenID(
        server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
        realm_name=realm,
        client_id=client,
    )
    # Cleanup
    admin.delete_client(client_id=client_id)


@pytest.fixture
def oid_with_credentials(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    """Fixture for an initialized KeycloakOpenID class and a random user credentials.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :param realm: Keycloak realm
    :type realm: str
    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak OpenID client with user credentials
    :rtype: Tuple[KeycloakOpenID, str, str]
    """
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": False,
            "protocol": "openid-connect",
            "secret": secret,
            "clientAuthenticatorType": "client-secret",
        }
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "credentials": [{"type": "password", "value": password}],
        }
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    admin.delete_client(client_id=client_id)
    admin.delete_user(user_id=user_id)


@pytest.fixture
def oid_with_credentials_authz(env: KeycloakTestEnv, realm: str, admin: KeycloakAdmin):
    """Fixture for an initialized KeycloakOpenID class and a random user credentials.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :param realm: Keycloak realm
    :type realm: str
    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak OpenID client configured as an authorization server with client credentials
    :rtype: Tuple[KeycloakOpenID, str, str]
    """
    # Set the realm
    admin.realm_name = realm
    # Create client
    client = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    client_id = admin.create_client(
        payload={
            "name": client,
            "clientId": client,
            "enabled": True,
            "publicClient": False,
            "protocol": "openid-connect",
            "secret": secret,
            "clientAuthenticatorType": "client-secret",
            "authorizationServicesEnabled": True,
            "serviceAccountsEnabled": True,
        }
    )
    admin.create_client_authz_role_based_policy(
        client_id=client_id,
        payload={
            "name": "test-authz-rb-policy",
            "roles": [{"id": admin.get_realm_role(role_name="offline_access")["id"]}],
        },
    )
    # Create user
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    user_id = admin.create_user(
        payload={
            "username": username,
            "email": f"{username}@test.test",
            "enabled": True,
            "credentials": [{"type": "password", "value": password}],
        }
    )

    yield (
        KeycloakOpenID(
            server_url=f"http://{env.KEYCLOAK_HOST}:{env.KEYCLOAK_PORT}",
            realm_name=realm,
            client_id=client,
            client_secret_key=secret,
        ),
        username,
        password,
    )

    # Cleanup
    admin.delete_client(client_id=client_id)
    admin.delete_user(user_id=user_id)


@pytest.fixture
def realm(admin: KeycloakAdmin) -> str:
    """Fixture for a new random realm.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :yields: Keycloak realm
    :rtype: str
    """
    realm_name = str(uuid.uuid4())
    admin.create_realm(payload={"realm": realm_name, "enabled": True})
    yield realm_name
    admin.delete_realm(realm_name=realm_name)


@pytest.fixture
def user(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random user.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak user
    :rtype: str
    """
    admin.realm_name = realm
    username = str(uuid.uuid4())
    user_id = admin.create_user(payload={"username": username, "email": f"{username}@test.test"})
    yield user_id
    admin.delete_user(user_id=user_id)


@pytest.fixture
def group(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random group.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak group
    :rtype: str
    """
    admin.realm_name = realm
    group_name = str(uuid.uuid4())
    group_id = admin.create_group(payload={"name": group_name})
    yield group_id
    admin.delete_group(group_id=group_id)


@pytest.fixture
def client(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random client.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak client id
    :rtype: str
    """
    admin.realm_name = realm
    client = str(uuid.uuid4())
    client_id = admin.create_client(payload={"name": client, "clientId": client})
    yield client_id
    admin.delete_client(client_id=client_id)


@pytest.fixture
def authz_client(admin: KeycloakAdmin, realm: str) -> str:
    """Fixture for a new random client.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :yields: Keycloak client id
    :rtype: str
    """
    admin.realm_name = realm
    client = str(uuid.uuid4())
    client_id = admin.create_client(payload={"name": client, "clientId": client})
    admin.update_client(
        client_id=client_id,
        payload={
            "surrogateAuthRequired": False,
            "enabled": True,
            "alwaysDisplayInConsole": False,
            "clientAuthenticatorType": "client-secret",
            "bearerOnly": False,
            "consentRequired": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "frontchannelLogout": False,
            "protocol": "openid-connect",
            "access": {"view": True, "configure": True, "manage": True},
            "authorizationServicesEnabled": True,
        },
    )
    yield client_id
    admin.delete_client(client_id=client_id)


@pytest.fixture
def client_role(admin: KeycloakAdmin, realm: str, authz_client: str) -> str:
    """Fixture for a new random client role.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :yields: Keycloak client role
    :rtype: str
    """
    admin.realm_name = realm
    role = str(uuid.uuid4())
    created_role = admin.create_client_role(authz_client, {"name": role, "composite": False})
    role_id = admin.get_client_role_id(client_id=authz_client, role_name=created_role)
    yield role_id
    admin.delete_client_role(authz_client, role)


@pytest.fixture
def authz_resource(admin: KeycloakAdmin, realm: str, authz_client: str) -> str:
    """Fixture for a new random authz resource.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :yields: Keycloak authz resource
    :rtype: str
    """
    admin.realm_name = realm
    resource = str(uuid.uuid4())
    res = admin.create_client_authz_resource(client_id=authz_client, payload=admin.create_resource_payload(name=resource))
    resource_id = res['_id']
    yield resource_id


@pytest.fixture
def authz_scope(admin: KeycloakAdmin, realm: str, authz_client: str) -> str:
    """Fixture for a new random authz scope.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :yields: Keycloak authz scope
    :rtype: str
    """
    admin.realm_name = realm
    scope = str(uuid.uuid4())
    res = admin.create_client_resource_scope(
        client_id=authz_client, payload=admin.create_resource_scope_payload(name=scope)
    )
    scope_id = res["id"]
    yield scope_id


@pytest.fixture
def authz_policy(admin: KeycloakAdmin, realm: str, authz_client: str, user: str) -> str:
    """Fixture for a new random authz policy.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param user: Keycloak user
    :type user: str
    :yields: Keycloak authz policy
    :rtype: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    res = admin.create_user_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user),
    )
    policy_id = res["id"]
    yield policy_id


@pytest.fixture
def authz_scope_permission(admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str, authz_policy: str) -> str:
    """Fixture for a new random authz scope permission.

    :param admin: Keycloak admin
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    :yields: Keycloak authz policy
    :rtype: str
    """
    admin.realm_name = realm
    permission = str(uuid.uuid4())
    res = admin.create_scope_permission(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            scopes=[authz_scope],
            policies=[authz_policy],
        ),
    )
    permission_id = res["id"]
    yield permission_id
