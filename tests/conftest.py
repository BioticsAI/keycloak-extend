"""Fixtures for tests."""

import os
import json as _json
import subprocess
import uuid
from pathlib import Path

import pytest
import requests
from dotenv import load_dotenv
from keycloak_extend import KeycloakAdmin, KeycloakOpenID
import logging


logger = logging.getLogger(__file__)
load_dotenv()


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line(
        "markers", "dev_only: mark test to run only in development environment"
    )


def pytest_addoption(parser):
    """Add custom pytest command line options."""
    group = parser.getgroup("plan")
    group.addoption(
        "--plan",
        action="store_true",
        default=False,
        help="Only display the test execution plan without running tests",
    )


def pytest_collection_modifyitems(session, config, items,):
    """Log the test execution plan before running tests in a tree structure."""
    from collections import defaultdict

    test_tree = defaultdict(lambda: defaultdict(list))
    
    # Main loop with single function call
    for item in items:
        directory, filename, test_name = make_test_tree(item)
        test_tree[directory][filename].append(test_name)

        # Add ultralightlabs verification attribute
        module = item.module
        if hasattr(module, 'ultralightlabs_verification'):
            verification_name = getattr(module, 'ultralightlabs_verification')
            if not verification_name.startswith('VER'):
                logger.error(f'module {module.__qualname__} has an invalid ultralightlabs_verification attribute')
            else:
                item.add_marker(pytest.mark.ultralightlabs_verify_test(name=verification_name))
                item.record_xml_attribute('name', verification_name)
        else:
            logger.warn(f"Module {module} doesn't have ultralightlabs_verification set.")

    if config.getoption("--plan"):
        print_execution_plan(config, test_tree, session)


def make_test_tree(item):
    """Process individual test item and populate the test tree structure."""
    parts = item.nodeid.split("::")
    file_path = parts[0]
    test_name = parts[1]

    path_parts = file_path.split("/")
    if len(path_parts) > 1:
        directory = "/".join(path_parts[:-1])
        filename = path_parts[-1]
    else:
        directory = "."
        filename = path_parts[0]

    return directory, filename, test_name


def print_execution_plan(config, test_tree, session):
    """Print the test execution plan and clear test items if in plan mode."""
    print("\nTest Execution Plan:")
    print("=" * 80)

    total_tests = 0
    for directory in sorted(test_tree.keys()):
        print(f"\n-> {directory}")
        for filename in sorted(test_tree[directory].keys()):
            print(f"  |-> {filename}")
            for test in sorted(test_tree[directory][filename]):
                print(f"      |-> {test}")
                total_tests += 1

    print("\n" + "=" * 80)
    print(f"Total tests to run: {total_tests}\n")
    print("Plan mode: Skipping test execution")
    session.items = []


@pytest.fixture(scope='session')
def docker_ip():
    return "localhost"


@pytest.fixture(scope='session')
def docker_compose_file():
    return Path(".").resolve() / "tests/docker-compose.yaml"


@pytest.fixture(scope="session")
def keycloak_service(docker_services):
    """Starts Keycloak in a Docker container for integration tests."""
    port = docker_services.port_for("keycloak", 8080)
    health_check_port = docker_services.port_for("keycloak", 9000)
    
    def check():
        try:
            response = requests.get(f"http://localhost:{health_check_port}/health")
        except requests.exceptions.ConnectionError:
            return False
        
        return response.json()['status'] == "UP"

    docker_services.wait_until_responsive(check=check, timeout=180.0, pause=5.0)

    # Ensure the realm does not require HTTPS so tests can obtain tokens over HTTP
    _configure_keycloak_ssl_and_admin(port)

    url = f"http://localhost:{port}/"
    return url


def _configure_keycloak_ssl_and_admin(host_port: int) -> None:
    """Disable SSL requirement on 'master' realm and ensure admin has an email.

    We execute kcadm inside the running container corresponding to the published host_port.
    """
    try:
        ps_out = subprocess.check_output(
            [
                "docker",
                "ps",
                "--format",
                "{{.ID}} {{.Image}} {{.Names}} {{.Ports}}",
            ],
            text=True,
        )
    except Exception as e:
        logger.error(f"Failed to list docker containers: {e}")
        return

    candidate_container = None
    for line in ps_out.strip().splitlines():
        parts = line.split(" ")
        if len(parts) < 4:
            continue
        container_id = parts[0]
        name = parts[2]
        ports = " ".join(parts[3:])
        # Match published port to container 8080
        if f":{host_port}->8080/tcp" in ports:
            candidate_container = name
            break

    if not candidate_container:
        logger.error("Could not find Keycloak container for tests; skipping SSL config step.")
        return

    def _exec(cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["docker", "exec", candidate_container, *cmd], text=True, capture_output=True)

    # Authenticate kcadm (non-interactive)
    auth_cmd = [
        "/opt/keycloak/bin/kcadm.sh",
        "config",
        "credentials",
        "--server",
        "http://localhost:8080",
        "--realm",
        "master",
        "--user",
        os.environ.get("KEYCLOAK_ADMIN", "admin"),
        "--password",
        os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
    ]
    res = _exec(auth_cmd)
    if res.returncode != 0:
        logger.error(f"kcadm auth failed: {res.stderr}\n{res.stdout}")
        return

    # Disable SSL requirement
    update_ssl_cmd = [
        "/opt/keycloak/bin/kcadm.sh",
        "update",
        "realms/master",
        "-s",
        "sslRequired=NONE",
    ]
    res = _exec(update_ssl_cmd)
    if res.returncode != 0:
        logger.error(f"Failed to set sslRequired=NONE: {res.stderr}\n{res.stdout}")
        # proceed; sometimes already set

    # Ensure admin has an email to avoid 'Account is not fully set up'
    get_admin_cmd = [
        "/opt/keycloak/bin/kcadm.sh",
        "get",
        "users",
        "-r",
        "master",
        "-q",
        "username=admin",
    ]
    res = _exec(get_admin_cmd)
    if res.returncode == 0 and res.stdout:
        try:
            users = _json.loads(res.stdout)
            if isinstance(users, list) and users:
                admin_id = users[0].get("id")
                if admin_id:
                    set_email_cmd = [
                        "/opt/keycloak/bin/kcadm.sh",
                        "update",
                        f"users/{admin_id}",
                        "-r",
                        "master",
                        "-s",
                        "email=admin@example.com",
                        "-s",
                        "emailVerified=true",
                    ]
                    _exec(set_email_cmd)
        except Exception:
            pass

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
            host,
            port = 8080,
            username: str = os.environ.get("KEYCLOAK_ADMIN", "admin"),
            password: str = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
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
def env(docker_ip):
    """Fixture for getting the test environment configuration object.

    :returns: Keycloak test environment object
    :rtype: KeycloakTestEnv
    """
    return KeycloakTestEnv(host=docker_ip)


@pytest.fixture
def admin(env: KeycloakTestEnv, keycloak_service):
    """Fixture for initialized KeycloakAdmin class.

    :param env: Keycloak test environment
    :type env: KeycloakTestEnv
    :returns: Keycloak admin
    :rtype: KeycloakAdmin
    """
    return KeycloakAdmin(
        server_url=keycloak_service,
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
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
            "firstName": username,
            "lastName": username,
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
    # Create realm with HTTP allowed, brute force protection, and password history enabled for tests
    admin.create_realm(payload={
        "realm": realm_name, 
        "enabled": True, 
        "sslRequired": "NONE",
        "bruteForceProtected": True,
        "failureFactor": 2,  # Lock after 2 failed attempts
        "maxFailureWaitSeconds": 30,
        "minimumQuickLoginWaitSeconds": 1,
        "passwordPolicy": "length(8) and passwordHistory(2)"
    })
    try:
        # Some Keycloak versions ignore settings on create; enforce again via update
        admin.update_realm(realm_name=realm_name, payload={
            "sslRequired": "NONE",
            "bruteForceProtected": True,
            "failureFactor": 2,
            "maxFailureWaitSeconds": 30,
            "minimumQuickLoginWaitSeconds": 1,
            "passwordPolicy": "length(8) and passwordHistory(2)"
        })
    except Exception:
        pass
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
    resource = str(uuid.uuid4())
    res = admin.create_client_authz_resource(client_id=authz_client,
                                             payload=admin.create_resource_payload(name=resource))
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
    admin.connection.realm_name = realm
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
    admin.connection.realm_name = realm
    policy = str(uuid.uuid4())
    res = admin.create_user_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user),
    )
    policy_id = res["id"]
    yield policy_id


@pytest.fixture
def authz_scope_permission(admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str,
                           authz_policy: str) -> str:
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
    admin.connection.realm_name = realm
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
