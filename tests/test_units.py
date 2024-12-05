import pytest
from unittest.mock import MagicMock
from keycloak_extend import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError


@pytest.mark.unit
def test_get_policy_dependent_permissions_empty():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    admin.connection.raw_get.return_value = MagicMock(status_code=200, json=lambda: [])
    res = admin.get_policy_dependent_permissions(client_id="client_id", policy_id="policy_id")
    assert res == []


@pytest.mark.unit
def test_get_permissions_associated_policies_no_policies():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    admin.connection.raw_get.return_value = MagicMock(status_code=200, json=lambda: [])
    res = admin.get_permissions_associated_policies(client_id="client_id", permission_id="perm_id")
    assert res == []


@pytest.mark.unit
def test_update_client_resource_skip_exists():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Simulate a 404 to check skip_exists behavior
    admin.connection.raw_put.return_value = MagicMock(status_code=404, text="Not Found")
    with pytest.raises(KeycloakGetError):
        admin.update_client_resource("client_id", "resource_id", {"name": "new-resource"}, skip_exists=True)


@pytest.mark.unit
def test_delete_client_resource_non_204():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Simulate a 400 error
    admin.connection.raw_delete.return_value = MagicMock(status_code=400, text="Bad Request")
    with pytest.raises(KeycloakGetError):
        admin.delete_client_resource("client_id", "resource_id")


@pytest.mark.unit
def test_get_user_policy_id_no_results():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Return empty list to simulate no policies found
    admin.connection.raw_get.return_value = MagicMock(status_code=200, json=lambda: [])
    res = admin.get_user_policy_id("client_id", "non_existent_policy")
    assert res is None


@pytest.mark.unit
def test_create_scope_permission_already_exists():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Simulate a 409 conflict implying resource already exists
    admin.connection.raw_post.return_value = MagicMock(status_code=409, text="Conflict")
    with pytest.raises(KeycloakGetError):
        admin.create_scope_permission("client_id", {"name": "existing_permission"}, skip_exists=False)


@pytest.mark.unit
def test_get_client_resource_scope_id_none():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # No scopes returned
    admin.connection.raw_get.return_value = MagicMock(status_code=200, json=lambda: [])
    res = admin.get_client_resource_scope_id("client_id", "non_existent_scope")
    assert res is None


@pytest.mark.unit
def test_update_scope_permission_bad_request():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Simulate 400 Bad Request
    admin.connection.raw_put.return_value = MagicMock(status_code=400, text="Bad Request")
    with pytest.raises(KeycloakGetError):
        admin.update_scope_permission("client_id", "perm_id", {"name": "invalid"})


@pytest.mark.unit
def test_delete_permission_error():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Simulate internal server error
    admin.connection.raw_delete.return_value = MagicMock(status_code=500, text="Internal Server Error")
    with pytest.raises(KeycloakGetError):
        admin.delete_permission("client_id", "perm_id")


@pytest.mark.unit
def test_get_policies_by_name_no_match():
    admin = KeycloakAdmin(server_url="http://fake-server")
    admin.connection = MagicMock()
    admin.connection.realm_name = "test"
    # Return empty list, indicating no matching policy
    admin.connection.raw_get.return_value = MagicMock(status_code=200, json=lambda: [])
    res = admin.get_policies_by_name("client_id", "no_such_policy")
    assert res == []
