import uuid

import pytest
from keycloak_extend import KeycloakAdmin

@pytest.mark.unit
def test_create_realm_and_client(keycloak_service):
    admin = KeycloakAdmin(
        server_url=keycloak_service,
        username="admin",
        password="admin",
    )

    realm_name = str(uuid.uuid4())
    admin.create_realm(payload={"realm": realm_name, "enabled": True})

    client_id = admin.create_client(
        payload={
            "name": "test-client",
            "clientId": "test-client",
            "enabled": True,
            "protocol": "openid-connect",
        },
    )

    clients = admin.get_clients()
    assert any(c["id"] == client_id for c in clients)

    admin.delete_client(client_id=client_id)
    admin.delete_realm(realm_name=realm_name)
