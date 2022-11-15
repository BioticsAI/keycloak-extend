import uuid
import time
from typing import Tuple
from keycloak_extend import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakPostError


def test_get_rpt(admin: KeycloakAdmin, oid_with_credentials_authz: Tuple[KeycloakOpenID, str, str]):
    oid, username, password = oid_with_credentials_authz
    admin.realm_name = oid.realm_name
    token = oid.token(username=username, password=password)
    access_token = token["access_token"]
    client_name = oid.client_id
    client_id = admin.get_client_id(client_name)
    scope = str(uuid.uuid4())
    created_scope = admin.create_client_resource_scope(
        client_id=client_id, payload=admin.create_resource_scope_payload(name=scope)
    )
    resource = str(uuid.uuid4())
    admin.create_client_authz_resource(
        client_id=client_id, payload=admin.create_resource_payload(name=resource, scopes=[created_scope])
    )
    permissions = {f"{resource}": f"{scope}"}
    try:
        rpt = oid.get_rpt(
            token=access_token,
            permission=permissions,
        )
    except KeycloakPostError as e:
        assert str(e) == '403: b\'{"error":"access_denied","error_description":"not_authorized"}\''

    policy = str(uuid.uuid4())
    user_id = admin.get_user_id(username=username)
    created_user_policy = admin.create_user_policy(
        client_id=client_id,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user_id),
    )
    permission = str(uuid.uuid4())
    admin.create_scope_permission(
        client_id=client_id,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            resources=[admin.get_client_resource_id(client_id=client_id, resource_name=resource)],
            scopes=[created_scope["id"]],
            policies=[created_user_policy["id"]],
        ),
    )

    rpt = oid.get_rpt(
        token=access_token,
        permission=permissions,
    )

    assert rpt["result"] == True

