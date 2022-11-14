import uuid
from keycloak_extend import KeycloakAdmin


def test_update_client_auth_settings(admin: KeycloakAdmin, realm: str, authz_client: str):
    """Test update client authorization settings
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    """
    admin.realm_name = realm
    res = admin.update_client_auth_settings(
        client_id=authz_client,
        payload={
            "allowRemoteResourceManagement": True,
            "policyEnforcementMode": "ENFORCING",
            "decisionStrategy": "AFFIRMATIVE",
        },
    )

    assert res == {}


def test_update_client_resource(admin: KeycloakAdmin, realm: str, authz_client: str, authz_resource: str):
    """Test update authz resource
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_resource: Keycloak authz resource
    :type authz_resource: str
    """
    admin.realm_name = realm
    resource = str(uuid.uuid4())
    res = admin.update_client_resource(
        client_id=authz_client, resource_id=authz_resource, payload=admin.create_resource_payload(name=resource)
    )
    assert res == {}


def test_delete_client_resource(admin: KeycloakAdmin, realm: str, authz_client: str, authz_resource: str):
    """Test delete authz resource
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_resource: Keycloak authz resource
    :type authz_resource: str
    """
    admin.realm_name = realm
    res = admin.delete_client_resource(client_id=authz_client, resource_id=authz_resource)
    assert res == {}


def test_create_client_resource_scope(admin: KeycloakAdmin, realm: str, authz_client: str):
    """Test create authz scope
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    """
    admin.realm_name = realm
    scope = str(uuid.uuid4())
    res = admin.create_client_resource_scope(
        client_id=authz_client, payload=admin.create_resource_scope_payload(name=scope)
    )
    assert "id" in res
    assert "name" in res
    assert res["name"] == scope


def test_create_client_role_policy(admin: KeycloakAdmin, realm: str, authz_client: str, client_role: str):
    """Test create authz role policy
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param client_role: Keycloak client role id
    :type client_role: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    res = admin.create_client_role_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_role_policy_payload(name=policy, role_id=client_role),
    )
    assert "id" in res
    assert "name" in res
    assert "roles" in res
    assert "decisionStrategy" in res
    assert "logic" in res
    assert res["name"] == policy
    assert len(res["roles"]) == 1
    assert res["roles"][0]["id"] == client_role


def test_create_user_policy(admin: KeycloakAdmin, realm: str, authz_client: str, user: str):
    """Test create authz user policy
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param user: Keycloak user
    :type user: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    res = admin.create_user_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user),
    )
    assert "id" in res
    assert "name" in res
    assert "users" in res
    assert "decisionStrategy" in res
    assert "logic" in res
    assert res["name"] == policy
    assert len(res["users"]) == 1
    assert res["users"][0] == user


def test_delete_policy(admin: KeycloakAdmin, realm: str, authz_client: str, authz_policy: str):
    """Test delete authz policy
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    """
    admin.realm_name = realm
    res = admin.delete_policy(client_id=authz_client, policy_id=authz_policy)
    assert res == {}


def test_create_scope_permission(
    admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str, authz_policy: str
):
    """Test create authz scope permission
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
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
    assert "id" in res
    assert "name" in res
    assert "type" in res
    assert "decisionStrategy" in res
    assert "logic" in res
    assert res["name"] == permission
    assert len(res["policies"]) == 1
    assert len(res["scopes"]) == 1
    assert res["scopes"][0] == authz_scope
    assert res["policies"][0] == authz_policy


def test_update_scope_permission(
    admin: KeycloakAdmin,
    realm: str,
    authz_client: str,
    authz_scope: str,
    authz_policy: str,
    authz_scope_permission: str,
):
    """Test update authz scope permission
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    :param authz_scope_permission: Keycloak authz scope permission
    :type authz_scope_permission: str
    """
    admin.realm_name = realm
    permission = str(uuid.uuid4())
    res = admin.update_scope_permission(
        client_id=authz_client,
        permission_id=authz_scope_permission,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            scopes=[authz_scope],
            policies=[authz_policy],
        ),
    )
    assert res == bytes()


def test_delete_permission(
    admin: KeycloakAdmin,
    realm: str,
    authz_client: str,
    authz_scope_permission: str,
):
    """Test update authz scope permission
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope_permission: Keycloak authz scope permission
    :type authz_scope_permission: str
    """
    admin.realm_name = realm
    res = admin.delete_permission(
        client_id=authz_client,
        permission_id=authz_scope_permission,
    )
    assert res == {}


def test_get_policies_by_name(admin: KeycloakAdmin, realm: str, authz_client: str, user: str):
    """Test get authz policies by name
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param user: Keycloak user
    :type user: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    created_policy = admin.create_user_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user),
    )
    res = admin.get_policies_by_name(client_id=authz_client, name=policy)
    assert len(res) == 1
    for p in res:
        assert "id" in p
        assert "name" in p
        assert "type" in p
        assert "logic" in p
        assert "decisionStrategy" in p
        assert "config" in p
        assert p["id"] == created_policy["id"]
        assert p["name"] == policy


def test_get_user_policies(admin: KeycloakAdmin, realm: str, authz_client: str, user: str):
    """Test get authz user policies
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param user: Keycloak user
    :type user: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    created_policy = admin.create_user_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user),
    )
    res = admin.get_user_policies(client_id=authz_client)
    assert len(res) == 1
    for p in res:
        assert "id" in p
        assert "name" in p
        assert "type" in p
        assert "logic" in p
        assert "decisionStrategy" in p
        assert p["id"] == created_policy["id"]
        assert p["name"] == policy


def test_get_user_policy_id(admin: KeycloakAdmin, realm: str, authz_client: str, user: str):
    """Test get authz user policy id
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param user: Keycloak user
    :type user: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    created_policy = admin.create_user_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_user_policy_payload(name=policy, user_id=user),
    )
    res = admin.get_user_policy_id(client_id=authz_client, policy_name=policy)
    assert res == created_policy["id"]


def test_get_role_policies(admin: KeycloakAdmin, realm: str, authz_client: str, client_role: str):
    """Test get authz role policies
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param client_role: Keycloak client role id
    :type client_role: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    created_policy = admin.create_client_role_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_role_policy_payload(name=policy, role_id=client_role),
    )
    res = admin.get_role_policies(client_id=authz_client)
    for p in res:
        assert "id" in p
        assert "name" in p
        assert "roles" in p
        assert "decisionStrategy" in p
        assert "logic" in p
        assert p["name"] == policy
        assert p["id"] == created_policy["id"]
        assert len(p["roles"]) == 1
        assert p["roles"][0]["id"] == client_role


def test_get_role_policy_id(admin: KeycloakAdmin, realm: str, authz_client: str, client_role: str):
    """Test get authz role policy id
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param client_role: Keycloak client role id
    :type client_role: str
    """
    admin.realm_name = realm
    policy = str(uuid.uuid4())
    created_policy = admin.create_client_role_policy(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_role_policy_payload(name=policy, role_id=client_role),
    )
    res = admin.get_role_policy_id(client_id=authz_client, policy_name=policy)
    assert res == created_policy["id"]


def test_get_client_resource_scope_id(admin: KeycloakAdmin, realm: str, authz_client: str):
    """Test get authz scope id
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    """
    admin.realm_name = realm
    scope = str(uuid.uuid4())
    created_scope = admin.create_client_resource_scope(
        client_id=authz_client, payload=admin.create_resource_scope_payload(name=scope)
    )
    res = admin.get_client_resource_scope_id(client_id=authz_client, scope_name=scope)
    assert res == created_scope["id"]


def test_get_client_resource_id(admin: KeycloakAdmin, realm: str, authz_client: str):
    """Test get authz resource id
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    """
    admin.realm_name = realm
    resource = str(uuid.uuid4())
    created_resource = admin.create_client_authz_resource(
        client_id=authz_client, payload=admin.create_resource_payload(name=resource)
    )
    res = admin.get_client_resource_id(client_id=authz_client, resource_name=resource)
    assert res == created_resource["_id"]


def test_get_policy_dependent_permissions(
    admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str, authz_policy: str
):
    """Test get authz policy dependent permissions
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    """
    admin.realm_name = realm
    permission = str(uuid.uuid4())
    created_permission = admin.create_scope_permission(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            scopes=[authz_scope],
            policies=[authz_policy],
        ),
    )
    res = admin.get_policy_dependent_permissions(client_id=authz_client, policy_id=authz_policy)
    assert len(res) == 1
    for p in res:
        assert "id" in p
        assert "name" in p
        assert "type" in p
        assert "logic" in p
        assert "decisionStrategy" in p
        assert "config" in p
        assert p["id"] == created_permission["id"]
        assert p["name"] == permission


def test_get_permissions_associated_policies(
    admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str, authz_policy: str
):
    """Test get authz permission associated policy
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    """
    admin.realm_name = realm
    permission = str(uuid.uuid4())
    created_permission = admin.create_scope_permission(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            scopes=[authz_scope],
            policies=[authz_policy],
        ),
    )
    res = admin.get_permissions_associated_policies(client_id=authz_client, permission_id=created_permission["id"])
    assert len(res) == 1
    for p in res:
        assert "id" in p
        assert "name" in p
        assert "type" in p
        assert "logic" in p
        assert "decisionStrategy" in p
        assert "config" in p
        assert p["id"] == authz_policy


def test_get_permissions_by_name(
    admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str, authz_policy: str
):
    """Test get authz permissions by name
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    """
    admin.realm_name = realm
    permission = str(uuid.uuid4())
    created_permission = admin.create_scope_permission(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            scopes=[authz_scope],
            policies=[authz_policy],
        ),
    )
    res = admin.get_permissions_by_name(client_id=authz_client, name=permission)
    assert len(res) == 1
    for p in res:
        assert "id" in p
        assert "name" in p
        assert "type" in p
        assert "logic" in p
        assert "decisionStrategy" in p
        assert p["id"] == created_permission["id"]
        assert p["name"] == permission


def test_get_permission_id(admin: KeycloakAdmin, realm: str, authz_client: str, authz_scope: str, authz_policy: str):
    """Test get authz permissions id
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param authz_scope: Keycloak authz scope
    :type authz_scope: str
    :param authz_policy: Keycloak policy
    :type authz_policy: str
    """
    admin.realm_name = realm
    permission = str(uuid.uuid4())
    created_permission = admin.create_scope_permission(
        client_id=authz_client,
        payload=admin.create_affirmative_positive_scope_permission_payload(
            name=permission,
            scopes=[authz_scope],
            policies=[authz_policy],
        ),
    )
    res = admin.get_permission_id(client_id=authz_client, name=permission)
    assert res == created_permission["id"]


def test_get_client_roles_by_name(admin: KeycloakAdmin, realm: str, authz_client: str):
    """Test get client roles by name
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    """
    admin.realm_name = realm
    role = str(uuid.uuid4())
    created_role = admin.create_client_role(authz_client, {"name": role, "composite": False})
    created_role = admin.get_client_role_id(client_id=authz_client, role_name=created_role)
    res = admin.get_client_roles_by_name(client_id=authz_client, name=role)
    assert len(res) == 1
    for r in res:
        assert "id" in r
        assert "name" in r
        assert r["id"] == created_role
        assert r["name"] == role


def test_delete_assign_client_role(admin: KeycloakAdmin, realm: str, authz_client: str, user: str):
    """Test delete assigned role to user
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    :param realm: Keycloak realm
    :type realm: str
    :param authz_client: Keycloak client with authorization enabled
    :type authz_client: str
    :param user: Keycloak user
    :type user: str
    """
    admin.realm_name = realm
    role = str(uuid.uuid4())
    admin.create_client_role(authz_client, {"name": role, "composite": False})
    role = admin.get_client_role(client_id=authz_client, role_name=role)
    admin.assign_client_role(user_id=user, client_id=authz_client, roles=[role])
    res = admin.delete_assign_client_role(client_id=authz_client, user_id=user, roles=[role])
    assert res == {}


def test_create_client_role_payload(admin: KeycloakAdmin):
    """Test create role payload
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    res = admin.create_client_role_payload(name="role")
    assert res == {"name": "role"}


def test_create_resource_scope_payload(admin: KeycloakAdmin):
    """Test create authz scope payload
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    res = admin.create_resource_scope_payload(name="scope")
    assert res == {"name": "scope"}


def test_create_affirmative_positive_role_policy_payload(admin: KeycloakAdmin):
    """Test create affirmative positive role policy payload
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    res = admin.create_affirmative_positive_role_policy_payload(name="policy", role_id="role_id")
    assert "type" in res
    assert "decisionStrategy" in res
    assert "logic" in res
    assert "name" in res
    assert "roles" in res
    assert res["type"] == "role"
    assert res["decisionStrategy"] == "AFFIRMATIVE"
    assert res["logic"] == "POSITIVE"
    assert res["name"] == "policy"
    assert res["roles"] == [{"id": "role_id", "required": True}]


def test_create_affirmative_positive_user_policy_payload(admin: KeycloakAdmin):
    """Test create affirmative positive role policy payload
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    res = admin.create_affirmative_positive_user_policy_payload(name="policy", user_id="user_id")
    assert "type" in res
    assert "decisionStrategy" in res
    assert "logic" in res
    assert "name" in res
    assert "users" in res
    assert res["type"] == "user"
    assert res["decisionStrategy"] == "AFFIRMATIVE"
    assert res["logic"] == "POSITIVE"
    assert res["name"] == "policy"
    assert res["users"] == ["user_id"]


def test_create_affirmative_positive_scope_permission_payload(admin: KeycloakAdmin):
    """Test create affirmative positive scope permission payload
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    res = admin.create_affirmative_positive_scope_permission_payload(
        name="permission", resources=["resource_id"], scopes=["scope_id"], policies=["policy_id"]
    )
    assert "type" in res
    assert "decisionStrategy" in res
    assert "logic" in res
    assert "name" in res
    assert "scopes" in res
    assert "policies" in res
    assert "resources" in res
    assert res["type"] == "scope"
    assert res["decisionStrategy"] == "AFFIRMATIVE"
    assert res["logic"] == "POSITIVE"
    assert res["name"] == "permission"
    assert res["scopes"] == ["scope_id"]
    assert res["policies"] == ["policy_id"]
    assert res["resources"] == ["resource_id"]


def test_create_resource_payload(admin: KeycloakAdmin):
    """Test create resource payload
    :param admin: Keycloak Admin client
    :type admin: KeycloakAdmin
    """
    res = admin.create_resource_payload(name="resource", scopes=["scope_id"])
    assert "scopes" in res
    assert "name" in res
    assert "displayName" in res
    assert res["name"] == "resource"
    assert res["displayName"] == "resource"
    assert res["scopes"] == ["scope_id"]
