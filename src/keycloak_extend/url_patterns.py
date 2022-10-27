from keycloak.urls_patterns import URL_ADMIN_CLIENT


URL_ADMIN_CLIENT_SETTINGS = URL_ADMIN_CLIENT + "/authz/resource-server"
URL_ADMIN_CLIENT_RESOURCE = URL_ADMIN_CLIENT + "/authz/resource-server/resource"
URL_ADMIN_CLIENT_RESOURCE_SCOPE = URL_ADMIN_CLIENT + "/authz/resource-server/scope"
URL_ADMIN_CLIENT_ROLE_POLICY = URL_ADMIN_CLIENT + "/authz/resource-server/policy/role"
URL_ADMIN_USER_POLICY = URL_ADMIN_CLIENT + "/authz/resource-server/policy/user"
URL_ADMIN_POLICY = URL_ADMIN_CLIENT + "/authz/resource-server/policy"
URL_ADMIN_POLICY_PERMISSIONS = URL_ADMIN_CLIENT + "/authz/resource-server/policy/{policy-id}/dependentPolicies"
URL_ADMIN_SCOPE_PERMISSION = URL_ADMIN_CLIENT + "/authz/resource-server/permission/scope"
URL_ADMIN_RESOURCE_PERMISSION = URL_ADMIN_CLIENT + "/authz/resource-server/permission/resource"
URL_ADMIN_PERMISSION = URL_ADMIN_CLIENT + "/authz/resource-server/permission"
URL_ADMIN_PERMISSION_ASSOCIATED_POLICIES = (
    URL_ADMIN_CLIENT + "/authz/resource-server/policy/{permission-id}/associatedPolicies"
)
