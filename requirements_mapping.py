TEST_REQUIREMENTS = {
    "User Management Layer": [
        {
            "system_req": "UN-001",
            "details": "As a PACS Administrator and Ultrasound Supervisor, I want to add a new user to the platform, so that they can access its features and services.",
            "subsystem_reqs": ["SSR-5 REQ-001-005 User Invite Flow"],
            "components": [
                {
                    "name": "User Management API",
                    "tests": [
                        {"name": "test_create_user_policy"},
                        {"name": "test_delete_policy"},
                        {"name": "test_get_user_policies"},
                        {"name": "test_get_user_policy_id"},
                        {"name": "test_get_user_policy_id_no_results"},
                    ],
                    "coverage_gaps": [
                        "Test coverage for user role assignment",
                        "Test coverage for user profile updates",
                        "Test coverage for user deactivation",
                        "Test coverage for user deletion",
                        "Test coverage for user group management",
                    ],
                    "cross_component_recommendations": [
                        "Add integration tests for user management and authentication",
                        "Add security tests for user data access",
                        "Add performance tests for user creation and deletion",
                    ],
                }
            ],
        }
    ],
    "Authorization Layer": [
        {
            "system_req": "UN-002",
            "details": "As a PACS Administrator and Ultrasound Supervisor, I want to assign role-based access policies to users on the platform, so that our medical center can follow the principle of least privilege.",
            "subsystem_reqs": ["SSR-5 REQ-001-005 User Invite Flow"],
            "components": [
                {
                    "name": "Authorization API",
                    "tests": [
                        {"name": "test_create_client_role_policy"},
                        {"name": "test_create_scope_permission"},
                        {"name": "test_update_scope_permission"},
                        {"name": "test_delete_permission"},
                        {"name": "test_get_policies_by_name"},
                        {"name": "test_get_role_policies"},
                        {"name": "test_get_role_policy_id"},
                        {"name": "test_get_policy_dependent_permissions"},
                        {"name": "test_get_permissions_associated_policies"},
                        {"name": "test_get_permissions_by_name"},
                        {"name": "test_get_permission_id"},
                        {"name": "test_create_affirmative_positive_role_policy_payload"},
                        {"name": "test_create_affirmative_positive_user_policy_payload"},
                        {"name": "test_create_affirmative_positive_scope_permission_payload"},
                        {"name": "test_get_policy_dependent_permissions_empty"},
                        {"name": "test_get_permissions_associated_policies_no_policies"},
                        {"name": "test_get_policies_by_name_no_match"},
                    ],
                    "coverage_gaps": [
                        "Role permission inheritance",
                        "Custom role creation",
                        "Permission group management",
                        "Role assignment validation",
                        "Access token validation",
                        "Role retrieval functionality",
                        "Role creation functionality",
                    ],
                    "cross_component_recommendations": [
                        "Add integration tests for role management",
                        "Add security tests for permission validation",
                        "Test role inheritance scenarios",
                    ],
                }
            ],
        }
    ],
    "Authentication Layer": [
        {
            "system_req": "UN-021",
            "details": "As a user on the platform, I want to login into the application using a secure password.",
            "subsystem_reqs": ["SSR-1 REQ-001-001 User Authentication"],
            "components": [
                {
                    "name": "Authentication API",
                    "tests": [
                        {"name": "test_get_rpt"},
                    ],
                    "coverage_gaps": [
                        "Test coverage for password complexity validation",
                        "Test coverage for brute force protection",
                        "Test coverage for concurrent session handling",
                        "Test coverage for session timeout",
                        "Test coverage for remember me functionality",
                        "Test coverage for password history",
                        "Test coverage for failed login attempts tracking",
                        "Test coverage for account lockout",
                        "Test coverage for session hijacking prevention",
                        "Test coverage for token refresh flow",
                        "Test coverage for secure cookie handling",
                        "Test coverage for IP-based restrictions",
                    ],
                    "cross_component_recommendations": [
                        "Add integration tests between authentication and authorization",
                        "Add security tests for authentication flows",
                        "Add performance tests for login operations",
                        "Add tests for session management",
                        "Add tests for token lifecycle",
                        "Add tests for authentication audit logging",
                        "Add tests for security headers and cookies",
                    ],
                }
            ],
        }
    ],
    "Resource Management Layer": [
        {
            "system_req": "N/A",
            "details": "Tests related to client resource and scope management.",
            "subsystem_reqs": [],
            "components": [
                {
                    "name": "Resource Management API",
                    "tests": [
                        {"name": "test_update_client_auth_settings"},
                        {"name": "test_update_client_resource"},
                        {"name": "test_delete_client_resource"},
                        {"name": "test_create_client_resource_scope"},
                        {"name": "test_get_client_resource_scope_id"},
                        {"name": "test_get_client_resource_id"},
                        {"name": "test_create_resource_payload"},
                        {"name": "test_create_resource_scope_payload"},
                        {"name": "test_update_client_resource_skip_exists"},
                        {"name": "test_delete_client_resource_non_204"},
                        {"name": "test_get_client_resource_scope_id_none"},
                    ],
                    "coverage_gaps": [
                        "Test coverage for resource ownership validation",
                        "Test coverage for resource lifecycle management",
                        "Test coverage for resource access auditing",
                    ],
                    "cross_component_recommendations": [
                        "Add integration tests for resource and role management",
                        "Add security tests for resource access validation",
                        "Add performance tests for resource creation and deletion",
                    ],
                }
            ],
        }
    ],
    "Role Management Layer": [
        {
            "system_req": "N/A",
            "details": "Tests related to client role management.",
            "subsystem_reqs": [],
            "components": [
                {
                    "name": "Role Management API",
                    "tests": [
                        {"name": "test_get_client_roles_by_name"},
                        {"name": "test_delete_assign_client_role"},
                        {"name": "test_create_client_role_payload"},
                    ],
                    "coverage_gaps": [
                        "Test coverage for role inheritance",
                        "Test coverage for role permission updates",
                        "Test coverage for role assignment validation",
                    ],
                    "cross_component_recommendations": [
                        "Add integration tests for role and resource management",
                        "Add security tests for role permission validation",
                        "Add performance tests for role creation and deletion",
                    ],
                }
            ],
        }
    ],
    "Permission Management Layer": [
        {
            "system_req": "N/A",
            "details": "Tests related to permission management.",
            "subsystem_reqs": [],
            "components": [
                {
                    "name": "Permission Management API",
                    "tests": [
                        {"name": "test_create_scope_permission_already_exists"},
                        {"name": "test_update_scope_permission_bad_request"},
                        {"name": "test_delete_permission_error"},
                    ],
                    "coverage_gaps": [
                        "Test coverage for permission inheritance",
                        "Test coverage for permission group updates",
                        "Test coverage for permission assignment validation",
                    ],
                    "cross_component_recommendations": [
                        "Add integration tests for permission and role management",
                        "Add security tests for permission validation",
                        "Add performance tests for permission creation and deletion",
                    ],
                }
            ],
        }
    ],
}