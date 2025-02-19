TEST_REQUIREMENTS = {
    "User Management Layer": [
        {
            "user_need": "UN-001",
            "details": "As a PACS Administrator and Ultrasound Supervisor, I want to add a new user to the platform, so that they can access its features and services",
            "system_reqs": ["REQ-001 Identity, Access, and User Management"],
            "subsystem_reqs": ["SSR-5 User Invite Flow"],
            "validation": ["VAL-1 User Invitation and User Account Creation Process"],
            "verifications": [],
            "components": [
                {
                    "name": "User Management API",
                    "tests": [],
                    "coverage_gaps": [],
                    "cross_component_recommendations": []
                }
            ],
        }
    ],
    "Authorization Layer": [
        {
            "user_need": "UN-002",
            "details": "As a PACS Administrator and Ultrasound Supervisor, I want to assign role-based access policies to users on the platform, so that our medical center can follow the principle of least privilege.",
            "system_reqs": ["REQ-001 Identity, Access, and User Management"],
            "subsystem_reqs": [],
            "validation": ["VAL-2 Validation Protocol for RBAC Policies"],
            "verifications": [],
            "components": [
                {
                    "name": "Authorization API",
                    "tests": [
                        {"name": "test_update_client_auth_settings"},
                        {"name": "test_update_client_resource"},
                        {"name": "test_delete_client_resource"},
                        {"name": "test_create_client_resource_scope"},
                        {"name": "test_create_client_role_policy"},
                        {"name": "test_create_user_policy"},
                        {"name": "test_delete_policy"},
                        {"name": "test_create_scope_permission"},
                        {"name": "test_update_scope_permission"},
                        {"name": "test_delete_permission"},
                        {"name": "test_get_policies_by_name"},
                        {"name": "test_get_user_policies"},
                        {"name": "test_get_user_policy_id"},
                        {"name": "test_get_role_policies"},
                        {"name": "test_get_role_policy_id"},
                        {"name": "test_get_client_resource_scope_id"},
                        {"name": "test_get_client_resource_id"},
                        {"name": "test_get_policy_dependent_permissions"},
                        {"name": "test_get_permissions_associated_policies"},
                        {"name": "test_get_permissions_by_name"},
                        {"name": "test_get_permission_id"},
                        {"name": "test_get_client_roles_by_name"},
                        {"name": "test_delete_assign_client_role"},
                        {"name": "test_create_client_role_payload"},
                        {"name": "test_create_resource_scope_payload"},
                        {"name": "test_create_affirmative_positive_role_policy_payload"},
                        {"name": "test_create_affirmative_positive_user_policy_payload"},
                        {"name": "test_create_affirmative_positive_scope_permission_payload"},
                        {"name": "test_create_resource_payload"},
                        {"name": "test_get_policy_dependent_permissions_empty"},
                        {"name": "test_get_permissions_associated_policies_no_policies"},
                        {"name": "test_update_client_resource_skip_exists"},
                        {"name": "test_delete_client_resource_non_204"},
                        {"name": "test_get_user_policy_id_no_results"},
                        {"name": "test_create_scope_permission_already_exists"},
                        {"name": "test_get_client_resource_scope_id_none"},
                        {"name": "test_update_scope_permission_bad_request"},
                        {"name": "test_delete_permission_error"},
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
            "user_need": "UN-021",
            "details": "As a user on the platform, I want to login into the application using a secure password",
            "system_reqs": [],
            "subsystem_reqs": ["SSR-1 User Authentication"],
            "validation": ["VAL-1 User Invitation and User Account Creation Process"],
            "verifications": [],
            "components": [
                {
                    "name": "Authentication API",
                    "tests": [
                        {"name": "test_get_rpt"}
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
}


def get_test_requirements(test_name):
    """
    Find all requirements associated with a test name.

    Args:
        test_name (str): The name of the test to look up.

    Returns:
        dict: A dictionary containing:
            - system_reqs: List of system requirements (empty list if none)
            - subsystem_reqs: List of subsystem requirements (empty list if none)
            - validation: List of validations (empty list if none)
            - verifications: List of verifications (empty list if none)
            - user_needs: List of user needs associated with the test (empty list if none)

    Returns None if the test is not found.
    """
    for category in TEST_REQUIREMENTS.values():
        for requirement in category:
            for component in requirement.get('components', []):
                for test in component.get('tests', []):
                    if test.get('name') == test_name:
                        return {
                            'system_reqs': requirement.get('system_reqs', []),
                            'subsystem_reqs': requirement.get('subsystem_reqs', []),
                            'validation': requirement.get('validation', []),
                            'verifications': requirement.get('verifications', []),
                            'user_needs': [requirement.get('user_need')] if requirement.get('user_need') else [],
                        }
    return None