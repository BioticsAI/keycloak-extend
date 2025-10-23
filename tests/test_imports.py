"""Import tests to verify all modules and exceptions are accessible."""

import pytest


def test_import_keycloak_extend_modules():
    """Test that all keycloak_extend modules can be imported."""
    # Test importing the main modules
    from keycloak_extend import KeycloakAdmin, KeycloakOpenID
    assert KeycloakAdmin is not None
    assert KeycloakOpenID is not None


def test_import_keycloak_extend_exceptions():
    """Test that all custom exceptions can be imported."""
    from keycloak_extend.exceptions import (
        AuthError,
        UserExistsError,
        UsernameExistsError,
        EmailExistsError,
        ValidationError,
        ClientConfigurationError,
        AccountLockedError,
        ActionRequired,
    )
    
    # Verify all exception classes exist
    assert AuthError is not None
    assert UserExistsError is not None
    assert UsernameExistsError is not None
    assert EmailExistsError is not None
    assert ValidationError is not None
    assert ClientConfigurationError is not None
    assert AccountLockedError is not None
    assert ActionRequired is not None


def test_import_keycloak_admin_extended_methods():
    """Test that extended KeycloakAdmin methods are accessible."""
    from keycloak_extend.keycloak_admin import (
        parse_keycloak_error,
        KeycloakAdmin
    )
    
    assert parse_keycloak_error is not None
    assert KeycloakAdmin is not None


def test_import_keycloak_openid_extended_methods():
    """Test that extended KeycloakOpenID methods are accessible."""
    from keycloak_extend.keycloak_openid import KeycloakOpenID
    
    assert KeycloakOpenID is not None


def test_exception_inheritance():
    """Test that custom exceptions have correct inheritance."""
    from keycloak_extend.exceptions import (
        AuthError,
        UserExistsError,
        UsernameExistsError,
        EmailExistsError,
        AccountLockedError,
        ActionRequired,
    )
    
    # Test inheritance relationships
    assert issubclass(UserExistsError, AuthError)
    assert issubclass(UsernameExistsError, UserExistsError)
    assert issubclass(EmailExistsError, UserExistsError)
    assert issubclass(AccountLockedError, AuthError)
    assert issubclass(ActionRequired, AuthError)


def test_import_parse_keycloak_error_function():
    """Test that parse_keycloak_error function can be imported directly."""
    from keycloak_extend.keycloak_admin import parse_keycloak_error
    assert callable(parse_keycloak_error)