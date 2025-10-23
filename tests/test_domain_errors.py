"""Tests for custom domain exceptions in keycloak_extend."""

import json
import pytest
from keycloak.exceptions import KeycloakError
from keycloak_extend.exceptions import (
    AuthError,
    UserExistsError,
    UsernameExistsError,
    EmailExistsError,
    ValidationError,
    ClientConfigurationError,
    AccountLockedError,
    ActionRequired,
    CantReusePassword,
)


class TestDomainExceptions:
    """Test custom domain exception classes."""

    def test_auth_error_creation(self):
        """Test AuthError base class creation."""
        # Test with message only
        error = AuthError("Generic authentication error")
        assert str(error) == "Generic authentication error"
        assert error.error_code is None
        assert error.original_error is None

        # Test with all parameters
        original = Exception("Original error")
        error = AuthError(
            "Detailed error", error_code="test_code", original_error=original
        )
        assert str(error) == "Detailed error"
        assert error.error_code == "test_code"
        assert error.original_error == original

    def test_user_exists_error_inheritance(self):
        """Test UserExistsError inherits from AuthError."""
        error = UserExistsError("User exists")
        assert isinstance(error, AuthError)
        assert str(error) == "User exists"

    def test_username_exists_error_creation(self):
        """Test UsernameExistsError with username attribute."""
        error = UsernameExistsError("testuser")
        assert isinstance(error, UserExistsError)
        assert error.username == "testuser"
        assert error.error_code == "username_exists"
        assert "testuser" in str(error)
        assert "username" in str(error).lower()

    def test_email_exists_error_creation(self):
        """Test EmailExistsError with email attribute."""
        error = EmailExistsError("test@example.com")
        assert isinstance(error, UserExistsError)
        assert error.email == "test@example.com"
        assert error.error_code == "email_exists"
        assert "test@example.com" in str(error)
        assert "email" in str(error).lower()

    def test_validation_error_creation(self):
        """Test ValidationError with field/error_code params."""
        # Test basic creation
        error = ValidationError("Invalid input")
        assert isinstance(error, AuthError)
        assert str(error) == "Invalid input"
        assert error.field is None
        assert error.error_code is None
        assert error.params is None

        # Test with all parameters
        error = ValidationError(
            "Field validation failed",
            field="email",
            error_code="invalid_email",
            params={"value": "invalid-email"},
        )
        assert error.field == "email"
        assert error.error_code == "invalid_email"
        assert error.params == {"value": "invalid-email"}

    def test_client_configuration_error_creation(self):
        """Test ClientConfigurationError creation."""
        error = ClientConfigurationError("Client config error")
        assert isinstance(error, AuthError)
        assert str(error) == "Client config error"

    def test_account_locked_error_creation(self):
        """Test AccountLockedError with username attribute."""
        error = AccountLockedError("locked_user")
        assert isinstance(error, AuthError)
        assert error.username == "locked_user"
        assert error.error_code == "account_locked"
        assert "locked_user" in str(error)
        assert "locked" in str(error).lower()

    def test_action_required_creation(self):
        """Test ActionRequired with action attribute."""
        # Test with default message
        error = ActionRequired("update_password")
        assert isinstance(error, AuthError)
        assert error.action == "update_password"
        assert "update_password" in str(error)

        # Test with custom message
        error = ActionRequired("update_password", "Custom action required")
        assert error.action == "update_password"
        assert str(error) == "Custom action required"

        # Test with original error
        original = Exception("Original")
        error = ActionRequired("update_password", original_error=original)
        assert error.original_error == original

    def test_cant_reuse_password_error(self):
        """Test CantReusePassword exception."""
        # Test default message
        error = CantReusePassword()
        assert error.error_code == "cant_reuse_password"
        assert "Can't reuse a password from the last set 5 passwords" in str(error)

        # Test with original error
        original = Exception("Original")
        error = CantReusePassword(original_error=original)
        assert error.original_error == original
        assert error.error_code == "cant_reuse_password"

    def test_auth_error_inheritance_chain(self):
        """Verify all domain errors inherit from AuthError."""
        errors_to_test = [
            UserExistsError("test"),
            UsernameExistsError("test"),
            EmailExistsError("test@test.com"),
            ValidationError("test"),
            ClientConfigurationError("test"),
            AccountLockedError("test"),
            ActionRequired("test"),
            CantReusePassword(),
        ]

        for error in errors_to_test:
            assert isinstance(error, AuthError), f"{type(error)} should inherit from AuthError"

