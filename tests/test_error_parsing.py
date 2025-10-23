"""Unit tests for error parsing and translation logic."""

import json
import pytest
from keycloak.exceptions import KeycloakError
from keycloak_extend.keycloak_admin import parse_keycloak_error
from keycloak_extend.exceptions import (
    UsernameExistsError,
    EmailExistsError,
    UserExistsError,
    ValidationError,
    ClientConfigurationError,
    AuthError,
)


class TestErrorParsingLogic:
    """Test the error parsing and translation logic."""

    def test_parse_409_username_conflict_lowercase(self):
        """Test 409 error with lowercase 'username' in message."""
        keycloak_error = KeycloakError(
            error_message=json.dumps({
                "errorMessage": "User exists with same username"
            }),
            response_code=409,
            response_body=json.dumps({
                "errorMessage": "User exists with same username"
            })
        )

        user_payload = {"username": "conflicting_user", "email": "test@test.com"}
        result = parse_keycloak_error(keycloak_error, user_payload)

        assert isinstance(result, UsernameExistsError)
        assert result.username == "conflicting_user"
        assert result.error_code == "username_exists"

    def test_parse_409_username_conflict_uppercase(self):
        """Test 409 error with uppercase 'USERNAME' in message."""
        keycloak_error = KeycloakError(
            error_message=json.dumps({
                "errorMessage": "User exists with same USERNAME"
            }),
            response_code=409,
            response_body=json.dumps({
                "errorMessage": "User exists with same USERNAME"
            })
        )

        user_payload = {"username": "conflicting_user", "email": "test@test.com"}
        result = parse_keycloak_error(keycloak_error, user_payload)

        assert isinstance(result, UsernameExistsError)
        assert result.username == "conflicting_user"

    def test_parse_409_email_conflict_lowercase(self):
        """Test 409 error with lowercase 'email' in message."""
        keycloak_error = KeycloakError(
            error_message=json.dumps({
                "errorMessage": "User exists with same email"
            }),
            response_code=409,
            response_body=json.dumps({
                "errorMessage": "User exists with same email"
            })
        )

        user_payload = {"username": "new_user", "email": "conflicting@test.com"}
        result = parse_keycloak_error(keycloak_error, user_payload)

        assert isinstance(result, EmailExistsError)
        assert result.email == "conflicting@test.com"
        assert result.error_code == "email_exists"

    def test_parse_409_email_conflict_uppercase(self):
        """Test 409 error with uppercase 'EMAIL' in message."""
        keycloak_error = KeycloakError(
            error_message=json.dumps({
                "errorMessage": "User exists with same EMAIL"
            }),
            response_code=409,
            response_body=json.dumps({
                "errorMessage": "User exists with same EMAIL"
            })
        )

        user_payload = {"username": "new_user", "email": "conflicting@test.com"}
        result = parse_keycloak_error(keycloak_error, user_payload)

        assert isinstance(result, EmailExistsError)
        assert result.email == "conflicting@test.com"

    def test_parse_409_generic_conflict(self):
        """Test 409 error without username or email indicators."""
        keycloak_error = KeycloakError(
            error_message="Generic conflict occurred",
            response_code=409,
            response_body="Generic conflict occurred"
        )

        user_payload = {"username": "test_user"}
        result = parse_keycloak_error(keycloak_error, user_payload)

        assert isinstance(result, UserExistsError)
        assert not isinstance(result, (UsernameExistsError, EmailExistsError))

    def test_parse_400_validation_error_complete(self):
        """Test 400 error with complete validation data."""
        keycloak_error = KeycloakError(
            error_message=json.dumps({
                "errorMessage": "Validation failed",
                "field": "email",
                "error": "invalid_email",
                "params": ["invalid@test"]
            }),
            response_code=400,
            response_body=json.dumps({
                "errorMessage": "Validation failed",
                "field": "email",
                "error": "invalid_email",
                "params": ["invalid@test"]
            })
        )

        result = parse_keycloak_error(keycloak_error, {})

        assert isinstance(result, ValidationError)
        assert result.field == "email"
        assert result.error_code == "invalid_email"
        assert result.params == ["invalid@test"]

    def test_parse_400_validation_error_partial(self):
        """Test 400 error with partial validation data."""
        keycloak_error = KeycloakError(
            error_message=json.dumps({
                "errorMessage": "Validation failed"
            }),
            response_code=400,
            response_body=json.dumps({
                "errorMessage": "Validation failed"
            })
        )

        result = parse_keycloak_error(keycloak_error, {})

        assert isinstance(result, ValidationError)
        assert result.field is None
        assert result.error_code is None
        assert result.params is None

    def test_parse_401_client_config_error(self):
        """Test 401 error translation."""
        keycloak_error = KeycloakError(
            error_message="Unauthorized access",
            response_code=401,
            response_body="Unauthorized access"
        )

        result = parse_keycloak_error(keycloak_error, {})

        assert isinstance(result, ClientConfigurationError)
        assert "configuration" in str(result).lower() or "permission" in str(result).lower()

    def test_parse_403_client_config_error(self):
        """Test 403 error translation."""
        keycloak_error = KeycloakError(
            error_message="Forbidden access",
            response_code=403,
            response_body="Forbidden access"
        )

        result = parse_keycloak_error(keycloak_error, {})

        assert isinstance(result, ClientConfigurationError)
        assert "configuration" in str(result).lower() or "permission" in str(result).lower()

    def test_parse_generic_error(self):
        """Test generic error translation."""
        keycloak_error = KeycloakError(
            error_message="Internal server error",
            response_code=500,
            response_body="Internal server error"
        )

        result = parse_keycloak_error(keycloak_error, {})

        assert isinstance(result, AuthError)
        assert not isinstance(result, (
            UsernameExistsError, EmailExistsError, UserExistsError,
            ValidationError, ClientConfigurationError
        ))
        assert "unexpected" in str(result).lower()
        assert "500" in str(result)

    def test_parse_keycloak_error_preserves_original(self):
        """Test that parsed errors preserve the original KeycloakError."""
        original_error = KeycloakError(
            error_message="Test error",
            response_code=500,
            response_body="Test error"
        )

        result = parse_keycloak_error(original_error, {})

        assert result.original_error == original_error

    def test_parse_409_no_json_body(self):
        """Test 409 error with non-JSON body falls back to generic UserExistsError."""
        keycloak_error = KeycloakError(
            error_message="Plain text error",
            response_code=409,
            response_body="Plain text error"
        )

        user_payload = {"username": "test_user"}
        result = parse_keycloak_error(keycloak_error, user_payload)

        assert isinstance(result, UserExistsError)
        assert str(result) == "Plain text error"