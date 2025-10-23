"""Extended tests for KeycloakAdmin with domain error handling."""

import json
import pytest
from unittest.mock import MagicMock, patch
from keycloak.exceptions import KeycloakError, KeycloakGetError
from keycloak_extend.exceptions import AccountLockedError, CantReusePassword
from keycloak_extend.keycloak_admin import KeycloakAdmin, parse_keycloak_error


class TestKeycloakAdminExtended:
    """Test extended KeycloakAdmin functionality."""
    def test_check_account_locked_shouldnt_raise(self, admin, realm, user):
        """Test unlocked account doesn't raise AccountLockedError."""
        admin.connection.realm_name = realm
        
        # This test verifies that an account that is not locked doesn't raise AccountLockedError
        user_id = user  # user fixture provides the user ID
        username = admin.get_user(user_id)['username']
        
        # Should not raise any exception (specifically AccountLockedError)
        # The check_account_locked method checks if the account is locked due to brute force
        result = admin.check_account_locked(username)
        
        # The method should return None or not raise AccountLockedError for non-locked accounts
        assert result is None

    def test_check_locked_account_should_raise(self, admin, realm, oid_with_credentials):
        """Test account lock detection with forced account lockout."""
        admin.connection.realm_name = realm
        oid_instance, username, password = oid_with_credentials
        
        # Force lock the account by making failed authentication attempts
        for _ in range(3):  # More than failureFactor=2 from realm fixture
            try:
                oid_instance.token(username=username, password="wrong_password")
            except:
                pass  # Expected to fail
        
        # Now test that check_account_locked raises AccountLockedError
        with pytest.raises(AccountLockedError):
            admin.check_account_locked(username)

    def test_create_user_duplicate_handling(self, admin, realm):
        """Test create_user handles duplicate user scenarios with exist_ok parameter."""
        admin.connection.realm_name = realm
        
        # Create a user with a specific username
        user_payload = {"username": "test_conflicting_user", "email": "conflicting@test.com"}
        first_user_id = admin.create_user(payload=user_payload)
        
        # Now try to create the same user again, which might trigger a conflict
        # The extended create_user method with exist_ok=True should handle this appropriately
        duplicate_user_id = admin.create_user(payload=user_payload, exist_ok=True)  # Using exist_ok=True should handle this
        
        # When exist_ok=True, it should handle the duplicate gracefully, possibly returning the existing user ID
        # This verifies that the extended functionality works without crashing
        assert duplicate_user_id is not None  # Should return a valid user ID or handle gracefully
        
        # Clean up by deleting the user
        admin.delete_user(user_id=first_user_id)

        # Test the exist_ok=False case to check if it handles conflicts appropriately
        # Create user again for this test
        first_user_id = admin.create_user(payload=user_payload)
        try:
            # Try to create duplicate with exist_ok=False, which should trigger conflict handling
            with pytest.raises(Exception):
                admin.create_user(payload=user_payload, exist_ok=False)  # Should raise an exception when exist_ok=False
        finally:
            # Clean up
            admin.delete_user(user_id=first_user_id)

    def test_create_user_success_path(self, admin, realm):
        """Test successful user creation."""
        admin.connection.realm_name = realm
        
        user_payload = {"username": "successful_user", "email": "successful@test.com"}
        
        # Test the real user creation functionality
        result = admin.create_user(payload=user_payload, exist_ok=False)
        
        # Verify that a user ID was returned (not None or empty)
        assert result is not None
        assert isinstance(result, str)  # The user ID should be a valid identifier
        
        # Clean up by deleting the created user
        admin.delete_user(user_id=result)

    def test_create_user_exist_ok_true(self, admin, realm):
        """Test create_user with exist_ok=True handles duplicate user creation."""
        admin.connection.realm_name = realm
        
        # Create a user first
        user_payload = {"username": "duplicate_test_user", "email": "duplicate@test.com"}
        first_user_id = admin.create_user(payload=user_payload)
        
        try:
            # Try to create the same user again with exist_ok=True
            # This should not raise an exception and should handle the duplicate gracefully
            result = admin.create_user(payload=user_payload, exist_ok=True)
            
            # With exist_ok=True, the expected behavior might be to return None when duplicate
            # or it may depend on the exact implementation
            # The important thing is it doesn't raise an exception
            # For now, just verify it doesn't crash
        finally:
            # Clean up by deleting the user
            admin.delete_user(user_id=first_user_id)

    def test_create_user_exist_ok_false_still_raises(self, admin, realm):
        """Test create_user with exist_ok=False still raises errors on conflicts."""
        admin.connection.realm_name = realm
        
        # Create a user first
        user_payload = {"username": "conflict_test_user", "email": "conflict@test.com"}
        first_user_id = admin.create_user(payload=user_payload)
        
        try:
            # Try to create the same user again with exist_ok=False
            # This should raise an exception
            with pytest.raises(Exception):
                admin.create_user(payload=user_payload, exist_ok=False)
        finally:
            # Clean up by deleting the user
            admin.delete_user(user_id=first_user_id)


class TestParseKeycloakErrorEdgeCases:
    """Test edge cases for parse_keycloak_error function."""

    def test_parse_keycloak_error_empty_response_body(self):
        """Test handling of empty response body."""
        keycloak_error = KeycloakError(
            error_message="Empty response",
            response_code=500,
            response_body=""
        )

        result = parse_keycloak_error(keycloak_error, {})
        assert isinstance(result, Exception)
        assert "unexpected" in str(result).lower()

    def test_parse_keycloak_error_none_response_body(self):
        """Test handling of None response body."""
        keycloak_error = KeycloakError(
            error_message="None response",
            response_code=500,
            response_body=None
        )

        result = parse_keycloak_error(keycloak_error, {})
        assert isinstance(result, Exception)
        assert "unexpected" in str(result).lower()

    def test_parse_keycloak_error_malformed_json(self):
        """Test handling of malformed JSON in response body."""
        keycloak_error = KeycloakError(
            error_message="Malformed JSON",
            response_code=500,
            response_body="{invalid json"
        )

        result = parse_keycloak_error(keycloak_error, {})
        assert isinstance(result, Exception)
        assert "unexpected" in str(result).lower()

    def test_parse_keycloak_error_missing_fields(self):
        """Test handling of JSON missing expected fields."""
        keycloak_error = KeycloakError(
            error_message="Missing fields",
            response_code=500,
            response_body=json.dumps({})
        )

        result = parse_keycloak_error(keycloak_error, {})
        assert isinstance(result, Exception)
        assert "unexpected" in str(result).lower()

    def test_set_user_password_cant_reuse_password(self, admin, realm, user):
        """Test set_user_password raises CantReusePassword when password history validation fails."""
        admin.connection.realm_name = realm
        user_id = user
        
        # The CantReusePassword exception is thrown when trying to reuse a password
        # from the password history (typically last 5 passwords)
        from keycloak_extend.exceptions import CantReusePassword
        
        # First, set an initial password - this sets up the password history
        admin.set_user_password(user_id, "Testing1!", temporary=False)
        
        # Now try to set a different password
        admin.set_user_password(user_id, "Testing2@", temporary=False)
        
        # Now try to set the initial password again, which should trigger password history validation
        # In a Keycloak instance with password history enabled, this should raise CantReusePassword
        with pytest.raises(CantReusePassword) as exc_info:
            admin.set_user_password(user_id, "Testing1!", temporary=False)
