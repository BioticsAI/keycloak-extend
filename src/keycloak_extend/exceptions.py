class AuthError(Exception):
    """Base exception for all custom authentication errors in this library."""

    def __init__(self, message, error_code=None, original_error=None):
        super().__init__(message)
        self.error_code = error_code
        self.original_error = original_error


class UserExistsError(AuthError):
    """Base exception for conflicts with existing users."""

    pass


class UsernameExistsError(UserExistsError):
    """Raised when a user with the same username already exists."""

    def __init__(self, username, message="User already exists", original_error=None):
        self.username = username
        super().__init__(f"{message}: username '{username}'", "username_exists", original_error)


class EmailExistsError(UserExistsError):
    """Raised when a user with the same email already exists."""

    def __init__(self, email, message="User already exists", original_error=None):
        self.email = email
        super().__init__(f"{message}: email '{email}'", "email_exists", original_error)


class ValidationError(AuthError):
    """Raised when user data fails server-side validation."""

    def __init__(
        self, message, field=None, error_code=None, params=None, original_error=None
    ):
        super().__init__(message, error_code, original_error)
        self.message = message
        self.field = field
        self.params = params


class ClientConfigurationError(AuthError):
    """Raised for 401/403 errors indicating a client-side configuration issue."""

    pass


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked due to brute force protection."""

    def __init__(self, username, message=None, original_error=None):
        self.username = username
        if message is None:
            message = f"Account is temporarily locked due to too many failed login attempts: {username}"
        super().__init__(message, "account_locked", original_error)


class ActionRequired(AuthError):
    """Raised when user authentication is successful but requires additional action."""

    def __init__(self, action, message=None, original_error=None):
        self.action = action
        if message is None:
            message = f"Action required: {action}"
        super().__init__(message, None, original_error)

class CantReusePassword(AuthError):
    def __init__(self, original_error=None):
        super().__init__("Can't reuse a password from the last set 5 passwords", "cant_reuse_password", original_error)