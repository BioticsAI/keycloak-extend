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
        self.error_code = "username_exists"
        super().__init__(f"{message}: username '{username}'", original_error)


class EmailExistsError(UserExistsError):
    """Raised when a user with the same email already exists."""

    def __init__(self, email, message="User already exists", original_error=None):
        self.email = email
        self.error_code = "email_exists"
        super().__init__(f"{message}: email '{email}'", original_error)


class ValidationError(AuthError):
    """Raised when user data fails server-side validation."""

    def __init__(
        self, message, field=None, error_code=None, params=None, original_error=None
    ):
        super().__init__(message, original_error)
        self.field = field
        self.error_code = error_code
        self.params = params


class ClientConfigurationError(AuthError):
    """Raised for 401/403 errors indicating a client-side configuration issue."""

    pass


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked due to brute force protection."""

    def __init__(self, username, message="Account is temporarily locked due to too many failed login attempts", original_error=None):
        self.username = username
        self.error_code = "account_locked"
        super().__init__(message, original_error)


class ActionRequired(AuthError):
    """Raised when user authentication is successful but requires additional action."""

    def __init__(self, action, message=None, original_error=None):
        self.action = action
        if message is None:
            message = f"Action required: {action}"
        super().__init__(message, original_error)
