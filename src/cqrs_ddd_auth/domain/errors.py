"""
Domain errors for the authentication and authorization system.

These errors provide a consistent interface for reporting failures
across different adapters and layers.
"""

from typing import Optional, Any


class AuthDomainError(Exception):
    """Base class for all auth domain errors."""

    def __init__(
        self,
        message: str,
        code: str = "AUTH_ERROR",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class AuthenticationError(AuthDomainError):
    """Raised when authentication fails (invalid credentials, expired, etc.)."""

    def __init__(
        self,
        message: str = "Authentication failed",
        code: str = "AUTHENTICATION_FAILED",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code, details)


class InvalidTokenError(AuthenticationError):
    """Raised when a token is invalid, expired, or malformed."""

    def __init__(
        self,
        message: str = "Invalid token",
        code: str = "INVALID_TOKEN",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code, details)


class AuthorizationError(AuthDomainError):
    """Raised when a user is authenticated but lacks permission."""

    def __init__(
        self,
        message: str = "Access denied",
        resource_type: Optional[str] = None,
        action: Optional[str] = None,
        resource_ids: Optional[list[str]] = None,
        code: str = "PERMISSION_DENIED",
    ):
        details = {
            "resource_type": resource_type,
            "action": action,
            "resource_ids": resource_ids,
        }
        # Filter None values
        details = {k: v for k, v in details.items() if v is not None}
        super().__init__(message, code, details)
        self.resource_type = resource_type
        self.action = action
        self.resource_ids = resource_ids


class OTPError(AuthDomainError):
    """Base class for OTP-related errors."""

    pass


class InvalidOTPError(OTPError):
    """Raised when an OTP code is invalid."""

    def __init__(
        self,
        message: str = "Invalid OTP code",
        code: str = "INVALID_OTP",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code, details)


class OTPRateLimitError(OTPError):
    """Raised when too many OTP attempts are made."""

    def __init__(
        self,
        message: str = "Too many attempts",
        code: str = "OTP_RATE_LIMIT",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code, details)


class UserManagementError(AuthDomainError):
    """Raised when a user management operation fails."""

    def __init__(
        self,
        message: str,
        code: str = "USER_MGMT_ERROR",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code, details)


class UserNotFoundError(UserManagementError):
    """Raised when a user is not found."""

    def __init__(
        self,
        message: str = "User not found",
        code: str = "USER_NOT_FOUND",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code, details)
