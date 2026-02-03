"""
Exception handlers for FastAPI.

Maps domain errors to HTTP exceptions.
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse

from cqrs_ddd_auth.domain.errors import (
    AuthenticationError,
    AuthorizationError,
    UserNotFoundError,
    UserManagementError,
    OTPError,
    InvalidOTPError,
    OTPRateLimitError,
)


async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """Handle AuthenticationError (401)."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


async def authorization_error_handler(request: Request, exc: AuthorizationError):
    """Handle AuthorizationError (403)."""
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


async def user_not_found_error_handler(request: Request, exc: UserNotFoundError):
    """Handle UserNotFoundError (404)."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


async def invalid_otp_error_handler(request: Request, exc: InvalidOTPError):
    """Handle InvalidOTPError (400)."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


async def otp_rate_limit_error_handler(request: Request, exc: OTPRateLimitError):
    """Handle OTPRateLimitError (429)."""
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


async def domain_error_handler(request: Request, exc: Exception):
    """Handle generic domain errors (400)."""

    # Check for known base classes if not caught by specific handlers
    if isinstance(exc, (UserManagementError, OTPError)):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": getattr(exc, "code", "ERROR"), "message": str(exc)},
        )

    # Should not happen if all specific handlers are registered, but good fallback
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "INTERNAL_ERROR", "message": "An internal error occurred"},
    )


def register_exception_handlers(app):
    """
    Register uniform exception handlers for the FastAPI app.

    Args:
        app: The FastAPI application instance
    """
    app.add_exception_handler(AuthenticationError, authentication_error_handler)
    app.add_exception_handler(AuthorizationError, authorization_error_handler)
    app.add_exception_handler(UserNotFoundError, user_not_found_error_handler)
    app.add_exception_handler(InvalidOTPError, invalid_otp_error_handler)
    app.add_exception_handler(OTPRateLimitError, otp_rate_limit_error_handler)
    app.add_exception_handler(UserManagementError, domain_error_handler)
    app.add_exception_handler(OTPError, domain_error_handler)
