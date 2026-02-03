"""
FastAPI integration for py-cqrs-ddd-auth.

Provides dependencies, middleware, and utilities for authentication
and token handling in FastAPI applications.
"""

from fastapi.security import OAuth2PasswordBearer

from .dependencies import (
    get_identity,
    get_current_user,
    require_authenticated,
    require_groups,
    extract_tokens,
    get_optional_token,
    create_get_identity_dependency,
)
from .middleware import (
    TokenRefreshMiddleware,
    AuthenticationMiddleware,
    attach_tokens,
)
from .exception_handlers import register_exception_handlers

# OAuth2 scheme for OpenAPI documentation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

__all__ = [
    "get_identity",
    "get_current_user",
    "require_authenticated",
    "require_groups",
    "extract_tokens",
    "get_optional_token",
    "create_get_identity_dependency",
    "TokenRefreshMiddleware",
    "AuthenticationMiddleware",
    "attach_tokens",
    "create_auth_router",
    "oauth2_scheme",
    "register_exception_handlers",
]
