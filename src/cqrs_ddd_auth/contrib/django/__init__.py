"""
Django integration for py-cqrs-ddd-auth.

Provides middleware for authentication, token refresh,
and identity context propagation.
"""

from .middleware import (
    TokenRefreshMiddleware,
    AuthenticationMiddleware,
    extract_tokens,
    attach_tokens,
)
from .decorators import (
    require_authenticated,
    require_groups,
)
from .views import get_auth_urls

__all__ = [
    "TokenRefreshMiddleware",
    "AuthenticationMiddleware",
    "extract_tokens",
    "attach_tokens",
    "require_authenticated",
    "require_groups",
    "get_auth_urls",
]
