# ruff: noqa: E402, F401
"""
Contrib modules for framework and library integrations.

Available integrations (installed conditionally based on dependencies):
- dependency_injector: AuthContainer for DI
- django: Middleware and decorators for Django
- fastapi: Dependencies and middleware for FastAPI
"""

# Conditional imports based on installed packages

__all__ = []

# Dependency Injector integration
try:
    from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer

    HAS_DEPENDENCY_INJECTOR = True
    __all__.append("AuthContainer")
except ImportError:
    HAS_DEPENDENCY_INJECTOR = False
    AuthContainer = None

# Django integration
try:
    import django
    from cqrs_ddd_auth.contrib.django import (
        TokenRefreshMiddleware as DjangoTokenRefreshMiddleware,
        AuthenticationMiddleware as DjangoAuthenticationMiddleware,
        extract_tokens as django_extract_tokens,
        attach_tokens as django_attach_tokens,
        require_authenticated as django_require_authenticated,
        require_groups as django_require_groups,
    )

    HAS_DJANGO = True
    __all__.extend(
        [
            "DjangoTokenRefreshMiddleware",
            "DjangoAuthenticationMiddleware",
            "django_extract_tokens",
            "django_attach_tokens",
            "django_require_authenticated",
            "django_require_groups",
        ]
    )
except ImportError:
    HAS_DJANGO = False

# FastAPI integration
try:
    import fastapi
    from cqrs_ddd_auth.contrib.fastapi import (
        TokenRefreshMiddleware as FastAPITokenRefreshMiddleware,
        AuthenticationMiddleware as FastAPIAuthenticationMiddleware,
        extract_tokens as fastapi_extract_tokens,
        attach_tokens as fastapi_attach_tokens,
        get_current_user,
        require_authenticated as fastapi_require_authenticated,
        require_groups as fastapi_require_groups,
        create_get_identity_dependency,
    )

    HAS_FASTAPI = True
    __all__.extend(
        [
            "FastAPITokenRefreshMiddleware",
            "FastAPIAuthenticationMiddleware",
            "fastapi_extract_tokens",
            "fastapi_attach_tokens",
            "get_current_user",
            "fastapi_require_authenticated",
            "fastapi_require_groups",
            "create_get_identity_dependency",
        ]
    )
except ImportError:
    HAS_FASTAPI = False

# search_query_dsl integration
try:
    import search_query_dsl
    from cqrs_ddd_auth.contrib.search_query_dsl import (
        FieldMapping,
        ABACConditionConverter,
        AuthorizationFilter,
    )

    __all__.extend(
        [
            "FieldMapping",
            "ABACConditionConverter",
            "AuthorizationFilter",
        ]
    )
except ImportError:
    raise ImportError(
        "search_query_dsl is required for ABAC filter integration. "
        "Install it with: pip install search-query-dsl"
    )
