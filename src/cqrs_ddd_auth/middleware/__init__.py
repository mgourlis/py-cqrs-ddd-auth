"""Authorization middleware for CQRS commands and queries."""

from cqrs_ddd_auth.middleware.authorization import (
    AuthorizationMiddleware,
    PermittedActionsMiddleware,
    AuthorizationConfig,
    PermittedActionsConfig,
    AuthorizationError,
    # Convenience functions
    authorize,
    permitted_actions,
    # Registry integration
    register_abac_middleware,
)

__all__ = [
    "AuthorizationMiddleware",
    "PermittedActionsMiddleware",
    "AuthorizationConfig",
    "PermittedActionsConfig",
    "AuthorizationError",
    # Convenience functions
    "authorize",
    "permitted_actions",
    # Registry integration
    "register_abac_middleware",
]
