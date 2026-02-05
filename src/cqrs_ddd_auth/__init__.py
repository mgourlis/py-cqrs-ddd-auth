"""
py-cqrs-ddd-auth: Toolkit-native authentication and authorization library.

Built using CQRS, DDD, and Saga patterns from py-cqrs-ddd-toolkit.
"""

__version__ = "0.1.0"

# Core identity exports
from cqrs_ddd_auth.identity import (
    Identity,
    AnonymousIdentity,
    SystemIdentity,
    AuthenticatedIdentity,
)
from cqrs_ddd_auth.ddd import (
    AuthEntity,
    AuthDomainEvent,
    AuthStoredEvent,
)
from cqrs_ddd_auth.undo import AuthUndoService
from cqrs_ddd_auth.event_store import AuthInMemoryEventStore

try:
    from cqrs_ddd_auth.infrastructure.persistence.sqlalchemy_event_store import (
        AuthSQLAlchemyEventStore,
    )
except ImportError:
    # SQLAlchemy might not be installed
    AuthSQLAlchemyEventStore = None

from cqrs_ddd_auth.contrib.pydantic import HAS_PYDANTIC

if HAS_PYDANTIC:
    from cqrs_ddd_auth.contrib.pydantic import (
        PydanticAuthEntity,
        PydanticAuthDomainEvent,
    )
from cqrs_ddd_auth.context import (
    RequestContext,
    request_context,
    get_identity,
    get_access_token,
)

# Middleware exports
from cqrs_ddd_auth.middleware import (
    AuthorizationMiddleware,
    PermittedActionsMiddleware,
    AuthorizationConfig,
    PermittedActionsConfig,
    AuthorizationError,
    authorize,
    permitted_actions,
    register_abac_middleware,
)

__all__ = [
    # Version
    "__version__",
    # Identity
    "Identity",
    "AnonymousIdentity",
    "SystemIdentity",
    "AuthenticatedIdentity",
    # Context
    "RequestContext",
    "request_context",
    "get_identity",
    "get_access_token",
    # Middleware
    "AuthorizationMiddleware",
    "PermittedActionsMiddleware",
    "AuthorizationConfig",
    "PermittedActionsConfig",
    "AuthorizationError",
    "authorize",
    "permitted_actions",
    "register_abac_middleware",
    # DDD
    "AuthEntity",
    "AuthDomainEvent",
    "AuthStoredEvent",
    "AuthUndoService",
    # Event Store
    "AuthInMemoryEventStore",
    "AuthSQLAlchemyEventStore",
]

if HAS_PYDANTIC:
    __all__ += [
        "PydanticAuthEntity",
        "PydanticAuthDomainEvent",
    ]
