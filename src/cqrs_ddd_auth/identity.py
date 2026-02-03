"""
Identity protocols and implementations.

The toolkit defines Identity as a Protocol—a contract that the host
application fulfills. The domain layer never knows how the identity
was resolved.

Context propagation is handled via contextvars for request-scoped data.
"""

from contextvars import ContextVar
from typing import Protocol, Optional, runtime_checkable
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════
# CONTEXT VARIABLES
# ═══════════════════════════════════════════════════════════════

_identity_context: ContextVar["Identity"] = ContextVar("identity")
_access_token_context: ContextVar[Optional[str]] = ContextVar(
    "access_token", default=None
)


# ═══════════════════════════════════════════════════════════════
# PROTOCOL
# ═══════════════════════════════════════════════════════════════


@runtime_checkable
class Identity(Protocol):
    """Protocol for identity information passed to handlers."""

    @property
    def user_id(self) -> str:
        """Unique identifier for the user."""
        ...

    @property
    def username(self) -> str:
        """Human-readable username."""
        ...

    @property
    def groups(self) -> list[str]:
        """Groups/roles the user belongs to."""
        ...

    @property
    def permissions(self) -> list[str]:
        """Direct permissions assigned to the user."""
        ...

    @property
    def tenant_id(self) -> Optional[str]:
        """Tenant identifier for multi-tenant applications."""
        ...

    @property
    def is_authenticated(self) -> bool:
        """Whether the identity represents an authenticated user."""
        ...

    @property
    def is_system(self) -> bool:
        """Whether this is a system/internal identity."""
        ...


# ═══════════════════════════════════════════════════════════════
# IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════


class AnonymousIdentity:
    """Default identity for unauthenticated requests."""

    user_id = "anonymous"
    username = "anonymous"
    groups: list[str] = []
    permissions: list[str] = []
    tenant_id = None
    is_authenticated = False
    is_system = False


class SystemIdentity:
    """Identity for internal system processes (event handlers, sagas)."""

    user_id = "system"
    username = "system"
    groups = ["*"]
    permissions = ["*"]
    tenant_id = None
    is_authenticated = True
    is_system = True


@dataclass
class AuthenticatedIdentity:
    """Concrete identity for authenticated users."""

    user_id: str
    username: str
    groups: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    tenant_id: Optional[str] = None
    is_authenticated: bool = True
    is_system: bool = False


# ═══════════════════════════════════════════════════════════════
# CONTEXT MANAGEMENT
# ═══════════════════════════════════════════════════════════════


def get_identity() -> Identity:
    """
    Get current identity from context.

    Returns AnonymousIdentity if no identity has been set.
    """
    try:
        return _identity_context.get()
    except LookupError:
        return AnonymousIdentity()


def set_identity(identity: Identity) -> None:
    """
    Set identity in current context.

    Called by authentication middleware after token validation.
    """
    _identity_context.set(identity)


def get_access_token() -> Optional[str]:
    """
    Get access token from context.

    Used for downstream authorization calls (e.g., to ABAC service).
    """
    return _access_token_context.get()


def set_access_token(token: str) -> None:
    """
    Set access token in current context.

    Called by authentication middleware alongside set_identity.
    """
    _access_token_context.set(token)


def clear_context() -> None:
    """
    Clear identity and token from context.

    Called at the end of request processing.
    """
    try:
        _identity_context.set(AnonymousIdentity())
        _access_token_context.set(None)
    except LookupError:
        pass
