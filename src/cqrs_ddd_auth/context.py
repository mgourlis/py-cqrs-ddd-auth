"""
Request context and context variable management.

Uses contextvars for request-scoped data propagation.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Optional

from cqrs_ddd_auth.identity import Identity, AnonymousIdentity


@dataclass
class RequestContext:
    """
    Request-scoped context containing identity and metadata.

    This is the primary mechanism for propagating authentication
    state through the application stack.
    """

    identity: Identity
    correlation_id: str
    causation_id: Optional[str] = None
    access_token: Optional[str] = None
    metadata: dict = field(default_factory=dict)


# Global context variable for request-scoped data
request_context: ContextVar[Optional[RequestContext]] = ContextVar(
    "request_context", default=None
)


def get_identity() -> Identity:
    """
    Get current identity from context.

    Returns AnonymousIdentity if no context is set.
    """
    ctx = request_context.get()
    return ctx.identity if ctx else AnonymousIdentity()


def get_access_token() -> Optional[str]:
    """
    Get access token for downstream authorization calls.

    Returns None if no context or token is set.
    """
    ctx = request_context.get()
    return ctx.access_token if ctx else None


def get_correlation_id() -> Optional[str]:
    """Get correlation ID for distributed tracing."""
    ctx = request_context.get()
    return ctx.correlation_id if ctx else None


def get_metadata() -> dict:
    """Get request metadata (IP address, user agent, etc.)."""
    ctx = request_context.get()
    return ctx.metadata if ctx else {}
