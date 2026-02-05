"""
Specialized DDD base classes with identity awareness.

These classes extend the core toolkit classes to automatically
capture technical user IDs and human-readable usernames from
the active identity context.
"""

from typing import Optional, Any
from dataclasses import dataclass
from cqrs_ddd.ddd import Entity, DomainEvent
from cqrs_ddd_auth.identity import get_identity
from cqrs_ddd.domain_event import enrich_event_metadata
from cqrs_ddd.event_store import StoredEvent
import logging

logger = logging.getLogger("cqrs_ddd")


class AuthEntity(Entity):
    """
    Base class for identity-aware entities (technical).
    Automatically captures user_id and username from identity context.
    """

    def __init__(
        self,
        *args,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        identity = get_identity()
        self.user_id = user_id or identity.user_id
        self.username = username or identity.username


@dataclass
class AuthDomainEvent(DomainEvent):
    """
    Base class for identity-aware domain events.
    Automatically captures user_id and username from identity context.
    """

    user_id: Optional[str] = None
    username: Optional[str] = None

    def __post_init__(self):
        identity = get_identity()
        if not self.user_id:
            self.user_id = identity.user_id
        if not self.username:
            self.username = identity.username


@dataclass
class AuthStoredEvent(StoredEvent):
    """
    Identity-aware stored event.
    Adds user_id, username and undone_by to the toolkit's StoredEvent.
    """

    user_id: Optional[str] = None
    username: Optional[str] = None
    undone_by: Optional[str] = None


def enrich_auth_metadata(
    event: Any,
    correlation_id: Optional[str] = None,
    causation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
) -> Any:
    """
    Enrich an event with identity metadata.
    """
    # 1. Standard toolkit enrichment (correlation, causation)
    event = enrich_event_metadata(
        event, correlation_id=correlation_id, causation_id=causation_id
    )

    # 2. Identity enrichment
    identity = get_identity()
    target_user_id = user_id or identity.user_id
    target_username = username or identity.username

    updates = {}
    if target_user_id and hasattr(event, "user_id") and not getattr(event, "user_id"):
        updates["user_id"] = target_user_id
    if (
        target_username
        and hasattr(event, "username")
        and not getattr(event, "username")
    ):
        updates["username"] = target_username

    if not updates:
        return event

    try:
        for key, value in updates.items():
            setattr(event, key, value)
        return event
    except (AttributeError, TypeError):
        if hasattr(event, "model_copy"):
            return event.model_copy(update=updates)
        elif hasattr(event, "copy"):
            return event.copy(update=updates)
        return event

        return event
