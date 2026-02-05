"""
Identity-aware In-Memory Event Store.
"""

from typing import Any, Optional
from datetime import datetime, timezone
from cqrs_ddd.event_store import InMemoryEventStore
from cqrs_ddd_auth.ddd import AuthStoredEvent, get_identity


class AuthInMemoryEventStore(InMemoryEventStore):
    """
    In-memory event store that captures user identity.
    """

    async def append(
        self, event: Any, expected_version: Optional[int] = None
    ) -> AuthStoredEvent:
        """
        Append event and capture identity.
        """
        # 1. Standard append (sets versions, etc.)
        # We'll mostly re-implement to return AuthStoredEvent
        key = (event.aggregate_type, event.aggregate_id)
        current_version = self._versions.get(key, 0)

        if expected_version is not None and current_version != expected_version:
            from cqrs_ddd.exceptions import CQRSDDDError

            raise CQRSDDDError(
                f"Concurrency error: expected version {expected_version}, "
                f"but current version is {current_version}"
            )

        new_version = current_version + 1
        self._versions[key] = new_version

        identity = get_identity()

        # Capture from event (if enriched) or context
        user_id = getattr(event, "user_id", None) or identity.user_id
        username = getattr(event, "username", None) or identity.username

        stored = AuthStoredEvent(
            id=self._next_id,
            event_id=event.event_id,
            aggregate_type=event.aggregate_type,
            aggregate_id=event.aggregate_id,
            event_type=event.event_type,
            event_version=event.version,
            occurred_at=event.occurred_at,
            correlation_id=event.correlation_id,
            causation_id=event.causation_id,
            payload=event.to_dict(),
            aggregate_version=new_version,
            user_id=user_id,
            username=username,
        )

        self._events.append(stored)
        self._next_id += 1

        return stored

    async def mark_as_undone(
        self, event_id: str, undo_event_id: Optional[str] = None
    ) -> None:
        """Mark as undone and capture who did it."""
        identity = get_identity()
        for event in self._events:
            if event.event_id == event_id:
                event.is_undone = True
                event.undone_at = datetime.now(timezone.utc)
                event.undo_event_id = undo_event_id
                if isinstance(event, AuthStoredEvent):
                    event.undone_by = identity.user_id or identity.username
                break
