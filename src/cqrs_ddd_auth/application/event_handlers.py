"""
Event handlers for identity change events.

These handlers trigger automatic IdP-to-ABAC synchronization
when identity-related changes occur (user created, roles assigned, etc.).
"""

import logging
from typing import Union

from cqrs_ddd.core import EventHandler

from cqrs_ddd_auth.domain.events import (
    UserCreatedInIdP,
    UserUpdatedInIdP,
    UserDeletedInIdP,
    UserRolesAssigned,
    UserRolesRemoved,
    UserAddedToGroups,
    UserRemovedFromGroups,
)
from cqrs_ddd_auth.infrastructure.ports.authorization import ABACAuthorizationPort


logger = logging.getLogger("cqrs_ddd_auth.event_handlers")


# Type alias for all identity change events
IdentityChangeEvent = Union[
    UserCreatedInIdP,
    UserUpdatedInIdP,
    UserDeletedInIdP,
    UserRolesAssigned,
    UserRolesRemoved,
    UserAddedToGroups,
    UserRemovedFromGroups,
]


class IdentityChangeSyncHandler(EventHandler):
    """
    Event handler that triggers IdP-to-ABAC sync on identity changes.

    This handler listens to identity change events and triggers
    synchronization to keep the ABAC engine's principal cache up-to-date.

    Register this handler as a background handler for each identity event type:

        dispatcher.register(UserCreatedInIdP, IdentityChangeSyncHandler(abac), priority=False)
        dispatcher.register(UserRolesAssigned, IdentityChangeSyncHandler(abac), priority=False)
        # ... etc

    Or use the convenience function:

        register_identity_sync_handlers(dispatcher, abac_adapter)

    Note: This uses the ABAC engine's built-in sync which syncs ALL principals.
    For high-frequency changes, consider debouncing or batching sync calls.
    """

    def __init__(self, abac_adapter: ABACAuthorizationPort):
        self.abac_adapter = abac_adapter

    async def handle(self, event: IdentityChangeEvent) -> None:
        """
        Handle identity change event by triggering ABAC sync.

        Args:
            event: Any identity change event
        """
        event_type = type(event).__name__

        logger.info(f"Identity change detected: {event_type}, triggering ABAC sync")

        try:
            if hasattr(self.abac_adapter, "sync_from_idp"):
                result = await self.abac_adapter.sync_from_idp()
                # Result is {"status": "sync_started"} - background task initiated
                logger.info(f"ABAC sync initiated after {event_type}: {result}")
            else:
                logger.warning(
                    "ABAC adapter does not support sync_from_idp, "
                    "skipping automatic sync"
                )
        except Exception as e:
            # Log but don't fail - sync errors shouldn't break the main flow
            logger.error(f"ABAC sync failed after {event_type}: {e}", exc_info=True)


def register_identity_sync_handlers(
    dispatcher,
    abac_adapter: ABACAuthorizationPort,
    priority: bool = False,
) -> None:
    """
    Register identity change sync handlers with an event dispatcher.

    This convenience function registers the IdentityChangeSyncHandler
    for all identity change event types.

    Args:
        dispatcher: Event dispatcher (e.g., from py-cqrs-ddd-toolkit)
        abac_adapter: ABAC adapter for sync operations
        priority: If True, sync runs synchronously before response.
            Default False (background, fire-and-forget).

    Example:
        from cqrs_ddd.dispatcher import EventDispatcher
        from cqrs_ddd_auth.application.event_handlers import register_identity_sync_handlers

        dispatcher = EventDispatcher()
        register_identity_sync_handlers(dispatcher, abac_adapter)
    """
    handler = IdentityChangeSyncHandler(abac_adapter)

    event_types = [
        UserCreatedInIdP,
        UserUpdatedInIdP,
        UserDeletedInIdP,
        UserRolesAssigned,
        UserRolesRemoved,
        UserAddedToGroups,
        UserRemovedFromGroups,
    ]

    for event_type in event_types:
        dispatcher.register(event_type, handler, priority=priority)

    logger.info(
        f"Registered identity sync handlers for {len(event_types)} event types "
        f"(priority={priority})"
    )


__all__ = [
    "IdentityChangeSyncHandler",
    "register_identity_sync_handlers",
]
