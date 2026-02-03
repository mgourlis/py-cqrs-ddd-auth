"""
Identity Provider Sync Commands.

Commands for synchronizing identity provider data (users, roles, groups)
to the ABAC policy engine cache. This enables the ABAC engine to make
authorization decisions based on current IdP state.

Typically triggered:
- On a schedule (e.g., every 5 minutes)
- After identity change events (user created, roles assigned, etc.)
"""

from dataclasses import dataclass
from typing import Optional, Any
import logging

from cqrs_ddd.core import Command, CommandHandler, CommandResponse

from cqrs_ddd_auth.infrastructure.ports.authorization import ABACAuthorizationPort


logger = logging.getLogger("cqrs_ddd_auth.sync")


# ═══════════════════════════════════════════════════════════════
# SYNC RESULT
# ═══════════════════════════════════════════════════════════════


@dataclass
class SyncResult:
    """
    Result of triggering an identity provider sync operation.
    """

    triggered: bool = True
    message: str = "Sync initiated in background"
    abac_response: Optional[dict[str, Any]] = None


# ═══════════════════════════════════════════════════════════════
# SYNC COMMAND
# ═══════════════════════════════════════════════════════════════


@dataclass(kw_only=True)
class SyncIdentityProvider(Command):
    """
    Sync identity provider data to ABAC cache.

    This command triggers synchronization of users, roles, and groups
    from the identity provider (e.g., Keycloak) to the ABAC policy
    engine's principal cache.

    The ABAC engine uses this data for:
    - Role-based policy evaluation
    - Group membership checks
    - Principal attribute lookups

    Example usage:
        # Scheduled sync
        command = SyncIdentityProvider()
        result = await handler.handle(command)

        # After identity change event
        command = SyncIdentityProvider(reason="UserCreated event")
        result = await handler.handle(command)
    """

    reason: Optional[str] = None  # Optional reason for audit logging


# ═══════════════════════════════════════════════════════════════
# SYNC HANDLER
# ═══════════════════════════════════════════════════════════════


class SyncIdentityProviderHandler(CommandHandler[SyncResult]):
    """
    Handle identity provider sync to ABAC cache.

    Uses the ABAC engine's built-in sync endpoint which communicates
    directly with the IdP (e.g., Keycloak) and updates its principal cache.

    Usage:
        handler = SyncIdentityProviderHandler(abac_adapter=abac_adapter)
        result = await handler.handle(SyncIdentityProvider())
        print(f"Synced {result.stats.total_synced} items")
    """

    def __init__(self, abac_adapter: ABACAuthorizationPort):
        super().__init__()
        self.abac_adapter = abac_adapter

    async def handle(
        self, command: SyncIdentityProvider
    ) -> CommandResponse[SyncResult]:
        """
        Execute the sync operation.

        Returns:
            CommandResponse containing SyncResult with stats and status
        """
        logger.info(f"Starting IdP sync: reason={command.reason or 'scheduled'}")

        try:
            if not hasattr(self.abac_adapter, "sync_from_idp"):
                raise NotImplementedError(
                    "ABAC adapter does not support sync_from_idp."
                )

            # Trigger sync - fire and forget
            # The SDK method returns a dict like {"status": "sync_started"}
            # It does NOT return stats or wait for completion
            response = await self.abac_adapter.sync_from_idp()

            result = SyncResult(
                triggered=True,
                abac_response=response,
            )

            logger.info(f"IdP sync initiated: {result}")

            return CommandResponse(result=result)

        except Exception as e:
            logger.exception(f"IdP sync failed: {e}")
            return CommandResponse(
                result=SyncResult(triggered=False, message=f"Sync failed: {str(e)}")
            )


__all__ = [
    "SyncIdentityProvider",
    "SyncIdentityProviderHandler",
    "SyncResult",
]
