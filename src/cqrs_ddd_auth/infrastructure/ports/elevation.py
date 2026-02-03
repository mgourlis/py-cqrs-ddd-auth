from typing import Protocol, Optional, runtime_checkable


@runtime_checkable
class ElevationStore(Protocol):
    """
    Protocol for storing temporary security elevation grants.

    Elevation grants allow users to perform sensitive operations for a
    short period after successful step-up authentication.
    """

    async def grant(self, user_id: str, action: str, ttl_seconds: int = 300) -> None:
        """Grant temporary elevation for an action."""
        ...

    async def is_elevated(self, user_id: str, action: str) -> bool:
        """Check if user is currently elevated for an action."""
        ...

    async def revoke(self, user_id: str, action: Optional[str] = None) -> None:
        """Revoke elevation for a specific action or all actions for a user."""
        ...

    async def cleanup_expired(self) -> int:
        """Remove expired elevation grants."""
        ...
