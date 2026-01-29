"""
Session Repository Port.

Defines the interface for persisting and retrieving authentication sessions.
"""

from typing import Protocol, Optional

from cqrs_ddd_auth.domain.aggregates import AuthSession


class AuthSessionRepository(Protocol):
    """
    Repository for authentication sessions.
    
    Sessions are persisted to allow multi-step authentication
    flows (credentials -> OTP -> success).
    """
    
    async def get(self, session_id: str) -> Optional[AuthSession]:
        """Get a session by ID."""
        ...
    
    async def save(self, session: AuthSession) -> None:
        """Save or update a session."""
        ...
    
    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        ...
    
    async def delete_expired(self) -> int:
        """Delete all expired sessions. Returns count deleted."""
        ...
    
    async def get_by_user_id(
        self, 
        user_id: str,
        active_only: bool = True
    ) -> list[AuthSession]:
        """Get all sessions for a user."""
        ...
