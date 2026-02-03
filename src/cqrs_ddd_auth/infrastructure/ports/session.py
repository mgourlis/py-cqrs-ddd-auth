"""
Session Port.

Defines the port interface for persisting and retrieving sessions.
The AggregateRoot AuthSession is defined in cqrs_ddd_auth.domain.aggregates.

Supports multiple backends: in-memory (dev), SQLAlchemy (prod), Redis (prod),
or Keycloak-managed sessions.
"""

from typing import Protocol, Optional, runtime_checkable

from cqrs_ddd_auth.domain.aggregates import (
    AuthSession,
    CreateAuthSessionModification,
)


@runtime_checkable
class AuthSessionPort(Protocol):
    """
    Port for authentication session management.

    This abstraction allows different session storage backends:
    - InMemorySessionAdapter: For development/testing
    - RedisSessionAdapter: For production (fast, distributed)
    - SQLAlchemySessionAdapter: For production (persistent)
    - KeycloakSessionAdapter: Uses Keycloak's session_state + local OTP state

    Sessions track multi-step authentication flows:
    1. PENDING_CREDENTIALS → Initial state
    2. PENDING_OTP → Credentials validated, waiting for OTP
    3. AUTHENTICATED → Complete
    4. FAILED/REVOKED/EXPIRED → Terminal states

    Usage:
        adapter = InMemorySessionAdapter()

        # Create returns the AuthSession aggregate with events
        modification = await adapter.create(ip_address="192.168.1.1")
        session = modification.session
        events = modification.events

        # Perform domain operations on the session
        mod = session.credentials_validated(...)

        # Save and get events
        await adapter.save(session)
        all_events = mod.events
    """

    async def create(
        self,
        ip_address: str = "",
        user_agent: str = "",
        expires_in_seconds: int = 1800,  # 30 minutes default
    ) -> CreateAuthSessionModification:
        """
        Create a new pending session.

        Args:
            ip_address: Client IP address
            user_agent: Client user agent
            expires_in_seconds: Session expiration time

        Returns:
            CreateAuthSessionModification containing session and events
        """
        ...

    async def get(self, session_id: str) -> Optional[AuthSession]:
        """
        Get session by ID.

        Args:
            session_id: Session identifier

        Returns:
            AuthSession if found and not expired, None otherwise
        """
        ...

    async def save(self, session: AuthSession) -> None:
        """
        Save or update a session.

        Args:
            session: Session to save
        """
        ...

    async def delete(self, session_id: str) -> None:
        """
        Delete a session.

        Args:
            session_id: Session to delete
        """
        ...

    async def get_by_user(
        self, user_id: str, active_only: bool = True
    ) -> list[AuthSession]:
        """
        Get all sessions for a user.

        Args:
            user_id: User's subject ID
            active_only: If True, only return non-expired/non-revoked sessions

        Returns:
            List of user's sessions
        """
        ...

    async def revoke_all_for_user(self, user_id: str) -> int:
        """
        Revoke all sessions for a user (logout all devices).

        Args:
            user_id: User's subject ID

        Returns:
            Number of sessions revoked
        """
        ...

    async def revoke(self, session_id: str) -> None:
        """
        Revoke a specific session.

        Args:
            session_id: Session identifier
        """
        ...

    async def revoke_redundant_for_user(self, user_id: str, current_ip: str) -> int:
        """
        Revoke redundant sessions for a user on the same IP.
        keeps the most recent session, revokes others.

        Args:
            user_id: User's subject ID
            current_ip: Current IP address

        Returns:
            Number of sessions revoked
        """
        ...

    async def cleanup_expired(self) -> int:
        """
        Delete all expired sessions.

        Returns:
            Number of sessions deleted
        """
        ...
