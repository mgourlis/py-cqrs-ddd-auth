"""
Session Adapter Implementations.

Provides various backends for AuthSessionPort:
- InMemorySessionAdapter: For development/testing
- RedisSessionAdapter: For production (distributed, fast)
- KeycloakSessionAdapter: For Keycloak-managed sessions with local OTP state
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, TYPE_CHECKING
from cqrs_ddd_auth.domain.aggregates import (
    AuthSession,
    AuthSessionStatus,
    CreateAuthSessionModification,
)
from cqrs_ddd_auth.infrastructure.ports.session import AuthSessionPort

if TYPE_CHECKING:
    from cqrs_ddd_auth.infrastructure.adapters.keycloak import KeycloakAdapter
    from cqrs_ddd_auth.infrastructure.adapters.keycloak_admin import (
        KeycloakAdminAdapter,
    )

logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.session")


# ═══════════════════════════════════════════════════════════════
# IN-MEMORY ADAPTER (Development/Testing)
# ═══════════════════════════════════════════════════════════════


class InMemorySessionAdapter(AuthSessionPort):
    """
    In-memory implementation of AuthSessionPort.

    Suitable for development and testing. Not for production
    as sessions are lost on restart and not distributed.

    Usage:
        adapter = InMemorySessionAdapter()
        modification = await adapter.create(ip_address="127.0.0.1")
        session = modification.session
        events = modification.events
    """

    def __init__(self):
        self._sessions: Dict[str, AuthSession] = {}

    async def create(
        self,
        ip_address: str = "",
        user_agent: str = "",
        expires_in_seconds: int = 1800,
    ) -> CreateAuthSessionModification:
        modification = AuthSession.create(
            ip_address=ip_address,
            user_agent=user_agent,
            expires_in_seconds=expires_in_seconds,
        )
        self._sessions[modification.session.id] = modification.session
        logger.debug(f"Created session: {modification.session.id}")
        return modification

    async def get(self, session_id: str) -> Optional[AuthSession]:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.is_expired():
            await self.delete(session_id)
            return None
        return session

    async def save(self, session: AuthSession) -> None:
        self._sessions[session.id] = session
        logger.debug(f"Saved session: {session.id}")

    async def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        logger.debug(f"Deleted session: {session_id}")

    async def get_by_user(
        self, user_id: str, active_only: bool = True
    ) -> list[AuthSession]:
        results = []
        for session in self._sessions.values():
            if session.subject_id == user_id:
                if active_only:
                    if (
                        session.status
                        not in (
                            AuthSessionStatus.FAILED,
                            AuthSessionStatus.REVOKED,
                            AuthSessionStatus.EXPIRED,
                        )
                        and not session.is_expired()
                    ):
                        results.append(session)
                else:
                    results.append(session)
        return results

    async def revoke_all_for_user(self, user_id: str) -> int:
        count = 0
        for session in list(self._sessions.values()):
            if (
                session.subject_id == user_id
                and session.status == AuthSessionStatus.AUTHENTICATED
            ):
                session.revoke()
                count += 1
        return count

    async def revoke(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.revoke()
            logger.debug(f"Revoked session: {session_id}")

    async def revoke_redundant_for_user(self, user_id: str, current_ip: str) -> int:
        user_sessions = []
        for session in self._sessions.values():
            if session.subject_id == user_id and session.ip_address == current_ip:
                if (
                    session.status
                    not in (
                        AuthSessionStatus.FAILED,
                        AuthSessionStatus.REVOKED,
                        AuthSessionStatus.EXPIRED,
                    )
                    and not session.is_expired()
                ):
                    user_sessions.append(session)

        # Sort by creation time descending (newest first)
        user_sessions.sort(
            key=lambda s: s.created_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        if len(user_sessions) < 2:
            return 0

        sessions_to_revoke = user_sessions[1:]
        count = 0
        for session in sessions_to_revoke:
            session.revoke()
            count += 1

        return count

    async def cleanup_expired(self) -> int:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def clear(self) -> None:
        """Clear all sessions (for testing)."""
        self._sessions.clear()


# ═══════════════════════════════════════════════════════════════
# REDIS ADAPTER (Production - Distributed)
# ═══════════════════════════════════════════════════════════════


class RedisSessionAdapter(AuthSessionPort):
    """
    Redis implementation of AuthSessionPort.

    Production-ready, distributed session storage with automatic
    expiration via Redis TTL. Uses AuthSession.to_dict()/from_dict()
    for serialization.

    Requires: redis[hiredis]

    Usage:
        import redis.asyncio as redis

        client = redis.Redis.from_url("redis://localhost:6379")
        adapter = RedisSessionAdapter(client, prefix="auth:session:")

        modification = await adapter.create(ip_address="127.0.0.1")
        session = modification.session
    """

    def __init__(
        self,
        redis_client: Any,  # redis.asyncio.Redis
        prefix: str = "auth:session:",
        user_sessions_prefix: str = "auth:user_sessions:",
    ):
        self._redis = redis_client
        self._prefix = prefix
        self._user_prefix = user_sessions_prefix

    def _session_key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def _user_key(self, user_id: str) -> str:
        return f"{self._user_prefix}{user_id}"

    async def create(
        self,
        ip_address: str = "",
        user_agent: str = "",
        expires_in_seconds: int = 1800,
    ) -> CreateAuthSessionModification:
        import json

        modification = AuthSession.create(
            ip_address=ip_address,
            user_agent=user_agent,
            expires_in_seconds=expires_in_seconds,
        )
        session = modification.session

        data = session.to_dict()
        await self._redis.setex(
            self._session_key(session.id),
            expires_in_seconds,
            json.dumps(data),
        )

        logger.debug(f"Created Redis session: {session.id}")
        return modification

    async def get(self, session_id: str) -> Optional[AuthSession]:
        import json

        data = await self._redis.get(self._session_key(session_id))
        if data is None:
            return None

        session = AuthSession.from_dict(json.loads(data))
        if session.is_expired():
            await self.delete(session_id)
            return None
        return session

    async def save(self, session: AuthSession) -> None:
        import json

        # Calculate remaining TTL
        ttl = None
        if session.expires_at:
            remaining = (
                session.expires_at - datetime.now(timezone.utc)
            ).total_seconds()
            ttl = max(1, int(remaining))

        data = session.to_dict()

        if ttl:
            await self._redis.setex(
                self._session_key(session.id),
                ttl,
                json.dumps(data),
            )
        else:
            await self._redis.set(
                self._session_key(session.id),
                json.dumps(data),
            )

        # Track user's sessions
        if session.subject_id:
            await self._redis.sadd(
                self._user_key(session.subject_id),
                session.id,
            )

        logger.debug(f"Saved Redis session: {session.id}")

    async def delete(self, session_id: str) -> None:
        # Get session first to remove from user index
        session = await self.get(session_id)
        if session and session.subject_id:
            await self._redis.srem(
                self._user_key(session.subject_id),
                session_id,
            )

        await self._redis.delete(self._session_key(session_id))
        logger.debug(f"Deleted Redis session: {session_id}")

    async def get_by_user(
        self, user_id: str, active_only: bool = True
    ) -> list[AuthSession]:
        session_ids = await self._redis.smembers(self._user_key(user_id))

        results = []
        for sid in session_ids:
            session = await self.get(sid.decode() if isinstance(sid, bytes) else sid)
            if session:
                if active_only:
                    if session.status not in (
                        AuthSessionStatus.FAILED,
                        AuthSessionStatus.REVOKED,
                        AuthSessionStatus.EXPIRED,
                    ):
                        results.append(session)
                else:
                    results.append(session)

        return results

    async def revoke_all_for_user(self, user_id: str) -> int:
        sessions = await self.get_by_user(user_id, active_only=True)
        count = 0
        for session in sessions:
            if session.status == AuthSessionStatus.AUTHENTICATED:
                session.revoke()
                await self.save(session)
                count += 1
        return count

    async def revoke(self, session_id: str) -> None:
        session = await self.get(session_id)
        if session:
            session.revoke()
            await self.save(session)
            logger.debug(f"Revoked Redis session: {session_id}")

    async def revoke_redundant_for_user(self, user_id: str, current_ip: str) -> int:
        # Get all active sessions for user
        sessions = await self.get_by_user(user_id, active_only=True)

        # Filter by IP
        ip_sessions = [s for s in sessions if s.ip_address == current_ip]

        # Sort by creation time descending (newest first)
        ip_sessions.sort(
            key=lambda s: s.created_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        if len(ip_sessions) < 2:
            return 0

        sessions_to_revoke = ip_sessions[1:]
        count = 0
        for session in sessions_to_revoke:
            session.revoke()
            await self.save(session)
            count += 1

        return count

    async def cleanup_expired(self) -> int:
        # Redis handles expiration via TTL, so this is mostly a no-op
        # But we can clean up user session indices
        return 0


# ═══════════════════════════════════════════════════════════════
# KEYCLOAK HYBRID ADAPTER (Production - IdP-managed + local OTP)
# ═══════════════════════════════════════════════════════════════


class KeycloakSessionAdapter(AuthSessionPort):
    """
    Keycloak-aware session adapter.

    Uses Keycloak's session_state from tokens as the session ID,
    but stores pending OTP state in a local cache (memory/Redis).

    Benefits:
    - Session lifecycle managed by Keycloak
    - Logout/revocation synced with IdP
    - OTP state stored locally for multi-step auth

    Usage:
        from cqrs_ddd_auth.infrastructure.adapters import KeycloakAdapter

        keycloak = KeycloakAdapter(config)
        session_adapter = KeycloakSessionAdapter(
            keycloak_adapter=keycloak,
            pending_store=RedisSessionAdapter(redis_client),  # or InMemorySessionAdapter()
        )
    """

    def __init__(
        self,
        keycloak_adapter: "KeycloakAdapter",  # KeycloakAdapter from cqrs_ddd_auth.infrastructure.adapters.keycloak
        pending_store: "AuthSessionPort",  # Store for pending OTP state
        keycloak_admin_adapter: Optional[
            "KeycloakAdminAdapter"
        ] = None,  # KeycloakAdminAdapter
    ):
        self._keycloak = keycloak_adapter
        self._pending = pending_store
        self._keycloak_admin = keycloak_admin_adapter

    async def create(
        self,
        ip_address: str = "",
        user_agent: str = "",
        expires_in_seconds: int = 1800,
    ) -> CreateAuthSessionModification:
        # For Keycloak mode, sessions are created after credential validation
        # This creates a placeholder in the pending store
        return await self._pending.create(
            ip_address=ip_address,
            user_agent=user_agent,
            expires_in_seconds=expires_in_seconds,
        )

    async def get(self, session_id: str) -> Optional[AuthSession]:
        # Check pending store first (for OTP flow)
        session = await self._pending.get(session_id)
        if session:
            return session

        # If not in pending, it might be a Keycloak session_state
        # but we can't look it up without the token
        return None

    async def save(self, session: AuthSession) -> None:
        await self._pending.save(session)

    async def delete(self, session_id: str) -> None:
        await self._pending.delete(session_id)

    async def get_by_user(
        self, user_id: str, active_only: bool = True
    ) -> list[AuthSession]:
        # Combine Keycloak sessions with pending sessions
        sessions = await self._pending.get_by_user(user_id, active_only)

        # Fetch Keycloak sessions via admin API if available
        if self._keycloak_admin:
            try:
                # Get realm settings for timeouts (optimization: this could be cached)
                try:
                    realm_settings = await self._keycloak_admin.get_realm_settings()
                    sso_max_lifespan = realm_settings.get(
                        "ssoSessionMaxLifespan", 36000
                    )  # Default 10h
                    sso_idle_timeout = realm_settings.get(
                        "ssoSessionIdleTimeout", 1800
                    )  # Default 30m
                except Exception:
                    # Fallback defaults if we can't get realm settings
                    realm_settings = {}
                    sso_max_lifespan = 36000
                    sso_idle_timeout = 1800

                kc_sessions = await self._keycloak_admin.get_user_sessions(user_id)

                for ks in kc_sessions:
                    # Keycloak timestamps are in milliseconds
                    start_ms = ks.get("start", 0)
                    last_access_ms = ks.get("lastAccess", start_ms)

                    # Calculate expiration: min(start + max_lifespan, last_access + idle_timeout)
                    expires_at_max = start_ms + (sso_max_lifespan * 1000)
                    expires_at_idle = last_access_ms + (sso_idle_timeout * 1000)
                    expires_at_ms = min(expires_at_max, expires_at_idle)

                    expires_at = datetime.fromtimestamp(
                        expires_at_ms / 1000, tz=timezone.utc
                    )

                    # Map Keycloak session to AuthSession (partial)
                    session = AuthSession(
                        entity_id=ks["id"],
                        status=AuthSessionStatus.AUTHENTICATED,
                        subject_id=user_id,
                        username=ks.get("username"),
                        ip_address=ks.get("ipAddress", ""),
                        created_at=datetime.fromtimestamp(
                            start_ms / 1000, tz=timezone.utc
                        ),
                        expires_at=expires_at,
                        updated_at=datetime.fromtimestamp(
                            last_access_ms / 1000, tz=timezone.utc
                        ),
                        user_claims={"client_sessions": ks.get("clients", {})},
                    )
                    sessions.append(session)
            except Exception:
                # Log error but don't fail, just return pending sessions
                logger.warning(
                    f"Failed to fetch Keycloak sessions for user {user_id}",
                    exc_info=True,
                )

        return sessions

    async def revoke(self, session_id: str) -> None:
        # Revoke locally first (if pending)
        await self._pending.delete(session_id)

        # Revoke in Keycloak if admin adapter is available
        if self._keycloak_admin:
            try:
                await self._keycloak_admin.revoke_user_session(session_id)
            except Exception:
                logger.warning(
                    f"Failed to revoke Keycloak session {session_id}", exc_info=True
                )

    async def revoke_redundant_for_user(self, user_id: str, current_ip: str) -> int:
        count = 0

        # 1. Clean up local pending sessions
        count += await self._pending.revoke_redundant_for_user(user_id, current_ip)

        # 2. Clean up Keycloak sessions if admin adapter is available
        if self._keycloak_admin:
            try:
                # Get all active sessions
                kc_sessions = await self._keycloak_admin.get_user_sessions(user_id)

                # Filter by IP
                ip_sessions = [
                    s for s in kc_sessions if s.get("ipAddress") == current_ip
                ]

                # Sort: Newest first (descending by 'start' timestamp)
                # Keycloak returns 'start' as a timestamp
                ip_sessions.sort(key=lambda x: x.get("start", 0), reverse=True)

                # Identify redundant sessions (Keep index 0, delete 1..N)
                if len(ip_sessions) >= 2:
                    sessions_to_revoke = ip_sessions[1:]

                    for session in sessions_to_revoke:
                        session_id = session["id"]
                        try:
                            await self._keycloak_admin.revoke_user_session(session_id)
                            count += 1
                        except Exception as e:
                            logger.warning(
                                f"Failed to revoke redundant Keycloak session {session_id}: {e}"
                            )
            except Exception:
                logger.warning(
                    f"Failed to clean up redundant Keycloak sessions for user {user_id}",
                    exc_info=True,
                )

        return count

    async def revoke_all_for_user(self, user_id: str) -> int:
        # Revoke pending sessions
        count = await self._pending.revoke_all_for_user(user_id)

        # Revoke Keycloak sessions via admin API if available
        if self._keycloak_admin:
            try:
                await self._keycloak_admin.logout_user(user_id)
                # We can't know exactly how many were revoked in Keycloak, but the action succeeded
            except Exception:
                logger.warning(
                    f"Failed to revoke Keycloak sessions for user {user_id}",
                    exc_info=True,
                )

        return count

    async def cleanup_expired(self) -> int:
        return await self._pending.cleanup_expired()

    def link_to_keycloak_session(
        self, session: AuthSession, keycloak_session_state: str
    ) -> AuthSession:
        """
        Link a pending session to Keycloak's session_state.

        Called after successful authentication to associate
        local session with Keycloak session.
        """
        # Store the Keycloak session_state for reference
        if session.user_claims is None:
            session.user_claims = {}
        session.user_claims["keycloak_session_state"] = keycloak_session_state
        return session


__all__ = [
    "InMemorySessionAdapter",
    "RedisSessionAdapter",
    "KeycloakSessionAdapter",
]
