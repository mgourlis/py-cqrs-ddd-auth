"""
In-memory repository implementations.

These are intended for testing, demos, and development.
For production, use persistent backends (Redis, PostgreSQL, etc.).
"""

from datetime import datetime, timezone
from typing import Dict, Optional, List

from cqrs_ddd_auth.domain.aggregates import AuthSession, AuthSessionStatus, OTPChallenge
from cqrs_ddd_auth.domain.value_objects import TOTPSecret


# ═══════════════════════════════════════════════════════════════
# AUTH SESSION REPOSITORY
# ═══════════════════════════════════════════════════════════════

class InMemorySessionRepository:
    """
    In-memory implementation of AuthSessionRepository.
    
    Sessions are stored in a dict keyed by session ID.
    Suitable for testing and single-instance deployments.
    """
    
    def __init__(self):
        self._sessions: Dict[str, AuthSession] = {}
    
    async def get(self, session_id: str) -> Optional[AuthSession]:
        """Get a session by ID."""
        return self._sessions.get(session_id)
    
    async def save(self, session: AuthSession) -> None:
        """Save or update a session."""
        self._sessions[session.id] = session
    
    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        self._sessions.pop(session_id, None)
    
    async def delete_expired(self) -> int:
        """Delete all expired sessions. Returns count deleted."""
        now = datetime.now(timezone.utc)
        expired_ids = [
            sid for sid, session in self._sessions.items()
            if session.expires_at and session.expires_at < now
        ]
        for sid in expired_ids:
            del self._sessions[sid]
        return len(expired_ids)
    
    async def get_by_user_id(
        self, 
        user_id: str,
        active_only: bool = True
    ) -> List[AuthSession]:
        """Get all sessions for a user."""
        sessions = [
            s for s in self._sessions.values()
            if s.subject_id == user_id
        ]
        if active_only:
            sessions = [
                s for s in sessions
                if s.status == AuthSessionStatus.AUTHENTICATED
                and not s.is_expired()
            ]
        return sessions
    
    def clear(self) -> None:
        """Clear all sessions (for testing)."""
        self._sessions.clear()


# ═══════════════════════════════════════════════════════════════
# TOTP SECRET REPOSITORY
# ═══════════════════════════════════════════════════════════════

class InMemoryTOTPSecretRepository:
    """
    In-memory storage for user TOTP secrets.
    
    Maps user_id -> TOTPSecret for authenticator app 2FA.
    """
    
    def __init__(self):
        self._secrets: Dict[str, TOTPSecret] = {}
    
    async def get(self, user_id: str) -> Optional[TOTPSecret]:
        """Get TOTP secret for a user."""
        return self._secrets.get(user_id)
    
    async def save(self, user_id: str, secret: TOTPSecret) -> None:
        """Save TOTP secret for a user."""
        self._secrets[user_id] = secret
    
    async def delete(self, user_id: str) -> None:
        """Delete TOTP secret for a user."""
        self._secrets.pop(user_id, None)
    
    async def exists(self, user_id: str) -> bool:
        """Check if user has TOTP configured."""
        return user_id in self._secrets
    
    def clear(self) -> None:
        """Clear all secrets (for testing)."""
        self._secrets.clear()


# ═══════════════════════════════════════════════════════════════
# OTP CHALLENGE REPOSITORY
# ═══════════════════════════════════════════════════════════════

class InMemoryOTPChallengeRepository:
    """
    In-memory storage for OTP challenges (email/SMS codes).
    
    Challenges are temporary and expire after a short time.
    """
    
    def __init__(self):
        self._challenges: Dict[str, OTPChallenge] = {}
        # Index by user_id for quick lookup
        self._by_user: Dict[str, List[str]] = {}  # user_id -> [challenge_ids]
    
    async def get(self, challenge_id: str) -> Optional[OTPChallenge]:
        """Get a challenge by ID."""
        return self._challenges.get(challenge_id)
    
    async def save(self, challenge: OTPChallenge) -> None:
        """Save a challenge."""
        self._challenges[challenge.id] = challenge
        
        # Update user index
        if challenge.user_id not in self._by_user:
            self._by_user[challenge.user_id] = []
        if challenge.id not in self._by_user[challenge.user_id]:
            self._by_user[challenge.user_id].append(challenge.id)
    
    async def delete(self, challenge_id: str) -> None:
        """Delete a challenge."""
        challenge = self._challenges.pop(challenge_id, None)
        if challenge and challenge.user_id in self._by_user:
            try:
                self._by_user[challenge.user_id].remove(challenge_id)
            except ValueError:
                pass
    
    async def get_active_for_user(
        self, 
        user_id: str, 
        method: Optional[str] = None
    ) -> Optional[OTPChallenge]:
        """
        Get the most recent active challenge for a user.
        
        Args:
            user_id: User to look up
            method: Optional filter by method (email, sms)
        
        Returns:
            Most recent valid challenge, or None
        """
        challenge_ids = self._by_user.get(user_id, [])
        
        for cid in reversed(challenge_ids):  # Most recent first
            challenge = self._challenges.get(cid)
            if challenge and challenge.is_valid():
                if method is None or challenge.method == method:
                    return challenge
        
        return None
    
    async def delete_expired(self) -> int:
        """Delete all expired challenges. Returns count deleted."""
        expired_ids = [
            cid for cid, challenge in self._challenges.items()
            if challenge.is_expired()
        ]
        for cid in expired_ids:
            await self.delete(cid)
        return len(expired_ids)
    
    def clear(self) -> None:
        """Clear all challenges (for testing)."""
        self._challenges.clear()
        self._by_user.clear()
