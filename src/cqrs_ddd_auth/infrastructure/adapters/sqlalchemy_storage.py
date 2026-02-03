"""
SQLAlchemy Adapter Implementations.

Provides SQLAlchemy backends for session and OTP storage:
- SQLAlchemySessionAdapter: Persistent session storage with encryption
- SQLAlchemyOTPChallengeAdapter: OTP challenge storage with encryption
- SQLAlchemyTOTPSecretAdapter: TOTP secret storage with encryption

These adapters use PGP encryption for sensitive data at rest and
SHA256 hashing for efficient lookups without decryption.

Requirements:
- sqlalchemy[asyncio]
- asyncpg (or another async driver)
- Encryption types (PGPEncryptedText, etc.) must be configured

Usage:
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    engine = create_async_engine("postgresql+asyncpg://...")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    adapter = SQLAlchemySessionAdapter(session_factory, passphrase="...")
"""

import logging
import uuid
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, List, Callable
from contextlib import asynccontextmanager

from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Integer,
    Boolean,
    select,
    delete,
    and_,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base

from cqrs_ddd_auth.domain.aggregates import (
    AuthSession,
    AuthSessionStatus,
    CreateAuthSessionModification,
    OTPChallenge,
    OTPChallengeStatus,
)
from cqrs_ddd_auth.domain.value_objects import TOTPSecret
from cqrs_ddd_auth.infrastructure.ports.session import AuthSessionPort
from cqrs_ddd_auth.infrastructure.ports.otp import (
    OTPChallengeRepository,
    TOTPSecretRepository,
)


logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.sqlalchemy")

Base = declarative_base()

# Type for async session factory
AsyncSessionFactory = Callable[[], AsyncSession]


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════


def hash_identifier(value: str) -> str:
    """Create a SHA256 hash of an identifier for efficient lookups."""
    if value is None:
        return None
    return f"hash:{hashlib.sha256(value.encode()).hexdigest()}"


# ═══════════════════════════════════════════════════════════════
# SQLALCHEMY MODELS (Base without encryption - extend for PGP)
# ═══════════════════════════════════════════════════════════════


class AuthSessionModel(Base):
    """
    SQLAlchemy model for auth sessions.

    This base model uses standard SQLAlchemy types.
    For PGP encryption, extend this class and override columns
    with PGPEncrypted* types in your application.

    Fields that should be encrypted in production:
    - subject_id
    - username
    - pending_access_token
    - pending_refresh_token
    - user_claims (JSON)
    - ip_address
    - user_agent
    - failure_reason

    The session_id_hash field is used for efficient lookups.
    """

    __tablename__ = "auth_sessions"

    # Primary key is the hash for efficient lookups
    session_id_hash = Column(String(128), primary_key=True, nullable=False)

    # Encrypted session ID (stored for retrieval)
    session_id = Column(Text, nullable=False)

    # Status (can be plaintext for filtering)
    status = Column(String(50), nullable=False, index=True)

    # User info - should be encrypted in production
    subject_id = Column(Text, nullable=True)
    subject_id_hash = Column(String(128), nullable=True, index=True)  # For user lookups
    username = Column(Text, nullable=True)

    # Pending tokens - MUST be encrypted in production
    pending_access_token = Column(Text, nullable=True)
    pending_refresh_token = Column(Text, nullable=True)

    # OTP state
    otp_required = Column(Boolean, default=False)
    available_otp_methods = Column(Text, nullable=True)  # JSON array
    otp_method_used = Column(Text, nullable=True)

    # Request context - should be encrypted in production
    ip_address = Column(Text, nullable=True)
    ip_address_hash = Column(
        String(128), nullable=True, index=True
    )  # For redundant session cleanup
    user_agent = Column(Text, nullable=True)

    # Timing
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Failure tracking
    failure_reason = Column(Text, nullable=True)

    # Extra claims - should be encrypted in production
    user_claims = Column(Text, nullable=True)  # JSON

    # Optimistic locking
    version = Column(Integer, default=0)

    __table_args__ = {
        "comment": "Authentication sessions with optional PGP encryption."
    }


class OTPChallengeModel(Base):
    """
    SQLAlchemy model for OTP challenges (email/SMS).

    This base model uses standard SQLAlchemy types.
    For PGP encryption, extend and override columns.

    Fields that should be encrypted:
    - user_id
    - secret
    """

    __tablename__ = "otp_challenges"

    # Composite primary key: user + method
    user_id_hash = Column(String(128), primary_key=True, nullable=False)
    method = Column(String(20), primary_key=True, nullable=False)

    # Encrypted fields
    challenge_id = Column(Text, nullable=False)
    user_id = Column(Text, nullable=False)
    secret = Column(Text, nullable=False)  # MUST be encrypted

    # Timing
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # State
    attempts = Column(Integer, default=0)
    status = Column(String(20), default="pending")

    __table_args__ = {"comment": "OTP challenges for email/SMS verification."}


class TOTPSecretModel(Base):
    """
    SQLAlchemy model for TOTP secrets.

    Long-lived secrets for authenticator app-based 2FA.
    MUST be encrypted at rest.
    """

    __tablename__ = "totp_secrets"

    # Primary key is user hash
    user_id_hash = Column(String(128), primary_key=True, nullable=False)

    # Encrypted fields
    user_id = Column(Text, nullable=False)
    secret = Column(Text, nullable=False)  # MUST be encrypted

    # Metadata
    created_at = Column(DateTime(timezone=True), nullable=False)
    enabled = Column(Boolean, default=True)

    __table_args__ = {"comment": "TOTP secrets for authenticator app 2FA."}


# ═══════════════════════════════════════════════════════════════
# SQLALCHEMY SESSION ADAPTER
# ═══════════════════════════════════════════════════════════════


class SQLAlchemySessionAdapter(AuthSessionPort):
    """
    SQLAlchemy implementation of AuthSessionPort.

    Production-ready persistent session storage.
    Uses SHA256 hashing for lookups and can be extended
    with PGP encryption for sensitive fields.

    Usage:
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

        engine = create_async_engine("postgresql+asyncpg://...")
        session_factory = async_sessionmaker(engine, expire_on_commit=False)

        adapter = SQLAlchemySessionAdapter(session_factory)

        # Create session
        modification = await adapter.create(ip_address="127.0.0.1")
        session = modification.session
    """

    def __init__(
        self,
        session_factory: AsyncSessionFactory,
        model_class: type = AuthSessionModel,
    ):
        """
        Initialize the adapter.

        Args:
            session_factory: Async session factory from async_sessionmaker
            model_class: SQLAlchemy model class (for custom encrypted models)
        """
        self.session_factory = session_factory
        self.model_class = model_class

    @asynccontextmanager
    async def _session_scope(self):
        """Provide a transactional scope for database operations."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    def _to_model(self, session: AuthSession) -> AuthSessionModel:
        """Convert AuthSession aggregate to SQLAlchemy model."""
        return self.model_class(
            session_id_hash=hash_identifier(session.id),
            session_id=session.id,
            status=session.status.value,
            subject_id=session.subject_id,
            subject_id_hash=hash_identifier(session.subject_id)
            if session.subject_id
            else None,
            username=session.username,
            pending_access_token=session.pending_access_token,
            pending_refresh_token=session.pending_refresh_token,
            otp_required=session.otp_required,
            available_otp_methods=json.dumps(session.available_otp_methods)
            if session.available_otp_methods
            else None,
            otp_method_used=session.otp_method_used,
            ip_address=session.ip_address,
            ip_address_hash=hash_identifier(session.ip_address)
            if session.ip_address
            else None,
            user_agent=session.user_agent,
            created_at=session.created_at,
            expires_at=session.expires_at,
            failure_reason=session.failure_reason,
            user_claims=json.dumps(session.user_claims)
            if session.user_claims
            else None,
            version=session.version,
        )

    def _from_model(self, model: AuthSessionModel) -> AuthSession:
        """Convert SQLAlchemy model to AuthSession aggregate."""
        available_methods = []
        if model.available_otp_methods:
            try:
                available_methods = json.loads(model.available_otp_methods)
            except json.JSONDecodeError:
                available_methods = []

        user_claims = None
        if model.user_claims:
            try:
                user_claims = json.loads(model.user_claims)
            except json.JSONDecodeError:
                user_claims = None

        session = AuthSession(
            entity_id=model.session_id,
            status=AuthSessionStatus(model.status),
            subject_id=model.subject_id,
            username=model.username,
            pending_access_token=model.pending_access_token,
            pending_refresh_token=model.pending_refresh_token,
            otp_required=model.otp_required or False,
            available_otp_methods=available_methods,
            otp_method_used=model.otp_method_used,
            ip_address=model.ip_address or "",
            user_agent=model.user_agent or "",
            expires_at=model.expires_at,
            failure_reason=model.failure_reason,
            user_claims=user_claims,
        )

        # Restore internal state
        if model.created_at:
            session._created_at = model.created_at
        session._version = model.version or 0

        return session

    async def create(
        self,
        ip_address: str = "",
        user_agent: str = "",
        expires_in_seconds: int = 1800,
    ) -> CreateAuthSessionModification:
        """Create a new pending session."""
        modification = AuthSession.create(
            ip_address=ip_address,
            user_agent=user_agent,
            expires_in_seconds=expires_in_seconds,
        )

        async with self._session_scope() as db:
            model = self._to_model(modification.session)
            db.add(model)

        logger.debug(f"Created session: {modification.session.id}")
        return modification

    async def get(self, session_id: str) -> Optional[AuthSession]:
        """Get session by ID."""
        session_hash = hash_identifier(session_id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                self.model_class.session_id_hash == session_hash
            )
            result = await db.execute(stmt)
            model = result.scalar_one_or_none()

            if model is None:
                return None

            session = self._from_model(model)

            # Check expiration
            if session.is_expired():
                logger.debug(f"Session {session_id} is expired")
                return None

            return session

    async def save(self, session: AuthSession) -> None:
        """Save or update a session."""
        session_hash = hash_identifier(session.id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                self.model_class.session_id_hash == session_hash
            )
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing
                existing.status = session.status.value
                existing.subject_id = session.subject_id
                existing.subject_id_hash = (
                    hash_identifier(session.subject_id) if session.subject_id else None
                )
                existing.username = session.username
                existing.pending_access_token = session.pending_access_token
                existing.pending_refresh_token = session.pending_refresh_token
                existing.otp_required = session.otp_required
                existing.available_otp_methods = (
                    json.dumps(session.available_otp_methods)
                    if session.available_otp_methods
                    else None
                )
                existing.otp_method_used = session.otp_method_used
                existing.ip_address = session.ip_address
                existing.ip_address_hash = (
                    hash_identifier(session.ip_address) if session.ip_address else None
                )
                existing.user_agent = session.user_agent
                existing.expires_at = session.expires_at
                existing.failure_reason = session.failure_reason
                existing.user_claims = (
                    json.dumps(session.user_claims) if session.user_claims else None
                )
                existing.version = session.version
            else:
                # Insert new
                model = self._to_model(session)
                db.add(model)

        logger.debug(f"Saved session: {session.id}")

    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        session_hash = hash_identifier(session_id)

        async with self._session_scope() as db:
            stmt = delete(self.model_class).where(
                self.model_class.session_id_hash == session_hash
            )
            await db.execute(stmt)

        logger.debug(f"Deleted session: {session_id}")

    async def get_by_user(
        self, user_id: str, active_only: bool = True
    ) -> List[AuthSession]:
        """Get all sessions for a user."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            conditions = [self.model_class.subject_id_hash == user_hash]

            if active_only:
                now = datetime.now(timezone.utc)
                conditions.extend(
                    [
                        self.model_class.expires_at > now,
                        self.model_class.status.notin_(
                            [
                                AuthSessionStatus.REVOKED.value,
                                AuthSessionStatus.EXPIRED.value,
                                AuthSessionStatus.FAILED.value,
                            ]
                        ),
                    ]
                )

            stmt = select(self.model_class).where(and_(*conditions))
            result = await db.execute(stmt)
            models = result.scalars().all()

            return [self._from_model(m) for m in models]

    async def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke all sessions for a user."""
        sessions = await self.get_by_user(user_id, active_only=True)
        count = 0

        for session in sessions:
            if session.status == AuthSessionStatus.AUTHENTICATED:
                session.revoke(reason="revoke_all")
                await self.save(session)
                count += 1

        return count

    async def revoke(self, session_id: str) -> None:
        """Revoke a specific session."""
        session = await self.get(session_id)
        if session and session.status == AuthSessionStatus.AUTHENTICATED:
            session.revoke(reason="manual_revoke")
            await self.save(session)

    async def revoke_redundant_for_user(self, user_id: str, current_ip: str) -> int:
        """Revoke redundant sessions for a user on the same IP."""
        sessions = await self.get_by_user(user_id, active_only=True)
        ip_hash = hash_identifier(current_ip)

        # Filter to same IP
        same_ip_sessions = [
            s
            for s in sessions
            if hash_identifier(s.ip_address) == ip_hash
            and s.status == AuthSessionStatus.AUTHENTICATED
        ]

        if len(same_ip_sessions) <= 1:
            return 0

        # Keep most recent, revoke others
        same_ip_sessions.sort(
            key=lambda s: s.created_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        count = 0

        for session in same_ip_sessions[1:]:
            session.revoke(reason="redundant_session")
            await self.save(session)
            count += 1

        return count

    async def cleanup_expired(self) -> int:
        """Delete all expired sessions."""
        now = datetime.now(timezone.utc)

        async with self._session_scope() as db:
            stmt = delete(self.model_class).where(self.model_class.expires_at < now)
            result = await db.execute(stmt)
            return result.rowcount


# ═══════════════════════════════════════════════════════════════
# SQLALCHEMY OTP CHALLENGE ADAPTER
# ═══════════════════════════════════════════════════════════════


class SQLAlchemyOTPChallengeAdapter(OTPChallengeRepository):
    """
    SQLAlchemy implementation of OTPChallengeRepository.

    Production-ready OTP challenge storage with encryption support.

    Usage:
        adapter = SQLAlchemyOTPChallengeAdapter(session_factory)

        challenge_id = await adapter.save_challenge(
            user_id="user-123",
            method="email",
            secret="JBSWY3DPEHPK3PXP",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
    """

    def __init__(
        self,
        session_factory: AsyncSessionFactory,
        model_class: type = OTPChallengeModel,
    ):
        self.session_factory = session_factory
        self.model_class = model_class

    @asynccontextmanager
    async def _session_scope(self):
        """Provide a transactional scope for database operations."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def save_challenge(
        self,
        user_id: str,
        method: str,
        secret: str,
        expires_at: datetime,
    ) -> str:
        """Save a new OTP challenge."""
        challenge_id = str(uuid.uuid4())
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            # Check for existing
            stmt = select(self.model_class).where(
                and_(
                    self.model_class.user_id_hash == user_hash,
                    self.model_class.method == method,
                )
            )
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing challenge
                existing.challenge_id = challenge_id
                existing.secret = secret
                existing.created_at = datetime.now(timezone.utc)
                existing.expires_at = expires_at
                existing.attempts = 0
                existing.status = OTPChallengeStatus.PENDING.value
            else:
                # Create new
                model = self.model_class(
                    user_id_hash=user_hash,
                    method=method,
                    challenge_id=challenge_id,
                    user_id=user_id,
                    secret=secret,
                    created_at=datetime.now(timezone.utc),
                    expires_at=expires_at,
                    attempts=0,
                    status=OTPChallengeStatus.PENDING.value,
                )
                db.add(model)

        logger.debug(f"Created OTP challenge: {challenge_id} for {user_id}/{method}")
        return challenge_id

    async def get_challenge(
        self,
        user_id: str,
        method: str,
    ) -> Optional[OTPChallenge]:
        """Get active OTP challenge for user."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                and_(
                    self.model_class.user_id_hash == user_hash,
                    self.model_class.method == method,
                )
            )
            result = await db.execute(stmt)
            model = result.scalar_one_or_none()

            if model is None:
                return None

            challenge = OTPChallenge(
                entity_id=model.challenge_id,
                user_id=model.user_id,
                method=model.method,
                secret=model.secret,
                expires_at=model.expires_at,
                attempts=model.attempts,
                status=OTPChallengeStatus(model.status),
            )

            # Set created_at
            if model.created_at:
                challenge._created_at = model.created_at

            # Check expiration
            if challenge.is_expired():
                logger.debug(f"OTP challenge for {user_id}/{method} is expired")
                return None

            return challenge

    async def mark_used(self, user_id: str, method: str) -> None:
        """Mark challenge as used after successful validation."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                and_(
                    self.model_class.user_id_hash == user_hash,
                    self.model_class.method == method,
                )
            )
            result = await db.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                model.status = OTPChallengeStatus.USED.value

    async def increment_attempts(self, user_id: str, method: str) -> None:
        """Increment failed attempts counter."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                and_(
                    self.model_class.user_id_hash == user_hash,
                    self.model_class.method == method,
                )
            )
            result = await db.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                model.attempts += 1
                if model.attempts >= OTPChallenge.MAX_ATTEMPTS:
                    model.status = OTPChallengeStatus.MAX_ATTEMPTS.value

    async def delete_expired(self) -> int:
        """Delete expired challenges."""
        now = datetime.now(timezone.utc)

        async with self._session_scope() as db:
            stmt = delete(self.model_class).where(self.model_class.expires_at < now)
            result = await db.execute(stmt)
            return result.rowcount


# ═══════════════════════════════════════════════════════════════
# SQLALCHEMY TOTP SECRET ADAPTER
# ═══════════════════════════════════════════════════════════════


class SQLAlchemyTOTPSecretAdapter(TOTPSecretRepository):
    """
    SQLAlchemy implementation of TOTPSecretRepository.

    Production-ready TOTP secret storage.
    MUST use encryption for the secret field in production.

    Usage:
        adapter = SQLAlchemyTOTPSecretAdapter(session_factory)

        await adapter.save("user-123", totp_secret)
        secret = await adapter.get_by_user_id("user-123")
    """

    def __init__(
        self,
        session_factory: AsyncSessionFactory,
        model_class: type = TOTPSecretModel,
    ):
        self.session_factory = session_factory
        self.model_class = model_class

    @asynccontextmanager
    async def _session_scope(self):
        """Provide a transactional scope for database operations."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def get_by_user_id(self, user_id: str) -> Optional[TOTPSecret]:
        """Get TOTP secret for a user."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                and_(
                    self.model_class.user_id_hash == user_hash,
                    self.model_class.enabled,
                )
            )
            result = await db.execute(stmt)
            model = result.scalar_one_or_none()

            if model is None:
                return None

            return TOTPSecret(secret=model.secret)

    async def save(self, user_id: str, secret: TOTPSecret) -> None:
        """Save TOTP secret for a user."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            stmt = select(self.model_class).where(
                self.model_class.user_id_hash == user_hash
            )
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                existing.secret = secret.secret
                existing.enabled = True
            else:
                model = self.model_class(
                    user_id_hash=user_hash,
                    user_id=user_id,
                    secret=secret.secret,
                    created_at=datetime.now(timezone.utc),
                    enabled=True,
                )
                db.add(model)

        logger.debug(f"Saved TOTP secret for user: {user_id}")

    async def delete(self, user_id: str) -> None:
        """Remove TOTP secret (disable 2FA)."""
        user_hash = hash_identifier(user_id)

        async with self._session_scope() as db:
            # Soft delete by disabling
            stmt = select(self.model_class).where(
                self.model_class.user_id_hash == user_hash
            )
            result = await db.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                model.enabled = False

        logger.debug(f"Disabled TOTP for user: {user_id}")


__all__ = [
    # Models
    "Base",
    "AuthSessionModel",
    "OTPChallengeModel",
    "TOTPSecretModel",
    # Adapters
    "SQLAlchemySessionAdapter",
    "SQLAlchemyOTPChallengeAdapter",
    "SQLAlchemyTOTPSecretAdapter",
    # Utilities
    "hash_identifier",
]
