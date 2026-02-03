"""
Domain aggregates for authentication.

Aggregates are clusters of domain objects that can be treated as a single unit.
The root entity (the aggregate root) ensures the consistency of changes.

Uses AggregateRoot base class from py-cqrs-ddd-toolkit.
"""

from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from cqrs_ddd_auth.domain.value_objects import UserClaims

import uuid

from cqrs_ddd.ddd import AggregateRoot, Modification, Entity
from cqrs_ddd_auth.domain.errors import AuthDomainError

from cqrs_ddd_auth.domain.events import (
    AuthSessionCreated,
    CredentialsValidated,
    OTPRequired,
    OTPValidated,
    AuthenticationSucceeded,
    AuthenticationFailed,
    SessionRevoked,
)


class AuthSessionStatus(str, Enum):
    """Status of an authentication session."""

    PENDING_CREDENTIALS = "pending_credentials"
    PENDING_OTP = "pending_otp"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ═══════════════════════════════════════════════════════════════
# MODIFICATIONS
# ═══════════════════════════════════════════════════════════════


class CreateAuthSessionModification(Modification):
    """Modification for creating a new auth session."""

    def __init__(self, session: "AuthSession", events: List):
        super().__init__(entity=session, events=events)
        self.session = session


class UpdateAuthSessionModification(Modification):
    """Modification for updating an auth session."""

    def __init__(self, session: "AuthSession", events: List):
        super().__init__(entity=session, events=events)
        self.session = session


# ═══════════════════════════════════════════════════════════════
# AUTH SESSION AGGREGATE ROOT
# ═══════════════════════════════════════════════════════════════


class AuthSession(AggregateRoot):
    """
    Aggregate root representing an authentication session.

    Tracks the multi-step authentication process from initial
    credentials through optional OTP to final token issuance.

    This aggregate can be stored in various backends (memory, Redis,
    SQLAlchemy, etc.) and emits domain events for state changes.

    Usage:
        # Create a new session
        modification = AuthSession.create(ip_address="192.168.1.1")
        session = modification.session
        events = modification.events

        # Validate credentials
        mod = session.credentials_validated(
            subject_id="user-123",
            username="john",
            requires_otp=True,
            available_otp_methods=["totp", "email"],
            access_token="...",
            refresh_token="...",
        )

        # Validate OTP
        mod = session.otp_validated(method="totp")
    """

    def __init__(
        self,
        entity_id: str = None,
        status: AuthSessionStatus = AuthSessionStatus.PENDING_CREDENTIALS,
        # User info (set after credential validation)
        subject_id: Optional[str] = None,
        username: Optional[str] = None,
        # Pending tokens (stored during OTP phase)
        pending_access_token: Optional[str] = None,
        pending_refresh_token: Optional[str] = None,
        # OTP state
        otp_required: bool = False,
        available_otp_methods: Optional[List[str]] = None,
        otp_method_used: Optional[str] = None,
        # Request context
        ip_address: str = "",
        user_agent: str = "",
        # Timing
        expires_at: Optional[datetime] = None,
        # Failure tracking
        failure_reason: Optional[str] = None,
        # Extra claims/attributes from IdP
        user_claims: Optional[dict[str, Any]] = None,
        **kwargs,
    ):
        super().__init__(entity_id=entity_id, **kwargs)
        self.status = status
        self.subject_id = subject_id
        self.username = username
        self.pending_access_token = pending_access_token
        self.pending_refresh_token = pending_refresh_token
        self.otp_required = otp_required
        self.available_otp_methods = available_otp_methods or []
        self.otp_method_used = otp_method_used
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.expires_at = expires_at
        self.failure_reason = failure_reason
        self.user_claims = user_claims

    @classmethod
    def create(
        cls,
        ip_address: str = "",
        user_agent: str = "",
        expires_in_seconds: int = 1800,
    ) -> CreateAuthSessionModification:
        """
        Factory method to create a new authentication session.

        Args:
            ip_address: Client IP address
            user_agent: Client user agent
            expires_in_seconds: Session expiration time (default 30 minutes)

        Returns:
            CreateAuthSessionModification with session and events
        """
        session = cls(
            entity_id=str(uuid.uuid4()),
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=expires_in_seconds),
        )

        event = AuthSessionCreated(
            session_id=session.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add_domain_event(event)

        return CreateAuthSessionModification(session, [event])

    def credentials_validated(
        self,
        subject_id: str,
        username: str,
        requires_otp: bool,
        available_otp_methods: Optional[List[str]] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        user_claims: Optional[dict[str, Any]] = None,
    ) -> UpdateAuthSessionModification:
        """
        Called when primary credentials (username/password) are valid.

        Args:
            subject_id: User's subject ID from IdP
            username: Username
            requires_otp: Whether OTP is required for this user
            available_otp_methods: List of OTP methods available (email, sms, totp)
            access_token: Token to store for later (when OTP is required)
            refresh_token: Refresh token to store for later
            user_claims: Additional claims from IdP

        Returns:
            UpdateAuthSessionModification with session and events
        """
        self._check_can_transition(AuthSessionStatus.PENDING_CREDENTIALS)

        self.subject_id = subject_id
        self.username = username
        self.otp_required = requires_otp
        self.available_otp_methods = available_otp_methods or []
        self.user_claims = user_claims

        # Store tokens for multi-step auth
        self.pending_access_token = access_token
        self.pending_refresh_token = refresh_token

        events: List[Any] = []

        events.append(
            CredentialsValidated(
                session_id=self.id,
                subject_id=subject_id,
                requires_otp=requires_otp,
            )
        )

        if requires_otp:
            self.status = AuthSessionStatus.PENDING_OTP
            events.append(
                OTPRequired(
                    session_id=self.id,
                    subject_id=subject_id,
                    available_methods=tuple(available_otp_methods or []),
                )
            )
        else:
            self._complete_authentication(events)

        for event in events:
            self.add_domain_event(event)

        self.increment_version()
        return UpdateAuthSessionModification(self, events)

    def otp_validated(self, method: str) -> UpdateAuthSessionModification:
        """
        Called when OTP is successfully validated.

        Args:
            method: The OTP method used (totp, email, sms)

        Returns:
            UpdateAuthSessionModification with session and events
        """
        self._check_can_transition(AuthSessionStatus.PENDING_OTP)

        self.otp_method_used = method
        events: List[Any] = []

        events.append(
            OTPValidated(
                session_id=self.id,
                subject_id=self.subject_id,
                method=method,
            )
        )

        self._complete_authentication(events)

        for event in events:
            self.add_domain_event(event)

        self.increment_version()
        return UpdateAuthSessionModification(self, events)

    def fail(self, reason: str) -> UpdateAuthSessionModification:
        """
        Mark authentication as failed.

        Args:
            reason: Reason for failure

        Returns:
            UpdateAuthSessionModification with session and events
        """
        self.status = AuthSessionStatus.FAILED
        self.failure_reason = reason

        event = AuthenticationFailed(
            session_id=self.id,
            subject_id=self.subject_id,
            reason=reason,
            ip_address=self.ip_address,
        )
        self.add_domain_event(event)
        self.increment_version()

        return UpdateAuthSessionModification(self, [event])

    def revoke(self, reason: str = "user_logout") -> UpdateAuthSessionModification:
        """
        Revoke an active session (logout).

        Args:
            reason: Reason for revocation (default: "user_logout")

        Returns:
            UpdateAuthSessionModification with session and events

        Raises:
            AuthDomainError: If session is not in AUTHENTICATED state
        """
        if self.status != AuthSessionStatus.AUTHENTICATED:
            raise AuthDomainError(
                "Can only revoke an authenticated session", code="INVALID_STATE"
            )

        self.status = AuthSessionStatus.REVOKED

        event = SessionRevoked(
            session_id=self.id,
            subject_id=self.subject_id,
            reason=reason,
        )
        self.add_domain_event(event)
        self.increment_version()

        return UpdateAuthSessionModification(self, [event])

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def can_validate_otp(self) -> bool:
        """Check if session is in a state where OTP can be validated."""
        return (
            self.status == AuthSessionStatus.PENDING_OTP
            and not self.is_expired()
            and self.pending_access_token is not None
        )

    def get_user_claims_object(self) -> Optional["UserClaims"]:
        """
        Reconstruct a UserClaims value object from stored claims dict.

        Useful for passing to OTP services that expect UserClaims.

        Returns:
            UserClaims object or None if no claims stored
        """
        if not self.user_claims:
            return None

        from cqrs_ddd_auth.domain.value_objects import UserClaims

        # Extract known fields, rest goes to attributes
        known_fields = {"sub", "username", "email", "groups", "roles"}
        attributes = {
            k: v for k, v in self.user_claims.items() if k not in known_fields
        }

        return UserClaims(
            sub=self.user_claims.get("sub", self.subject_id or ""),
            username=self.user_claims.get("username", self.username or ""),
            email=self.user_claims.get("email", ""),
            groups=tuple(self.user_claims.get("groups", [])),
            roles=tuple(),  # Roles not stored in simple dict
            attributes=attributes,
        )

    def _complete_authentication(self, events: list) -> None:
        """Internal method to complete the authentication flow."""
        self.status = AuthSessionStatus.AUTHENTICATED
        events.append(
            AuthenticationSucceeded(
                session_id=self.id,
                subject_id=self.subject_id,
                username=self.username or "",
                groups=tuple(self.user_claims.get("groups", []))
                if self.user_claims
                else (),
                ip_address=self.ip_address,
            )
        )

    def _check_can_transition(self, expected_status: AuthSessionStatus) -> None:
        """Validate state transition."""
        if self.status != expected_status:
            raise AuthDomainError(
                f"Invalid state transition: expected {expected_status.value}, "
                f"got {self.status.value}",
                code="INVALID_TRANSITION",
            )
        if self.is_expired():
            self.status = AuthSessionStatus.EXPIRED
            raise AuthDomainError("Session has expired", code="SESSION_EXPIRED")

    # ═══════════════════════════════════════════════════════════════
    # SERIALIZATION
    # ═══════════════════════════════════════════════════════════════

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to dictionary for storage."""
        return {
            "session_id": self.id,
            "status": self.status.value,
            "subject_id": self.subject_id,
            "username": self.username,
            "pending_access_token": self.pending_access_token,
            "pending_refresh_token": self.pending_refresh_token,
            "otp_required": self.otp_required,
            "available_otp_methods": self.available_otp_methods,
            "otp_method_used": self.otp_method_used,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "failure_reason": self.failure_reason,
            "user_claims": self.user_claims,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthSession":
        """Deserialize session from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)

        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        status = data.get("status", AuthSessionStatus.PENDING_CREDENTIALS.value)
        if isinstance(status, str):
            status = AuthSessionStatus(status)

        session = cls(
            entity_id=data.get("session_id"),
            status=status,
            subject_id=data.get("subject_id"),
            username=data.get("username"),
            pending_access_token=data.get("pending_access_token"),
            pending_refresh_token=data.get("pending_refresh_token"),
            otp_required=data.get("otp_required", False),
            available_otp_methods=data.get("available_otp_methods", []),
            otp_method_used=data.get("otp_method_used"),
            ip_address=data.get("ip_address", ""),
            user_agent=data.get("user_agent", ""),
            expires_at=expires_at,
            failure_reason=data.get("failure_reason"),
            user_claims=data.get("user_claims"),
        )

        # Restore created_at and version
        if created_at:
            session._created_at = created_at
        if "version" in data:
            session._version = data["version"]

        return session


class OTPChallengeStatus(str, Enum):
    """Status of an OTP challenge."""

    PENDING = "pending"
    USED = "used"
    EXPIRED = "expired"
    MAX_ATTEMPTS = "max_attempts"


# ═══════════════════════════════════════════════════════════════
# ENTITIES
# ═══════════════════════════════════════════════════════════════


class OTPChallenge(Entity):
    """
    Entity representing an OTP challenge for email/SMS verification.

    Has identity (user_id + method) and mutable state (attempts, status).
    Challenges expire after a configurable time.
    """

    MAX_ATTEMPTS = 5

    def __init__(
        self,
        entity_id: str = None,
        user_id: str = "",
        method: str = "",  # 'email', 'sms'
        secret: str = "",  # Base32 secret for pyotp verification
        expires_at: datetime = None,
        attempts: int = 0,
        status: OTPChallengeStatus = OTPChallengeStatus.PENDING,
        **kwargs,
    ):
        super().__init__(entity_id=entity_id, **kwargs)
        self.user_id = user_id
        self.method = method
        self.secret = secret
        self.expires_at = expires_at or (
            datetime.now(timezone.utc) + timedelta(minutes=2)
        )
        self.attempts = attempts
        self.status = status

    @classmethod
    def create(
        cls,
        user_id: str,
        method: str,
        secret: str,
        expiration_seconds: int = 120,
    ) -> "OTPChallenge":
        """Factory method to create a new OTP challenge."""
        return cls(
            entity_id=str(uuid.uuid4()),
            user_id=user_id,
            method=method,
            secret=secret,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=expiration_seconds),
        )

    def is_expired(self) -> bool:
        """Check if the challenge has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """Check if the challenge can still be used."""
        return (
            self.status == OTPChallengeStatus.PENDING
            and not self.is_expired()
            and self.attempts < self.MAX_ATTEMPTS
        )

    def increment_attempts(self) -> None:
        """Increment the failed attempts counter."""
        self.attempts += 1
        self.increment_version()

        if self.attempts >= self.MAX_ATTEMPTS:
            self.status = OTPChallengeStatus.MAX_ATTEMPTS

    def mark_used(self) -> None:
        """Mark the challenge as successfully used."""
        self.status = OTPChallengeStatus.USED
        self.increment_version()

    def verify_code(self, code: str) -> bool:
        """
        Verify a code against this challenge using pyotp.

        Returns:
            True if code is valid, False otherwise
        """
        if not self.is_valid():
            return False

        import pyotp

        # Calculate interval based on expiration time
        interval = int((self.expires_at - self.created_at).total_seconds())
        totp = pyotp.TOTP(self.secret, digits=len(code), interval=interval)

        if totp.verify(code, valid_window=1):
            self.mark_used()
            return True

        self.increment_attempts()
        return False


__all__ = [
    # AuthSession
    "AuthSession",
    "AuthSessionStatus",
    "CreateAuthSessionModification",
    "UpdateAuthSessionModification",
    # OTP
    "OTPChallenge",
    "OTPChallengeStatus",
]
