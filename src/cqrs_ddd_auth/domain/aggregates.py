"""
Domain aggregates for authentication.

Aggregates are clusters of domain objects that can be treated as a single unit.
The root entity (the aggregate root) ensures the consistency of changes.

Uses AggregateRoot base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, List
import uuid

from cqrs_ddd.ddd import AggregateRoot, Modification
from cqrs_ddd.exceptions import DomainError

from cqrs_ddd_auth.domain.value_objects import UserClaims
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


class OTPChallengeStatus(str, Enum):
    """Status of an OTP challenge."""
    PENDING = "pending"
    USED = "used"
    EXPIRED = "expired"
    MAX_ATTEMPTS = "max_attempts"


# ═══════════════════════════════════════════════════════════════
# ENTITIES
# ═══════════════════════════════════════════════════════════════

from cqrs_ddd.ddd import Entity


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
        **kwargs
    ):
        super().__init__(entity_id=entity_id, **kwargs)
        self.user_id = user_id
        self.method = method
        self.secret = secret
        self.expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(minutes=2))
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
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=expiration_seconds),
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
# AGGREGATE ROOT
# ═══════════════════════════════════════════════════════════════

class AuthSession(AggregateRoot):
    """
    Aggregate root representing an authentication session.
    
    Tracks the multi-step authentication process from initial
    credentials through optional OTP to final token issuance.
    
    Note: This aggregate is transport-agnostic. Token delivery
    (header vs cookie) is handled at the framework adapter layer.
    """
    
    def __init__(
        self,
        entity_id: str = None,
        ip_address: str = "",
        user_agent: str = "",
        status: AuthSessionStatus = AuthSessionStatus.PENDING_CREDENTIALS,
        subject_id: Optional[str] = None,
        user_claims: Optional[UserClaims] = None,
        otp_challenge_id: Optional[str] = None,
        otp_method: Optional[str] = None,
        failure_reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        **kwargs
    ):
        super().__init__(entity_id=entity_id, **kwargs)
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.status = status
        self.subject_id = subject_id
        self.user_claims = user_claims
        self.otp_challenge_id = otp_challenge_id
        self.otp_method = otp_method
        self.failure_reason = failure_reason
        self.expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(minutes=30))
    
    @classmethod
    def create(cls, ip_address: str, user_agent: str = "") -> CreateAuthSessionModification:
        """Factory method to create a new authentication session."""
        session = cls(
            entity_id=str(uuid.uuid4()),
            ip_address=ip_address,
            user_agent=user_agent,
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
        user_claims: UserClaims, 
        requires_otp: bool,
        available_otp_methods: list[str] | None = None
    ) -> UpdateAuthSessionModification:
        """
        Called when primary credentials (username/password) are valid.
        
        Args:
            user_claims: Decoded claims from the IdP
            requires_otp: Whether OTP is required for this user
            available_otp_methods: List of OTP methods available (email, sms, totp)
        """
        self._check_can_transition(AuthSessionStatus.PENDING_CREDENTIALS)
        
        self.subject_id = user_claims.sub
        self.user_claims = user_claims
        
        events = []
        
        events.append(CredentialsValidated(
            session_id=self.id,
            subject_id=user_claims.sub,
            requires_otp=requires_otp,
        ))
        
        if requires_otp:
            self.status = AuthSessionStatus.PENDING_OTP
            events.append(OTPRequired(
                session_id=self.id,
                subject_id=self.subject_id,
                available_methods=tuple(available_otp_methods or []),
            ))
        else:
            self._complete_authentication(events)
        
        for event in events:
            self.add_domain_event(event)
        
        return UpdateAuthSessionModification(self, events)
    
    def otp_validated(self, method: str) -> UpdateAuthSessionModification:
        """
        Called when OTP is successfully validated.
        
        Args:
            method: The OTP method used (totp, email, sms)
        """
        self._check_can_transition(AuthSessionStatus.PENDING_OTP)
        
        self.otp_method = method
        events = []
        
        events.append(OTPValidated(
            session_id=self.id,
            subject_id=self.subject_id,
            method=method,
        ))
        
        self._complete_authentication(events)
        
        for event in events:
            self.add_domain_event(event)
        
        return UpdateAuthSessionModification(self, events)
    
    def fail(self, reason: str) -> UpdateAuthSessionModification:
        """Mark authentication as failed."""
        self.status = AuthSessionStatus.FAILED
        self.failure_reason = reason
        
        event = AuthenticationFailed(
            session_id=self.id,
            subject_id=self.subject_id,
            reason=reason,
            ip_address=self.ip_address,
        )
        self.add_domain_event(event)
        
        return UpdateAuthSessionModification(self, [event])
    
    def revoke(self, reason: str = "user_logout") -> UpdateAuthSessionModification:
        """Revoke an active session (logout)."""
        if self.status != AuthSessionStatus.AUTHENTICATED:
            raise DomainError("Can only revoke an authenticated session")
        
        self.status = AuthSessionStatus.REVOKED
        
        event = SessionRevoked(
            session_id=self.id,
            subject_id=self.subject_id,
            reason=reason,
        )
        self.add_domain_event(event)
        
        return UpdateAuthSessionModification(self, [event])
    
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def _complete_authentication(self, events: list) -> None:
        """Internal method to complete the authentication flow."""
        self.status = AuthSessionStatus.AUTHENTICATED
        events.append(AuthenticationSucceeded(
            session_id=self.id,
            subject_id=self.subject_id,
            username=self.user_claims.username if self.user_claims else "",
            groups=self.user_claims.groups if self.user_claims else (),
            ip_address=self.ip_address,
        ))
    
    def _check_can_transition(self, expected_status: AuthSessionStatus) -> None:
        """Validate state transition."""
        if self.status != expected_status:
            raise DomainError(
                f"Invalid state transition: expected {expected_status.value}, "
                f"got {self.status.value}"
            )
        if self.is_expired():
            self.status = AuthSessionStatus.EXPIRED
            raise DomainError("Session has expired")
