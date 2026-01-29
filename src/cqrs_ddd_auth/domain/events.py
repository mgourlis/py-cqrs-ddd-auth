"""
Domain events for authentication.

Domain events represent facts that have happened in the domain.
They are immutable records of state changes.

Uses DomainEvent base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from cqrs_ddd.ddd import DomainEvent


@dataclass(frozen=True)
class AuthSessionCreated(DomainEvent):
    """Raised when a new authentication session is started."""
    session_id: str
    ip_address: str
    user_agent: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthSessionCreated":
        return cls(
            session_id=data["session_id"],
            ip_address=data["ip_address"],
            user_agent=data.get("user_agent", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class CredentialsValidated(DomainEvent):
    """Raised when primary credentials (username/password) are validated."""
    session_id: str
    subject_id: str  # Renamed from user_id to avoid conflict with base class
    requires_otp: bool
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CredentialsValidated":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            requires_otp=data["requires_otp"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class OTPRequired(DomainEvent):
    """Raised when multi-factor authentication is required."""
    session_id: str
    subject_id: str
    available_methods: tuple[str, ...] = ()
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPRequired":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            available_methods=tuple(data.get("available_methods", [])),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class OTPChallengeIssued(DomainEvent):
    """Raised when an OTP challenge is sent (email/SMS)."""
    session_id: str
    subject_id: str
    method: str  # 'email', 'sms', 'totp'
    challenge_id: str
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPChallengeIssued":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            method=data["method"],
            challenge_id=data["challenge_id"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class OTPValidated(DomainEvent):
    """Raised when OTP is successfully validated."""
    session_id: str
    subject_id: str
    method: str
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPValidated":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            method=data["method"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class OTPValidationFailed(DomainEvent):
    """Raised when OTP validation fails."""
    session_id: str
    subject_id: str
    method: str
    reason: str  # 'expired', 'invalid', 'max_attempts'
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPValidationFailed":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            method=data["method"],
            reason=data["reason"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class AuthenticationSucceeded(DomainEvent):
    """Raised when the full authentication flow completes successfully."""
    session_id: str
    subject_id: str
    username: str
    groups: tuple[str, ...]
    ip_address: str
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationSucceeded":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            username=data["username"],
            groups=tuple(data.get("groups", [])),
            ip_address=data["ip_address"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class AuthenticationFailed(DomainEvent):
    """Raised when authentication fails at any step."""
    session_id: str
    reason: str
    subject_id: Optional[str] = None
    ip_address: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationFailed":
        return cls(
            session_id=data["session_id"],
            reason=data["reason"],
            subject_id=data.get("subject_id"),
            ip_address=data.get("ip_address", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class SessionRevoked(DomainEvent):
    """Raised when a session is explicitly revoked (logout)."""
    session_id: str
    subject_id: str
    reason: str = "user_logout"
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionRevoked":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            reason=data.get("reason", "user_logout"),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class TokenRefreshed(DomainEvent):
    """Raised when tokens are refreshed."""
    session_id: str
    subject_id: str
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenRefreshed":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass(frozen=True)
class TokenExpired(DomainEvent):
    """Raised when a token expires."""
    session_id: str
    subject_id: str
    token_type: str  # 'access' or 'refresh'
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> str:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenExpired":
        return cls(
            session_id=data["session_id"],
            subject_id=data["subject_id"],
            token_type=data["token_type"],
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )
