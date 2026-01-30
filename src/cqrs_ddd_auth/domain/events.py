"""
Domain events for authentication.

Domain events represent facts that have happened in the domain.
They are immutable records of state changes.

Uses DomainEvent base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any

from cqrs_ddd.ddd import DomainEvent


@dataclass
class AuthSessionCreated(DomainEvent):
    """Raised when a new authentication session is started."""
    session_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthSessionCreated":
        return cls(
            session_id=data.get("session_id"),
            ip_address=data.get("ip_address", ""),
            user_agent=data.get("user_agent", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class CredentialsValidated(DomainEvent):
    """Raised when primary credentials (username/password) are validated."""
    session_id: Optional[str] = None
    requires_otp: bool = False
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CredentialsValidated":
        return cls(
            session_id=data.get("session_id"),
            requires_otp=data.get("requires_otp", False),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPRequired(DomainEvent):
    """Raised when multi-factor authentication is required."""
    session_id: Optional[str] = None
    available_methods: tuple[str, ...] = ()
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPRequired":
        return cls(
            session_id=data.get("session_id"),
            available_methods=tuple(data.get("available_methods", [])),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPChallengeIssued(DomainEvent):
    """Raised when an OTP challenge is sent (email/SMS)."""
    session_id: Optional[str] = None
    method: str = ""  # 'email', 'sms', 'totp'
    challenge_id: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPChallengeIssued":
        return cls(
            session_id=data.get("session_id"),
            method=data.get("method", ""),
            challenge_id=data.get("challenge_id", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPValidated(DomainEvent):
    """Raised when OTP is successfully validated."""
    session_id: Optional[str] = None
    method: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPValidated":
        return cls(
            session_id=data.get("session_id"),
            method=data.get("method", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPValidationFailed(DomainEvent):
    """Raised when OTP validation fails."""
    session_id: Optional[str] = None
    method: str = ""
    reason: str = ""  # 'expired', 'invalid', 'max_attempts'
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPValidationFailed":
        return cls(
            session_id=data.get("session_id"),
            method=data.get("method", ""),
            reason=data.get("reason", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class AuthenticationSucceeded(DomainEvent):
    """Raised when the full authentication flow completes successfully."""
    session_id: Optional[str] = None
    username: str = ""
    groups: tuple[str, ...] = ()
    ip_address: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationSucceeded":
        return cls(
            session_id=data.get("session_id"),
            username=data.get("username", ""),
            groups=tuple(data.get("groups", [])),
            ip_address=data.get("ip_address", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class AuthenticationFailed(DomainEvent):
    """Raised when authentication fails at any step."""
    session_id: Optional[str] = None
    reason: str = ""
    ip_address: str = ""
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationFailed":
        return cls(
            session_id=data.get("session_id"),
            reason=data.get("reason", ""),
            ip_address=data.get("ip_address", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class SessionRevoked(DomainEvent):
    """Raised when a session is explicitly revoked (logout)."""
    session_id: Optional[str] = None
    reason: str = "user_logout"
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionRevoked":
        return cls(
            session_id=data.get("session_id"),
            reason=data.get("reason", "user_logout"),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class TokenRefreshed(DomainEvent):
    """Raised when tokens are refreshed."""
    session_id: Optional[str] = None
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenRefreshed":
        return cls(
            session_id=data.get("session_id"),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class TokenExpired(DomainEvent):
    """Raised when a token expires."""
    session_id: Optional[str] = None
    token_type: str = ""  # 'access' or 'refresh'
    
    @property
    def aggregate_type(self) -> str:
        return "AuthSession"
    
    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenExpired":
        return cls(
            session_id=data.get("session_id"),
            token_type=data.get("token_type", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )
