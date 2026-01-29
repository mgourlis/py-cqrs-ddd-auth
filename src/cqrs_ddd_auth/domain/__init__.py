"""Domain layer for authentication."""

from cqrs_ddd.ddd import Modification
from cqrs_ddd.exceptions import DomainError

from cqrs_ddd_auth.domain.value_objects import (
    Credentials,
    TOTPSecret,
    UserClaims,
    OTPChallenge,
)
from cqrs_ddd_auth.domain.events import (
    AuthSessionCreated,
    CredentialsValidated,
    OTPRequired,
    OTPChallengeIssued,
    OTPValidated,
    OTPValidationFailed,
    AuthenticationSucceeded,
    AuthenticationFailed,
    SessionRevoked,
    TokenRefreshed,
    TokenExpired,
)
from cqrs_ddd_auth.domain.aggregates import (
    AuthSession,
    AuthSessionStatus,
    CreateAuthSessionModification,
    UpdateAuthSessionModification,
)

__all__ = [
    # Base
    "Modification",
    "DomainError",
    # Value Objects
    "Credentials",
    "TOTPSecret",
    "UserClaims",
    "OTPChallenge",
    # Events
    "AuthSessionCreated",
    "CredentialsValidated",
    "OTPRequired",
    "OTPChallengeIssued",
    "OTPValidated",
    "OTPValidationFailed",
    "AuthenticationSucceeded",
    "AuthenticationFailed",
    "SessionRevoked",
    "TokenRefreshed",
    "TokenExpired",
    # Aggregates & Modifications
    "AuthSession",
    "AuthSessionStatus",
    "CreateAuthSessionModification",
    "UpdateAuthSessionModification",
]
