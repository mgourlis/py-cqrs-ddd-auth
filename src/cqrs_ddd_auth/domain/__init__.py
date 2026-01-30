"""Domain layer for authentication."""

from cqrs_ddd.ddd import Modification
from cqrs_ddd.exceptions import DomainError

from cqrs_ddd_auth.domain.value_objects import (
    Credentials,
    TOTPSecret,
    UserClaims,
    # Role Unification
    RoleSource,
    AuthRole,
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
    OTPChallenge,
    OTPChallengeStatus,
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
    # Role Unification
    "RoleSource",
    "AuthRole",
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
    # Aggregates & Entities
    "AuthSession",
    "AuthSessionStatus",
    "OTPChallenge",
    "OTPChallengeStatus",
    # Modifications
    "CreateAuthSessionModification",
    "UpdateAuthSessionModification",
]
