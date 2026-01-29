"""Port interfaces (Protocols) for infrastructure adapters."""

from cqrs_ddd_auth.ports.identity_provider import (
    IdentityProviderPort,
    TokenResponse,
)
from cqrs_ddd_auth.ports.otp import (
    OTPServicePort,
    TOTPSecretRepository,
    OTPChallengeRepository,
)
from cqrs_ddd_auth.ports.authorization import (
    ABACAuthorizationPort,
)
from cqrs_ddd_auth.ports.communication import (
    EmailSenderPort,
    SMSSenderPort,
)
from cqrs_ddd_auth.ports.session import (
    AuthSessionRepository,
)

__all__ = [
    # Identity Provider
    "IdentityProviderPort",
    "TokenResponse",
    # OTP
    "OTPServicePort",
    "TOTPSecretRepository",
    "OTPChallengeRepository",
    # Authorization
    "ABACAuthorizationPort",
    # Communication
    "EmailSenderPort",
    "SMSSenderPort",
    # Session
    "AuthSessionRepository",
]
