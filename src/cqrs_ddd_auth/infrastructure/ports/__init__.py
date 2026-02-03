"""Port interfaces (Protocols) for infrastructure adapters."""

from cqrs_ddd_auth.infrastructure.ports.identity_provider import (
    IdentityProviderPort,
    TokenResponse,
)
from cqrs_ddd_auth.infrastructure.ports.identity_provider_admin import (
    IdentityProviderAdminPort,
    GroupRolesCapability,
    CreateUserData,
    UpdateUserData,
    UserData,
    RoleData,
    GroupData,
    UserFilters,
)
from cqrs_ddd_auth.infrastructure.ports.otp import (
    OTPServicePort,
    TOTPSecretRepository,
    OTPChallengeRepository,
)
from cqrs_ddd_auth.infrastructure.ports.authorization import (
    ABACAuthorizationPort,
    AuthorizationConditionsResult,
    CheckAccessBatchResult,
)
from cqrs_ddd_auth.infrastructure.ports.communication import (
    EmailSenderPort,
    SMSSenderPort,
)
from cqrs_ddd_auth.infrastructure.ports.elevation import (
    ElevationStore,
)
from cqrs_ddd_auth.infrastructure.ports.session import (
    AuthSessionPort,
)

__all__ = [
    # Identity Provider
    "IdentityProviderPort",
    "TokenResponse",
    # Identity Provider Admin
    "IdentityProviderAdminPort",
    "GroupRolesCapability",
    "CreateUserData",
    "UpdateUserData",
    "UserData",
    "RoleData",
    "GroupData",
    "UserFilters",
    # OTP
    "OTPServicePort",
    "TOTPSecretRepository",
    "OTPChallengeRepository",
    # Authorization
    "ABACAuthorizationPort",
    "AuthorizationConditionsResult",
    "CheckAccessBatchResult",
    # Communication
    "EmailSenderPort",
    "SMSSenderPort",
    # Elevation
    "ElevationStore",
    # Session
    "AuthSessionPort",
]
