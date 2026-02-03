"""Concrete infrastructure adapters (Keycloak, ABAC, OTP, Tokens, Repositories)."""
# ruff: noqa: E402, F401

# Token handling (always available - no external deps)
from cqrs_ddd_auth.infrastructure.adapters.tokens import (
    TokenSource,
    TokenExtractionResult,
)


# Session adapters (new - recommended)
from cqrs_ddd_auth.infrastructure.adapters.session import (
    InMemorySessionAdapter,
    RedisSessionAdapter,
    KeycloakSessionAdapter,
)

# OTP storage adapters (new - recommended)
from cqrs_ddd_auth.infrastructure.adapters.otp_storage import (
    InMemoryOTPChallengeAdapter,
    RedisOTPChallengeAdapter,
    InMemoryTOTPSecretAdapter,
    RedisTOTPSecretAdapter,
)

# Elevation adapters
from cqrs_ddd_auth.infrastructure.adapters.elevation import (
    InMemoryElevationStore,
    RedisElevationStore,
)

# SQLAlchemy adapters (optional - requires sqlalchemy[asyncio])
try:
    from cqrs_ddd_auth.infrastructure.adapters.sqlalchemy_storage import (
        # Models
        Base as SQLAlchemyBase,
        AuthSessionModel,
        OTPChallengeModel,
        TOTPSecretModel,
        # Adapters
        SQLAlchemySessionAdapter,
        SQLAlchemyOTPChallengeAdapter,
        SQLAlchemyTOTPSecretAdapter,
        # Utilities
        hash_identifier,
    )

    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

__all__ = [
    # Token Handling
    "TokenSource",
    "TokenExtractionResult",
    # Session Adapters
    "InMemorySessionAdapter",
    "RedisSessionAdapter",
    "KeycloakSessionAdapter",
    # OTP Storage Adapters
    "InMemoryOTPChallengeAdapter",
    "RedisOTPChallengeAdapter",
    "InMemoryTOTPSecretAdapter",
    "RedisTOTPSecretAdapter",
    # Elevation Adapters
    "InMemoryElevationStore",
    "RedisElevationStore",
]

# Add SQLAlchemy exports if available
if HAS_SQLALCHEMY:
    __all__.extend(
        [
            "SQLAlchemyBase",
            "AuthSessionModel",
            "OTPChallengeModel",
            "TOTPSecretModel",
            "SQLAlchemySessionAdapter",
            "SQLAlchemyOTPChallengeAdapter",
            "SQLAlchemyTOTPSecretAdapter",
            "hash_identifier",
        ]
    )

# OTP Services (optional - requires pyotp)
try:
    from cqrs_ddd_auth.infrastructure.adapters.otp import (
        TOTPService,
        EmailOTPService,
        SMSOTPService,
        CompositeOTPService,
    )

    HAS_PYOTP = True
    __all__.extend(
        [
            "TOTPService",
            "EmailOTPService",
            "SMSOTPService",
            "CompositeOTPService",
        ]
    )
except ImportError:
    HAS_PYOTP = False

# Keycloak Adapter (optional - requires httpx, PyJWT)
try:
    from cqrs_ddd_auth.infrastructure.adapters.keycloak import (
        KeycloakAdapter,
        KeycloakConfig,
        AuthenticationError,
        InvalidTokenError,
        GroupPathStrategy,  # Keycloak-specific group handling
    )
    from cqrs_ddd_auth.infrastructure.adapters.keycloak_admin import (
        KeycloakAdminAdapter,
        KeycloakAdminConfig,
        UserManagementError,
        UserNotFoundError,
    )

    HAS_KEYCLOAK = True
    __all__.extend(
        [
            "KeycloakAdapter",
            "KeycloakConfig",
            "AuthenticationError",
            "InvalidTokenError",
            "GroupPathStrategy",
            "KeycloakAdminAdapter",
            "KeycloakAdminConfig",
            "UserManagementError",
            "UserNotFoundError",
        ]
    )
except ImportError:
    HAS_KEYCLOAK = False

# Communication Adapters
from cqrs_ddd_auth.infrastructure.adapters.communication import (  # noqa: F401
    ConsoleEmailSender,
    ConsoleSMSSender,
)

__all__.extend(
    [
        "ConsoleEmailSender",
        "ConsoleSMSSender",
    ]
)

# RBAC Adapter
from cqrs_ddd_auth.infrastructure.adapters.rbac import (  # noqa: F401
    SimpleRBACAdapter,
    OwnershipAwareRBACAdapter,
    RoleExtractor,
    default_role_extractor,
    OwnershipStrategy,
)

__all__.extend(
    [
        "SimpleRBACAdapter",
        "OwnershipAwareRBACAdapter",
        "RoleExtractor",
        "default_role_extractor",
        "OwnershipStrategy",
    ]
)
