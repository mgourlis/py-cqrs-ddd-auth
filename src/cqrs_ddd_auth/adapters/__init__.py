"""Concrete infrastructure adapters (Keycloak, ABAC, OTP, Tokens, Repositories)."""

# Token handling (always available - no external deps)
from cqrs_ddd_auth.adapters.tokens import (
    TokenSource,
    TokenExtractionResult,
    TokenRefreshResult,
    TokenRefreshAdapter,
)

# In-memory repositories (always available)
from cqrs_ddd_auth.adapters.repositories import (
    InMemorySessionRepository,
    InMemoryTOTPSecretRepository,
    InMemoryOTPChallengeRepository,
)

__all__ = [
    # Token Handling
    "TokenSource",
    "TokenExtractionResult",
    "TokenRefreshResult",
    "TokenRefreshAdapter",
    # Repositories
    "InMemorySessionRepository",
    "InMemoryTOTPSecretRepository",
    "InMemoryOTPChallengeRepository",
]

# OTP Services (optional - requires pyotp)
try:
    from cqrs_ddd_auth.adapters.otp import (
        TOTPService,
        EmailOTPService,
        SMSOTPService,
        CompositeOTPService,
    )
    HAS_PYOTP = True
    __all__.extend([
        "TOTPService",
        "EmailOTPService",
        "SMSOTPService",
        "CompositeOTPService",
    ])
except ImportError:
    HAS_PYOTP = False

# Keycloak Adapter (optional - requires httpx, PyJWT)
try:
    from cqrs_ddd_auth.adapters.keycloak import (
        KeycloakAdapter,
        KeycloakConfig,
        AuthenticationError,
        InvalidTokenError,
        GroupPathStrategy,  # Keycloak-specific group handling
    )
    from cqrs_ddd_auth.adapters.keycloak_admin import (
        KeycloakAdminAdapter,
        KeycloakAdminConfig,
        UserManagementError,
        UserNotFoundError,
    )
    HAS_KEYCLOAK = True
    __all__.extend([
        "KeycloakAdapter",
        "KeycloakConfig",
        "AuthenticationError",
        "InvalidTokenError",
        "GroupPathStrategy",
        "KeycloakAdminAdapter",
        "KeycloakAdminConfig",
        "UserManagementError",
        "UserNotFoundError",
    ])
except ImportError:
    HAS_KEYCLOAK = False

# ABAC Adapter (optional - requires stateful-abac-sdk)
try:
    from cqrs_ddd_auth.adapters.abac import (
        StatefulABACAdapter,
        ABACClientConfig,
    )
    HAS_ABAC = True
    __all__.extend([
        "StatefulABACAdapter",
        "ABACClientConfig",
    ])
except ImportError:
    HAS_ABAC = False
