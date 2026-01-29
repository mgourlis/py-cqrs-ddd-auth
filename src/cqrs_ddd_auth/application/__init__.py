"""Application layer for authentication - Commands, Handlers, Results."""

from cqrs_ddd.core import CommandResponse

from cqrs_ddd_auth.application.commands import (
    AuthenticateWithCredentials,
    ValidateOTP,
    SendOTPChallenge,
    RefreshTokens,
    Logout,
    RevokeAllSessions,
    SetupTOTP,
    ConfirmTOTPSetup,
    DisableTOTP,
)
from cqrs_ddd_auth.application.results import (
    AuthStatus,
    AuthResult,
    TokenPair,
    OTPChallengeResult,
    TOTPSetupResult,
    LogoutResult,
)
from cqrs_ddd_auth.application.handlers import (
    AuthenticateWithCredentialsHandler,
    ValidateOTPHandler,
    SendOTPChallengeHandler,
    RefreshTokensHandler,
    LogoutHandler,
    SetupTOTPHandler,
    ConfirmTOTPSetupHandler,
)

__all__ = [
    # Base
    "CommandResponse",
    # Commands
    "AuthenticateWithCredentials",
    "ValidateOTP",
    "SendOTPChallenge",
    "RefreshTokens",
    "Logout",
    "RevokeAllSessions",
    "SetupTOTP",
    "ConfirmTOTPSetup",
    "DisableTOTP",
    # Results
    "AuthStatus",
    "AuthResult",
    "TokenPair",
    "OTPChallengeResult",
    "TOTPSetupResult",
    "LogoutResult",
    # Handlers
    "AuthenticateWithCredentialsHandler",
    "ValidateOTPHandler",
    "SendOTPChallengeHandler",
    "RefreshTokensHandler",
    "LogoutHandler",
    "SetupTOTPHandler",
    "ConfirmTOTPSetupHandler",
]
