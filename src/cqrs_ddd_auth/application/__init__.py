"""Application layer for authentication - Commands, Queries, Handlers, Results."""

from cqrs_ddd.core import CommandResponse, QueryResponse

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
from cqrs_ddd_auth.application.queries import (
    GetUserInfo,
    GetAvailableOTPMethods,
    ListActiveSessions,
    GetSessionDetails,
    CheckTOTPEnabled,
)
from cqrs_ddd_auth.application.results import (
    AuthStatus,
    AuthResult,
    TokenPair,
    OTPChallengeResult,
    TOTPSetupResult,
    LogoutResult,
    # Query results
    UserInfoResult,
    AvailableOTPMethodsResult,
    OTPMethodInfo,
    ListSessionsResult,
    SessionInfo,
    TOTPStatusResult,
)
from cqrs_ddd_auth.application.handlers import (
    # Command handlers
    AuthenticateWithCredentialsHandler,
    ValidateOTPHandler,
    SendOTPChallengeHandler,
    RefreshTokensHandler,
    LogoutHandler,
    SetupTOTPHandler,
    ConfirmTOTPSetupHandler,
    # Query handlers
    GetUserInfoHandler,
    GetAvailableOTPMethodsHandler,
    ListActiveSessionsHandler,
    GetSessionDetailsHandler,
    CheckTOTPEnabledHandler,
)

__all__ = [
    # Base
    "CommandResponse",
    "QueryResponse",
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
    # Queries
    "GetUserInfo",
    "GetAvailableOTPMethods",
    "ListActiveSessions",
    "GetSessionDetails",
    "CheckTOTPEnabled",
    # Command Results
    "AuthStatus",
    "AuthResult",
    "TokenPair",
    "OTPChallengeResult",
    "TOTPSetupResult",
    "LogoutResult",
    # Query Results
    "UserInfoResult",
    "AvailableOTPMethodsResult",
    "OTPMethodInfo",
    "ListSessionsResult",
    "SessionInfo",
    "TOTPStatusResult",
    # Command Handlers
    "AuthenticateWithCredentialsHandler",
    "ValidateOTPHandler",
    "SendOTPChallengeHandler",
    "RefreshTokensHandler",
    "LogoutHandler",
    "SetupTOTPHandler",
    "ConfirmTOTPSetupHandler",
    # Query Handlers
    "GetUserInfoHandler",
    "GetAvailableOTPMethodsHandler",
    "ListActiveSessionsHandler",
    "GetSessionDetailsHandler",
    "CheckTOTPEnabledHandler",
]

