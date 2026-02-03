"""Application layer for authentication - Commands, Queries, Handlers, Results."""

from cqrs_ddd.core import CommandResponse, QueryResponse

from cqrs_ddd_auth.application.commands import (
    AuthenticateWithCredentials,
    ValidateOTP,
    RefreshTokens,
    Logout,
    RevokeAllSessions,
    SetupTOTP,
    ConfirmTOTPSetup,
    DisableTOTP,
    # Saga Commands
    SendOTPChallenge,
    GrantTemporaryElevation,
    RevokeElevation,
    ResumeSensitiveOperation,
    # User management commands
    CreateUser,
    UpdateUser,
    DeleteUser,
    SetUserPassword,
    SendPasswordReset,
    SendVerifyEmail,
    AssignRoles,
    RemoveRoles,
    AddToGroups,
    RemoveFromGroups,
)
from cqrs_ddd_auth.application.sync_commands import (
    SyncIdentityProvider,
    SyncIdentityProviderHandler,
    SyncResult,
)
from cqrs_ddd_auth.application.event_handlers import (
    IdentityChangeSyncHandler,
    register_identity_sync_handlers,
)
from cqrs_ddd_auth.application.sagas import (
    StepUpAuthenticationSaga,
)
from cqrs_ddd_auth.application.queries import (
    # Auth queries
    GetUserInfo,
    GetAvailableOTPMethods,
    ListActiveSessions,
    GetSessionDetails,
    CheckTOTPEnabled,
    # User management queries
    GetUser,
    GetUserByUsername,
    GetUserByEmail,
    ListUsers,
    GetUserRoles,
    GetUserGroups,
    GetTypeLevelPermissions,
)
from cqrs_ddd_auth.application.results import (
    AuthStatus,
    AuthResult,
    TokenPair,
    OTPChallengeResult,
    TOTPSetupResult,
    LogoutResult,
    # User management command results
    CreateUserResult,
    UpdateUserResult,
    DeleteUserResult,
    SetPasswordResult,
    SendPasswordResetResult,
    SendVerifyEmailResult,
    AssignRolesResult,
    RemoveRolesResult,
    AddToGroupsResult,
    RemoveFromGroupsResult,
    # Auth query results
    UserInfoResult,
    AvailableOTPMethodsResult,
    OTPMethodInfo,
    ListSessionsResult,
    SessionInfo,
    TOTPStatusResult,
    # User management query results
    UserResult,
    ListUsersResult,
    RoleInfo,
    UserRolesResult,
    GroupInfo,
    UserGroupsResult,
    TypeLevelPermissionsResult,
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
    # User management command handlers
    CreateUserHandler,
    UpdateUserHandler,
    DeleteUserHandler,
    SetUserPasswordHandler,
    SendPasswordResetHandler,
    SendVerifyEmailHandler,
    AssignRolesHandler,
    RemoveRolesHandler,
    AddToGroupsHandler,
    RemoveFromGroupsHandler,
    # Auth query handlers
    GetUserInfoHandler,
    GetAvailableOTPMethodsHandler,
    ListActiveSessionsHandler,
    GetSessionDetailsHandler,
    CheckTOTPEnabledHandler,
    # User management query handlers
    GetUserHandler,
    GetUserByUsernameHandler,
    GetUserByEmailHandler,
    ListUsersHandler,
    GetUserRolesHandler,
    GetUserGroupsHandler,
    GetTypeLevelPermissionsHandler,
)

__all__ = [
    # Base
    "CommandResponse",
    "QueryResponse",
    # Auth Commands
    "AuthenticateWithCredentials",
    "ValidateOTP",
    "SendOTPChallenge",
    "RefreshTokens",
    "Logout",
    "RevokeAllSessions",
    "SetupTOTP",
    "ConfirmTOTPSetup",
    "ConfirmTOTPSetup",
    "DisableTOTP",
    # Saga Commands
    "SendOTPChallenge",
    "GrantTemporaryElevation",
    "RevokeElevation",
    "ResumeSensitiveOperation",
    # User Management Commands
    "CreateUser",
    "UpdateUser",
    "DeleteUser",
    "SetUserPassword",
    "SendPasswordReset",
    "SendVerifyEmail",
    "AssignRoles",
    "RemoveRoles",
    "AddToGroups",
    "RemoveFromGroups",
    # Sync Commands
    "SyncIdentityProvider",
    "SyncIdentityProviderHandler",
    "SyncResult",
    # Event Handlers
    "IdentityChangeSyncHandler",
    "register_identity_sync_handlers",
    # Auth Queries
    "GetUserInfo",
    "GetAvailableOTPMethods",
    "ListActiveSessions",
    "GetSessionDetails",
    "CheckTOTPEnabled",
    # User Management Queries
    "GetUser",
    "GetUserByUsername",
    "GetUserByEmail",
    "ListUsers",
    "GetUserRoles",
    "GetUserGroups",
    "GetTypeLevelPermissions",
    # Auth Command Results
    "AuthStatus",
    "AuthResult",
    "TokenPair",
    "OTPChallengeResult",
    "TOTPSetupResult",
    "LogoutResult",
    # User Management Command Results
    "CreateUserResult",
    "UpdateUserResult",
    "DeleteUserResult",
    "SetPasswordResult",
    "SendPasswordResetResult",
    "SendVerifyEmailResult",
    "AssignRolesResult",
    "RemoveRolesResult",
    "AddToGroupsResult",
    "RemoveFromGroupsResult",
    # Auth Query Results
    "UserInfoResult",
    "AvailableOTPMethodsResult",
    "OTPMethodInfo",
    "ListSessionsResult",
    "SessionInfo",
    "TOTPStatusResult",
    # User Management Query Results
    "UserResult",
    "ListUsersResult",
    "RoleInfo",
    "UserRolesResult",
    "GroupInfo",
    "UserGroupsResult",
    "TypeLevelPermissionsResult",
    # Auth Command Handlers
    "AuthenticateWithCredentialsHandler",
    "ValidateOTPHandler",
    "SendOTPChallengeHandler",
    "RefreshTokensHandler",
    "LogoutHandler",
    "SetupTOTPHandler",
    "ConfirmTOTPSetupHandler",
    # User Management Command Handlers
    "CreateUserHandler",
    "UpdateUserHandler",
    "DeleteUserHandler",
    "SetUserPasswordHandler",
    "SendPasswordResetHandler",
    "SendVerifyEmailHandler",
    "AssignRolesHandler",
    "RemoveRolesHandler",
    "AddToGroupsHandler",
    "RemoveFromGroupsHandler",
    # Auth Query Handlers
    "GetUserInfoHandler",
    "GetAvailableOTPMethodsHandler",
    "ListActiveSessionsHandler",
    "GetSessionDetailsHandler",
    "CheckTOTPEnabledHandler",
    # User Management Query Handlers
    "GetUserHandler",
    "GetUserByUsernameHandler",
    "GetUserByEmailHandler",
    "ListUsersHandler",
    "GetUserRolesHandler",
    "GetUserGroupsHandler",
    "GetTypeLevelPermissionsHandler",
    # Sagas
    "StepUpAuthenticationSaga",
]
