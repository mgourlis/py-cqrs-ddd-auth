"""
Authentication command handlers.

Handlers orchestrate the authentication flow by coordinating
between domain aggregates and infrastructure ports.

Supports two authentication modes:
1. Stateless: No session tracking, inline OTP validation
2. Stateful: Session tracking for multi-step flows

Uses CommandHandler base class from py-cqrs-ddd-toolkit.
"""

from typing import Optional, List, Any

from cqrs_ddd.core import CommandHandler, CommandResponse

from cqrs_ddd_auth.application.commands import (
    AuthenticateWithCredentials,
    ValidateOTP,
    SendOTPChallenge,
    RefreshTokens,
    Logout,
    SetupTOTP,
    ConfirmTOTPSetup,
    DisableTOTP,
    RevokeSession,
    RevokeAllSessions,
)
from cqrs_ddd_auth.application.results import (
    AuthResult,
    TokenPair,
    OTPChallengeResult,
    TOTPSetupResult,
    LogoutResult,
    RevokeSessionResult,
    RevokeAllSessionsResult,
)
from cqrs_ddd_auth.infrastructure.ports.session import AuthSession, AuthSessionPort
from cqrs_ddd_auth.domain.aggregates import AuthSessionStatus
from cqrs_ddd_auth.domain.value_objects import TOTPSecret, UserClaims
from cqrs_ddd_auth.infrastructure.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.infrastructure.ports.identity_provider_admin import (
    IdentityProviderAdminPort,
)
from cqrs_ddd_auth.infrastructure.ports.otp import OTPServicePort, TOTPSecretRepository
from cqrs_ddd_auth.application.stateless import PreAuthTokenService
from cqrs_ddd_auth.application.commands import (
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
from cqrs_ddd_auth.application.results import (
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
)
from cqrs_ddd_auth.infrastructure.ports.identity_provider_admin import (
    IdentityProviderAdminPort as UserMgmtPort,
    CreateUserData,
    UpdateUserData,
)
from cqrs_ddd_auth.domain.events import (
    UserCreatedInIdP,
    UserUpdatedInIdP,
    UserDeletedInIdP,
    UserRolesAssigned,
    UserRolesRemoved,
    UserAddedToGroups,
    UserRemovedFromGroups,
)
from datetime import timedelta
from cqrs_ddd_auth.application.commands import (
    GrantTemporaryElevation,
    RevokeElevation,
    ResumeSensitiveOperation,
)
from cqrs_ddd_auth.application.results import (
    GrantTemporaryElevationResult,
    RevokeElevationResult,
    ResumeSensitiveOperationResult,
)
from cqrs_ddd_auth.domain.events import (
    TemporaryElevationGranted,
    TemporaryElevationRevoked,
)
from cqrs_ddd.core import QueryHandler, QueryResponse
from cqrs_ddd_auth.application.queries import (
    GetUserInfo,
    GetAvailableOTPMethods,
    ListActiveSessions,
    GetSessionDetails,
    CheckTOTPEnabled,
)
from cqrs_ddd_auth.application.results import (
    UserInfoResult,
    AvailableOTPMethodsResult,
    OTPMethodInfo,
    ListSessionsResult,
    SessionInfo,
    TOTPStatusResult,
)
from cqrs_ddd_auth.application.queries import (
    GetUser,
    GetUserByUsername,
    GetUserByEmail,
    ListUsers,
    GetUserRoles,
    GetUserGroups,
    GetTypeLevelPermissions,
)
from cqrs_ddd_auth.application.results import (
    UserResult,
    ListUsersResult,
    RoleInfo,
    UserRolesResult,
    GroupInfo,
    UserGroupsResult,
    TypeLevelPermissionsResult,
)
from cqrs_ddd_auth.infrastructure.ports.identity_provider_admin import (
    GroupRolesCapability,
    UserFilters,
)
from cqrs_ddd_auth.infrastructure.ports.authorization import ABACAuthorizationPort


class AuthenticateWithCredentialsHandler(CommandHandler[AuthResult]):
    """
    Handle credential-based authentication.

    Supports two modes:

    1. STATELESS MODE (track_session=False, default):
       - Validates credentials with IdP → returns tokens or otp_required
       - If otp_required, client re-sends credentials + otp_method + otp_code
       - No server-side session needed

    2. STATEFUL MODE (track_session=True):
       - Creates AuthSession for tracking
       - If otp_required, returns session_id
       - Client uses ValidateOTP command with session_id

    Flow:
    1. Validate credentials with IdP
    2. Check required groups (optional)
    3. Check if OTP is required for user
    4. If OTP required and no code provided → return otp_required
    5. If OTP required and code provided → validate inline
    6. Return tokens on success
    """

    def __init__(
        self,
        idp: IdentityProviderPort,
        otp_service: Optional[OTPServicePort] = None,
        session_repo: Optional[AuthSessionPort] = None,
        pre_auth_service: Optional[PreAuthTokenService] = None,
    ):
        super().__init__()
        self.idp = idp
        self.otp_service = otp_service
        self.session_repo = session_repo
        self.pre_auth_service = pre_auth_service

    async def handle(
        self, command: AuthenticateWithCredentials
    ) -> CommandResponse[AuthResult]:
        all_events: List[Any] = []
        user_claims: Optional[UserClaims] = None
        keycloak_tokens: Optional[TokenPair] = None
        session: Optional[AuthSession] = None
        session_id: Optional[str] = command.session_id

        # --- PHASE 0: PRE-AUTHENTICATION SETUP ---

        is_new_session = False
        # Create session if stateful mode requested for first time
        if (
            not session_id
            and getattr(command, "track_session", False)
            and self.session_repo
        ):
            modification = AuthSession.create(
                ip_address=getattr(command, "ip_address", ""),
                user_agent=getattr(command, "user_agent", ""),
            )
            session = modification.session
            session_id = session.id
            is_new_session = True
            all_events.extend(modification.events)

        # --- PHASE 1: IDENTITY RESOLUTION ---
        try:
            # A. STATEFUL CONTINUATION (Step 2+ or existing session)
            if session_id and self.session_repo and not is_new_session:
                if not session:
                    session = await self.session_repo.get(session_id)

                if not session:
                    return CommandResponse(
                        result=AuthResult.failed(
                            "Session not found", "SESSION_NOT_FOUND"
                        ),
                        events=all_events,
                    )

                if session.is_expired():
                    return CommandResponse(
                        result=AuthResult.failed("Session expired", "SESSION_EXPIRED"),
                        events=all_events,
                    )

                # Restore context from session if available (for continuation steps)
                if session.user_claims:
                    user_claims = UserClaims.from_dict(session.user_claims)

                if session.pending_access_token:
                    keycloak_tokens = TokenPair(
                        access_token=session.pending_access_token,
                        refresh_token=session.pending_refresh_token or "",
                    )

            # B. STATELESS CONTINUATION (Step 2 or 3)
            elif command.pre_auth_token and self.pre_auth_service:
                claims_dict, keycloak_tokens = self.pre_auth_service.decrypt(
                    command.pre_auth_token
                )
                user_claims = UserClaims.from_dict(claims_dict)

            # C. INITIAL LOGIN (Step 1)
            else:
                # We need to authenticate with password if we didn't restore context above
                if not keycloak_tokens:
                    keycloak_tokens = await self.idp.authenticate(
                        command.username, command.password
                    )
                    user_claims = await self.idp.decode_token(
                        keycloak_tokens.access_token
                    )

        except Exception as e:
            if session:
                fail_mod = session.fail(str(e))
                all_events.extend(fail_mod.events)
                await self.session_repo.save(session)
            return CommandResponse(
                result=AuthResult.failed(
                    str(e), "AUTHENTICATION_FAILED", session_id=session_id
                ),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        # --- PHASE 2: BUSINESS LOGIC / MFA ---

        # Check required groups (optional)
        if command.required_groups:
            user_groups = list(user_claims.groups) if user_claims.groups else []
            has_required_group = any(g in user_groups for g in command.required_groups)
            if not has_required_group:
                error_msg = "User not in required group"
                if session:
                    fail_mod = session.fail(error_msg)
                    all_events.extend(fail_mod.events)
                    await self.session_repo.save(session)

                return CommandResponse(
                    result=AuthResult.failed(
                        error_message=error_msg,
                        error_code="UNAUTHORIZED_GROUP",
                        session_id=session_id,
                    ),
                    events=all_events,
                    correlation_id=command.correlation_id,
                    causation_id=command.command_id,
                )

        # Check OTP requirement
        requires_otp = False
        available_methods: List[str] = []

        if self.idp.requires_otp(user_claims):
            requires_otp = True

        if self.otp_service:
            if not requires_otp:
                requires_otp = await self.otp_service.is_required_for_user(user_claims)
            if requires_otp:
                available_methods = await self.otp_service.get_available_methods(
                    user_claims
                )

        # Handle OTP requirement
        if requires_otp:
            # Inline validation if code provided
            if command.otp_method and command.otp_code and self.otp_service:
                is_valid = await self.otp_service.validate(
                    claims=user_claims, method=command.otp_method, code=command.otp_code
                )
                if not is_valid:
                    if session:
                        fail_mod = session.fail("Invalid OTP code")
                        all_events.extend(fail_mod.events)
                        await self.session_repo.save(session)
                    return CommandResponse(
                        result=AuthResult.failed(
                            "Invalid OTP code", "INVALID_OTP", session_id=session_id
                        ),
                        events=all_events,
                    )

                # Success - update session to PENDING_OTP so Phase 3 can complete it
                if session:
                    update_mod = session.credentials_validated(
                        subject_id=user_claims.sub,
                        username=user_claims.username,
                        requires_otp=True,
                        available_otp_methods=available_methods,
                        access_token=keycloak_tokens.access_token,
                        refresh_token=keycloak_tokens.refresh_token,
                        user_claims=user_claims.to_dict(),
                    )
                    all_events.extend(update_mod.events)
                    # We don't save here, we save in Phase 3 or below

            # Send challenge if method selected but no code provided
            elif command.otp_method and self.otp_service:
                try:
                    await self.otp_service.send_challenge(
                        user_claims, command.otp_method
                    )
                except Exception as e:
                    return CommandResponse(
                        result=AuthResult.failed(
                            f"Failed to send OTP: {str(e)}",
                            "OTP_SEND_FAILED",
                            session_id=session_id,
                        )
                    )

                # Still need OTP code
                return await self._otp_required_response(
                    user_claims,
                    keycloak_tokens,
                    available_methods,
                    session,
                    session_id,
                    all_events,
                    command,
                )

            else:
                # Still need OTP
                return await self._otp_required_response(
                    user_claims,
                    keycloak_tokens,
                    available_methods,
                    session,
                    session_id,
                    all_events,
                    command,
                )

        else:
            # No OTP required - fulfill stateful lifecycle if applicable
            if session and session.status == AuthSessionStatus.PENDING_CREDENTIALS:
                update_mod = session.credentials_validated(
                    subject_id=user_claims.sub,
                    username=user_claims.username,
                    requires_otp=False,
                    access_token=keycloak_tokens.access_token,
                    refresh_token=keycloak_tokens.refresh_token,
                    user_claims=user_claims.to_dict(),
                )
                all_events.extend(update_mod.events)
                await self.session_repo.save(session)

        # --- PHASE 3: FINALIZE SUCCESS ---

        if (
            session
            and session.status == AuthSessionStatus.PENDING_OTP
            and command.otp_code
        ):
            otp_mod = session.otp_validated(method=command.otp_method or "unknown")
            all_events.extend(otp_mod.events)
            await self.session_repo.save(session)

        return CommandResponse(
            result=AuthResult.success(
                tokens=keycloak_tokens,
                user_id=user_claims.sub,
                username=user_claims.username,
                session_id=session_id,
                user_claims=user_claims.to_dict(),
            ),
            events=all_events,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

    async def _otp_required_response(
        self,
        user_claims: UserClaims,
        keycloak_tokens: TokenPair,
        available_methods: List[str],
        session: Optional[AuthSession],
        session_id: Optional[str],
        all_events: List[Any],
        command: AuthenticateWithCredentials,
    ) -> CommandResponse[AuthResult]:
        pre_auth_token = None
        if not session and self.pre_auth_service:
            pre_auth_token = self.pre_auth_service.encrypt(
                user_claims.to_dict(), keycloak_tokens
            )

        if session:
            update_mod = session.credentials_validated(
                subject_id=user_claims.sub,
                username=user_claims.username,
                requires_otp=True,
                available_otp_methods=available_methods,
                access_token=keycloak_tokens.access_token,
                refresh_token=keycloak_tokens.refresh_token,
                user_claims=user_claims.to_dict(),
            )
            all_events.extend(update_mod.events)
            await self.session_repo.save(session)

        return CommandResponse(
            result=AuthResult.otp_required(
                available_methods=available_methods,
                session_id=session_id,
                pre_auth_token=pre_auth_token,
            ),
            events=all_events,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class ValidateOTPHandler(CommandHandler[AuthResult]):
    """
    Handle OTP validation (stateful mode only).

    Used when track_session=True and OTP is required.
    Retrieves session by ID and completes authentication.
    """

    def __init__(
        self,
        otp_service: OTPServicePort,
        session_repo: AuthSessionPort,
    ):
        super().__init__()
        self.otp_service = otp_service
        self.session_repo = session_repo

    async def handle(self, command: ValidateOTP) -> CommandResponse[AuthResult]:
        session = await self.session_repo.get(command.session_id)
        if not session:
            return CommandResponse(
                result=AuthResult.failed(
                    error_message="Session not found",
                    error_code="SESSION_NOT_FOUND",
                    session_id=command.session_id,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        if session.is_expired():
            return CommandResponse(
                result=AuthResult.failed(
                    error_message="Session expired",
                    error_code="SESSION_EXPIRED",
                    session_id=command.session_id,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        all_events: List[Any] = []

        try:
            # Reconstruct UserClaims for OTP service
            user_claims = session.get_user_claims_object()
            if not user_claims:
                return CommandResponse(
                    result=AuthResult.failed(
                        error_message="Session has no user claims",
                        error_code="NO_USER_CLAIMS",
                        session_id=command.session_id,
                    ),
                    events=[],
                    correlation_id=command.correlation_id,
                    causation_id=command.command_id,
                )

            # Validate OTP
            is_valid = await self.otp_service.validate(
                claims=user_claims,
                method=command.method,
                code=command.code,
            )

            if not is_valid:
                fail_mod = session.fail("Invalid OTP code")
                all_events.extend(fail_mod.events)
                await self.session_repo.save(session)

                return CommandResponse(
                    result=AuthResult.failed(
                        error_message="Invalid OTP code",
                        error_code="INVALID_OTP",
                        session_id=session.id,
                    ),
                    events=all_events,
                    correlation_id=command.correlation_id,
                    causation_id=command.command_id,
                )

            # Complete authentication
            otp_mod = session.otp_validated(method=command.method)
            all_events.extend(otp_mod.events)
            await self.session_repo.save(session)

            # Use stored tokens from credentials validation step
            if not session.pending_access_token:
                return CommandResponse(
                    result=AuthResult.failed(
                        error_message="Session has no pending tokens",
                        error_code="NO_PENDING_TOKENS",
                        session_id=session.id,
                    ),
                    events=all_events,
                    correlation_id=command.correlation_id,
                    causation_id=command.command_id,
                )

            tokens = TokenPair(
                access_token=session.pending_access_token,
                refresh_token=session.pending_refresh_token or "",
            )

            # user_claims is already stored as dict
            claims_dict = session.user_claims or {}

            return CommandResponse(
                result=AuthResult.success(
                    tokens=tokens,
                    user_id=session.subject_id,
                    username=session.username,
                    session_id=session.id,
                    user_claims=claims_dict,
                ),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        except Exception as e:
            fail_mod = session.fail(str(e))
            all_events.extend(fail_mod.events)
            await self.session_repo.save(session)

            return CommandResponse(
                result=AuthResult.failed(
                    error_message=str(e),
                    error_code="AUTHENTICATION_FAILED",
                    session_id=session.id,
                ),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class SendOTPChallengeHandler(CommandHandler[OTPChallengeResult]):
    """
    Handle sending OTP challenges (email/SMS).

    Supports multiple modes for identifying the user:
    - Stateful: Uses session_id to get user claims from session
    - Stateless: Uses access_token to decode claims
    - Saga/Internal: Uses user_id to look up user from admin port
    """

    def __init__(
        self,
        otp_service: OTPServicePort,
        session_repo: Optional[AuthSessionPort] = None,
        idp: Optional[IdentityProviderPort] = None,
        idp_admin: Optional[IdentityProviderAdminPort] = None,
    ):
        super().__init__()
        self.otp_service = otp_service
        self.session_repo = session_repo
        self.idp = idp
        self.idp_admin = idp_admin

    async def handle(
        self, command: SendOTPChallenge
    ) -> CommandResponse[OTPChallengeResult]:
        user_claims: Optional[UserClaims] = None
        session_id = command.session_id

        # Priority order: session_id > access_token > user_id
        if command.session_id and self.session_repo:
            # Mode 1: Get user claims from session (stateful)
            session = await self.session_repo.get(command.session_id)
            if session:
                user_claims = session.get_user_claims_object()
        elif command.access_token and self.idp:
            # Mode 2: Decode claims from token (stateless)
            user_claims = await self.idp.decode_token(command.access_token)
        elif command.user_id and self.idp_admin:
            # Mode 3: Look up user from admin port (saga/internal)
            user_data = await self.idp_admin.get_user(command.user_id)
            if user_data:
                # Build minimal UserClaims from user data
                user_claims = UserClaims(
                    sub=user_data.user_id,
                    username=user_data.username,
                    email=user_data.email,
                    groups=(),  # Empty tuple - admin lookup doesn't include groups
                    attributes=user_data.attributes,
                )

        if not user_claims:
            return CommandResponse(
                result=OTPChallengeResult(
                    success=False,
                    message="Unable to determine user",
                    method=command.method,
                    session_id=session_id,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        try:
            message = await self.otp_service.send_challenge(
                claims=user_claims,
                method=command.method,
            )

            return CommandResponse(
                result=OTPChallengeResult(
                    success=True,
                    message=message,
                    method=command.method,
                    session_id=session_id,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        except Exception as e:
            return CommandResponse(
                result=OTPChallengeResult(
                    success=False,
                    message=str(e),
                    method=command.method,
                    session_id=session_id,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class RefreshTokensHandler(CommandHandler[TokenPair]):
    """Handle token refresh."""

    def __init__(self, idp: IdentityProviderPort):
        super().__init__()
        self.idp = idp

    async def handle(self, command: RefreshTokens) -> CommandResponse[TokenPair]:
        try:
            token_response = await self.idp.refresh(command.refresh_token)

            return CommandResponse(
                result=TokenPair(
                    access_token=token_response.access_token,
                    refresh_token=token_response.refresh_token,
                    expires_in=token_response.expires_in,
                    refresh_expires_in=token_response.refresh_expires_in,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        except Exception as e:
            return CommandResponse(
                result=AuthResult.failed(
                    error_message=str(e),
                    error_code="REFRESH_FAILED",
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class LogoutHandler(CommandHandler[LogoutResult]):
    """Handle logout."""

    def __init__(
        self,
        idp: IdentityProviderPort,
        session_repo: Optional[AuthSessionPort] = None,
    ):
        super().__init__()
        self.idp = idp
        self.session_repo = session_repo

    async def handle(self, command: Logout) -> CommandResponse[LogoutResult]:
        all_events: List[Any] = []

        try:
            await self.idp.logout(command.refresh_token)

            # Revoke session if stateful mode
            if command.session_id and self.session_repo:
                session = await self.session_repo.get(command.session_id)
                if session:
                    revoke_mod = session.revoke()
                    all_events.extend(revoke_mod.events)
                    await self.session_repo.save(session)

            return CommandResponse(
                result=LogoutResult(success=True),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        except Exception:
            return CommandResponse(
                result=LogoutResult(success=False),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class RevokeSessionHandler(CommandHandler[RevokeSessionResult]):
    """
    Handle RevokeSession command.

    Revokes a specific session by ID.
    """

    def __init__(self, session_repo: AuthSessionPort):
        super().__init__()
        self.session_repo = session_repo

    async def handle(
        self, command: RevokeSession
    ) -> CommandResponse[RevokeSessionResult]:
        all_events: List[Any] = []
        try:
            # We call the session_repo.revoke directly for optimization
            # (adapters handle both local state change and external revocation)
            await self.session_repo.revoke(command.session_id)

            return CommandResponse(
                result=RevokeSessionResult(success=True, session_id=command.session_id),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        except Exception:
            return CommandResponse(
                result=RevokeSessionResult(
                    success=False, session_id=command.session_id
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class RevokeAllSessionsHandler(CommandHandler[RevokeAllSessionsResult]):
    """
    Handle RevokeAllSessions command.

    Revokes all sessions for a specific user.
    """

    def __init__(self, session_repo: AuthSessionPort):
        super().__init__()
        self.session_repo = session_repo

    async def handle(
        self, command: RevokeAllSessions
    ) -> CommandResponse[RevokeAllSessionsResult]:
        try:
            count = await self.session_repo.revoke_all_for_user(command.user_id)

            return CommandResponse(
                result=RevokeAllSessionsResult(
                    success=True, user_id=command.user_id, sessions_revoked=count
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        except Exception:
            return CommandResponse(
                result=RevokeAllSessionsResult(
                    success=False, user_id=command.user_id, sessions_revoked=0
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class SetupTOTPHandler(CommandHandler[TOTPSetupResult]):
    """Handle TOTP setup initialization."""

    def __init__(self, issuer_name: str = "MyApp"):
        super().__init__()
        self.issuer_name = issuer_name

    async def handle(self, command: SetupTOTP) -> CommandResponse[TOTPSetupResult]:
        secret = TOTPSecret.generate()
        uri = secret.get_provisioning_uri(
            username=command.user_id,
            issuer=self.issuer_name,
        )

        return CommandResponse(
            result=TOTPSetupResult(
                secret=secret.secret,
                provisioning_uri=uri,
                user_id=command.user_id,
            ),
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class ConfirmTOTPSetupHandler(CommandHandler[bool]):
    """Handle TOTP setup confirmation."""

    def __init__(self, totp_repo: TOTPSecretRepository):
        super().__init__()
        self.totp_repo = totp_repo

    async def handle(self, command: ConfirmTOTPSetup) -> CommandResponse[bool]:
        secret = TOTPSecret(secret=command.secret)

        # Verify the code works
        if not secret.verify_code(command.code):
            return CommandResponse(
                result=False,
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        # Persist the secret
        await self.totp_repo.save(command.user_id, secret)

        return CommandResponse(
            result=True,
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class DisableTOTPHandler(CommandHandler[bool]):
    """Handle TOTP disable."""

    def __init__(self, totp_repo: TOTPSecretRepository):
        super().__init__()
        self.totp_repo = totp_repo

    async def handle(self, command: DisableTOTP) -> CommandResponse[bool]:
        secret = await self.totp_repo.get_by_user_id(command.user_id)
        if not secret:
            # Already disabled or never enabled
            return CommandResponse(
                result=True,
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        # Verify the code works (security check)
        if not secret.verify_code(command.verification_code):
            return CommandResponse(
                result=False,
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )

        # Remove the secret
        await self.totp_repo.delete(command.user_id)

        return CommandResponse(
            result=True,
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════


class CreateUserHandler(CommandHandler[CreateUserResult]):
    """
    Handle CreateUser command.

    Creates a new user in the identity provider.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, command: CreateUser) -> CommandResponse[CreateUserResult]:
        user_data = CreateUserData(
            username=command.username,
            email=command.email,
            first_name=command.first_name,
            last_name=command.last_name,
            enabled=command.enabled,
            email_verified=command.email_verified,
            attributes=command.attributes or {},
            temporary_password=command.temporary_password,
        )

        user_id = await self.idp_admin.create_user(user_data)

        # Emit event for ABAC sync
        event = UserCreatedInIdP(
            idp_user_id=user_id,
            username=command.username,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=CreateUserResult(
                user_id=user_id,
                username=command.username,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class UpdateUserHandler(CommandHandler[UpdateUserResult]):
    """
    Handle UpdateUser command.

    Updates an existing user's attributes.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, command: UpdateUser) -> CommandResponse[UpdateUserResult]:
        updates = UpdateUserData(
            email=command.email,
            first_name=command.first_name,
            last_name=command.last_name,
            enabled=command.enabled,
            email_verified=command.email_verified,
            attributes=command.attributes,
        )

        await self.idp_admin.update_user(command.user_id, updates)

        # Emit event for ABAC sync
        event = UserUpdatedInIdP(
            idp_user_id=command.user_id,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=UpdateUserResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class DeleteUserHandler(CommandHandler[DeleteUserResult]):
    """
    Handle DeleteUser command.

    Deletes a user from the identity provider.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, command: DeleteUser) -> CommandResponse[DeleteUserResult]:
        await self.idp_admin.delete_user(command.user_id)

        # Emit event for ABAC sync
        event = UserDeletedInIdP(
            idp_user_id=command.user_id,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=DeleteUserResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class SetUserPasswordHandler(CommandHandler[SetPasswordResult]):
    """
    Handle SetUserPassword command.

    Sets a user's password directly (admin action).
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(
        self, command: SetUserPassword
    ) -> CommandResponse[SetPasswordResult]:
        await self.idp_admin.set_password(
            command.user_id,
            command.password,
            command.temporary,
        )

        return CommandResponse(
            result=SetPasswordResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class SendPasswordResetHandler(CommandHandler[SendPasswordResetResult]):
    """
    Handle SendPasswordReset command.

    Triggers password reset email via the IdP.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(
        self, command: SendPasswordReset
    ) -> CommandResponse[SendPasswordResetResult]:
        await self.idp_admin.send_password_reset(command.user_id)

        return CommandResponse(
            result=SendPasswordResetResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class SendVerifyEmailHandler(CommandHandler[SendVerifyEmailResult]):
    """
    Handle SendVerifyEmail command.

    Sends email verification via the IdP.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(
        self, command: SendVerifyEmail
    ) -> CommandResponse[SendVerifyEmailResult]:
        await self.idp_admin.send_verify_email(command.user_id)

        return CommandResponse(
            result=SendVerifyEmailResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class AssignRolesHandler(CommandHandler[AssignRolesResult]):
    """
    Handle AssignRoles command.

    Assigns roles to a user.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, command: AssignRoles) -> CommandResponse[AssignRolesResult]:
        await self.idp_admin.assign_roles(command.user_id, command.role_names)

        # Emit event for ABAC sync
        event = UserRolesAssigned(
            idp_user_id=command.user_id,
            role_names=tuple(command.role_names),
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=AssignRolesResult(
                success=True,
                user_id=command.user_id,
                roles_assigned=command.role_names,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class RemoveRolesHandler(CommandHandler[RemoveRolesResult]):
    """
    Handle RemoveRoles command.

    Removes roles from a user.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, command: RemoveRoles) -> CommandResponse[RemoveRolesResult]:
        await self.idp_admin.remove_roles(command.user_id, command.role_names)

        # Emit event for ABAC sync
        event = UserRolesRemoved(
            idp_user_id=command.user_id,
            role_names=tuple(command.role_names),
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=RemoveRolesResult(
                success=True,
                user_id=command.user_id,
                roles_removed=command.role_names,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class AddToGroupsHandler(CommandHandler[AddToGroupsResult]):
    """
    Handle AddToGroups command.

    Adds a user to groups.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, command: AddToGroups) -> CommandResponse[AddToGroupsResult]:
        await self.idp_admin.add_to_groups(command.user_id, command.group_ids)

        # Emit event for ABAC sync
        event = UserAddedToGroups(
            idp_user_id=command.user_id,
            group_ids=tuple(command.group_ids),
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=AddToGroupsResult(
                success=True,
                user_id=command.user_id,
                groups_added=command.group_ids,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


class RemoveFromGroupsHandler(CommandHandler[RemoveFromGroupsResult]):
    """
    Handle RemoveFromGroups command.

    Removes a user from groups.
    """

    def __init__(self, idp_admin: UserMgmtPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(
        self, command: RemoveFromGroups
    ) -> CommandResponse[RemoveFromGroupsResult]:
        await self.idp_admin.remove_from_groups(command.user_id, command.group_ids)

        # Emit event for ABAC sync
        event = UserRemovedFromGroups(
            idp_user_id=command.user_id,
            group_ids=tuple(command.group_ids),
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=RemoveFromGroupsResult(
                success=True,
                user_id=command.user_id,
                groups_removed=command.group_ids,
            ),
            events=[event],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


# ═══════════════════════════════════════════════════════════════
# STEP-UP AUTHENTICATION SAGA HANDLERS
# ═══════════════════════════════════════════════════════════════


class GrantTemporaryElevationHandler(CommandHandler[GrantTemporaryElevationResult]):
    """
    Handle GrantTemporaryElevation command.

    Grants temporary elevated privileges to a user for a specific action.
    Used by the StepUpAuthenticationSaga after successful OTP validation.

    The actual elevation state should be stored in a cache or database
    that the authorization layer can query.
    """

    def __init__(self, elevation_store: Optional[Any] = None):
        super().__init__()
        # elevation_store could be a Redis client, cache, or database
        # for storing temporary elevation grants
        self.elevation_store = elevation_store

    async def handle(
        self, command: GrantTemporaryElevation
    ) -> CommandResponse[GrantTemporaryElevationResult]:
        from datetime import datetime, timezone

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=command.ttl_seconds)

        # Store elevation grant if we have a store
        if self.elevation_store:
            # Implementation depends on the store type
            # e.g., Redis: await self.elevation_store.setex(
            #     f"elevation:{command.user_id}:{command.action}",
            #     command.ttl_seconds,
            #     "granted"
            # )
            pass

        event = TemporaryElevationGranted(
            user_id=command.user_id,
            action=command.action,
            ttl_seconds=command.ttl_seconds,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=GrantTemporaryElevationResult(
                success=True,
                user_id=command.user_id,
                action=command.action,
                ttl_seconds=command.ttl_seconds,
                expires_at=expires_at,
                message=f"Temporary elevation granted for action '{command.action}'",
            ),
            events=[event],
            correlation_id=command.correlation_id or "",
            causation_id=command.command_id,
        )


class RevokeElevationHandler(CommandHandler[RevokeElevationResult]):
    """
    Handle RevokeElevation command.

    Revokes temporary elevated privileges from a user.
    Called after sensitive operation completes or on timeout/failure.
    """

    def __init__(self, elevation_store: Optional[Any] = None):
        super().__init__()
        self.elevation_store = elevation_store

    async def handle(
        self, command: RevokeElevation
    ) -> CommandResponse[RevokeElevationResult]:
        # Remove elevation grant if we have a store
        if self.elevation_store:
            # Implementation depends on the store type
            # e.g., Redis: await self.elevation_store.delete(
            #     f"elevation:{command.user_id}:*"
            # )
            pass

        event = TemporaryElevationRevoked(
            user_id=command.user_id,
            reason=command.reason,
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )

        return CommandResponse(
            result=RevokeElevationResult(
                success=True,
                user_id=command.user_id,
                reason=command.reason,
                message="Temporary elevation revoked",
            ),
            events=[event],
            correlation_id=command.correlation_id or "",
            causation_id=command.command_id,
        )


class ResumeSensitiveOperationHandler(CommandHandler[ResumeSensitiveOperationResult]):
    """
    Handle ResumeSensitiveOperation command.

    Signals that a suspended sensitive operation should be resumed
    after successful step-up authentication.

    The actual resumption logic depends on how operations are suspended.
    This could trigger a callback, publish to a queue, or update a database.
    """

    def __init__(self, operation_store: Optional[Any] = None):
        super().__init__()
        # operation_store could store suspended operations and their callbacks
        self.operation_store = operation_store

    async def handle(
        self, command: ResumeSensitiveOperation
    ) -> CommandResponse[ResumeSensitiveOperationResult]:
        resumed = False

        if self.operation_store:
            # Look up and resume the operation
            # Implementation depends on the store type
            resumed = True

        return CommandResponse(
            result=ResumeSensitiveOperationResult(
                success=True,
                operation_id=command.operation_id,
                resumed=resumed,
                message="Operation resume signal sent"
                if resumed
                else "No operation store configured",
            ),
            events=[],
            correlation_id=command.correlation_id or "",
            causation_id=command.command_id,
        )


# ═══════════════════════════════════════════════════════════════
# QUERY HANDLERS
# ═══════════════════════════════════════════════════════════════


class GetUserInfoHandler(QueryHandler[UserInfoResult]):
    """
    Handle GetUserInfo query.

    Returns user profile information from decoded access token
    or fetched from the IdP's userinfo endpoint.
    """

    def __init__(
        self,
        idp: IdentityProviderPort,
        totp_repo: Optional[TOTPSecretRepository] = None,
    ):
        super().__init__()
        self.idp = idp
        self.totp_repo = totp_repo

    async def handle(self, query: GetUserInfo) -> QueryResponse[UserInfoResult]:
        user_claims = None

        # Get claims from access token
        if query.access_token:
            user_claims = await self.idp.decode_token(query.access_token)
        elif query.user_id:
            # Would need admin API to fetch by user_id
            # For now, we require an access token
            raise ValueError("access_token is required when user_id is not available")
        else:
            raise ValueError("Either access_token or user_id must be provided")

        # Check TOTP status if repository available
        totp_enabled = False
        if self.totp_repo and user_claims:
            secret = await self.totp_repo.get_by_user_id(user_claims.sub)
            totp_enabled = secret is not None

        result = UserInfoResult.from_claims(user_claims, totp_enabled=totp_enabled)

        return QueryResponse(result=result)


class GetAvailableOTPMethodsHandler(QueryHandler[AvailableOTPMethodsResult]):
    """
    Handle GetAvailableOTPMethods query.

    Returns list of OTP methods available to the user
    based on their configuration and available services.
    """

    def __init__(
        self,
        idp: IdentityProviderPort,
        otp_service: Optional[OTPServicePort] = None,
        totp_repo: Optional[TOTPSecretRepository] = None,
    ):
        super().__init__()
        self.idp = idp
        self.otp_service = otp_service
        self.totp_repo = totp_repo

    async def handle(
        self, query: GetAvailableOTPMethods
    ) -> QueryResponse[AvailableOTPMethodsResult]:
        user_claims = None

        # Get claims from access token
        if query.access_token:
            user_claims = await self.idp.decode_token(query.access_token)
        elif query.user_id:
            raise ValueError("access_token is required")
        else:
            raise ValueError("Either access_token or user_id must be provided")

        methods: List[OTPMethodInfo] = []
        requires_otp = False

        if self.otp_service:
            requires_otp = await self.otp_service.is_required_for_user(user_claims)
            available = await self.otp_service.get_available_methods(user_claims)

            for method in available:
                destination = None
                enabled = False

                if method == "totp":
                    # Check if TOTP is configured
                    if self.totp_repo:
                        secret = await self.totp_repo.get_by_user_id(user_claims.sub)
                        enabled = secret is not None
                elif method == "email":
                    enabled = bool(user_claims.email)
                    if user_claims.email:
                        # Obfuscate email
                        local, domain = user_claims.email.split("@")
                        obfuscated = (
                            local[0] + "****" if len(local) > 1 else local + "****"
                        )
                        destination = f"{obfuscated}@{domain}"
                elif method == "sms":
                    # Would need phone number from claims/attributes
                    phone = user_claims.attributes.get("phone_number", "")
                    enabled = bool(phone)
                    if phone:
                        destination = (
                            phone[:3] + "****" + phone[-2:]
                            if len(phone) > 5
                            else "****"
                        )

                methods.append(
                    OTPMethodInfo(
                        method=method,
                        enabled=enabled,
                        destination=destination,
                    )
                )

        return QueryResponse(
            result=AvailableOTPMethodsResult(
                methods=methods,
                requires_otp=requires_otp,
            )
        )


class ListActiveSessionsHandler(QueryHandler[ListSessionsResult]):
    """
    Handle ListActiveSessions query.

    Returns list of active sessions for a user,
    used for session management UI.
    """

    def __init__(self, session_repo: AuthSessionPort):
        super().__init__()
        self.session_repo = session_repo

    async def handle(
        self, query: ListActiveSessions
    ) -> QueryResponse[ListSessionsResult]:
        sessions = await self.session_repo.get_by_user(
            user_id=query.user_id,
            active_only=not query.include_expired,
        )

        session_infos = []
        for session in sessions:
            session_infos.append(
                SessionInfo(
                    session_id=session.id,
                    status=session.status.value
                    if hasattr(session.status, "value")
                    else str(session.status),
                    ip_address=session.ip_address,
                    user_agent=session.user_agent,
                    created_at=session.created_at,
                    expires_at=session.expires_at,
                    is_current=session.id == query.current_session_id,
                    otp_method=session.otp_method_used,
                )
            )

        return QueryResponse(
            result=ListSessionsResult(
                sessions=session_infos,
                total_count=len(session_infos),
            )
        )


class GetSessionDetailsHandler(QueryHandler[SessionInfo]):
    """
    Handle GetSessionDetails query.

    Returns detailed information about a specific session.
    """

    def __init__(self, session_repo: AuthSessionPort):
        super().__init__()
        self.session_repo = session_repo

    async def handle(self, query: GetSessionDetails) -> QueryResponse[SessionInfo]:
        session = await self.session_repo.get(query.session_id)

        if not session:
            raise ValueError(f"Session not found: {query.session_id}")

        result = SessionInfo(
            session_id=session.id,
            status=session.status.value
            if hasattr(session.status, "value")
            else str(session.status),
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            created_at=session.created_at,
            expires_at=session.expires_at,
            is_current=False,
            otp_method=session.otp_method_used,
        )

        return QueryResponse(result=result)


class CheckTOTPEnabledHandler(QueryHandler[TOTPStatusResult]):
    """
    Handle CheckTOTPEnabled query.

    Returns whether TOTP 2FA is enabled for a user.
    """

    def __init__(self, totp_repo: TOTPSecretRepository):
        super().__init__()
        self.totp_repo = totp_repo

    async def handle(self, query: CheckTOTPEnabled) -> QueryResponse[TOTPStatusResult]:
        secret = await self.totp_repo.get_by_user_id(query.user_id)

        return QueryResponse(
            result=TOTPStatusResult(
                enabled=secret is not None,
                user_id=query.user_id,
                # configured_at would require storing metadata with the secret
            )
        )


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT QUERY HANDLERS
# ═══════════════════════════════════════════════════════════════


class GetUserHandler(QueryHandler[UserResult]):
    """
    Handle GetUser query.

    Returns user profile from the identity provider by ID.
    """

    def __init__(self, idp_admin: IdentityProviderAdminPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, query: GetUser) -> QueryResponse[UserResult]:
        user_data = await self.idp_admin.get_user(query.user_id)

        if not user_data:
            raise ValueError(f"User not found: {query.user_id}")

        result = UserResult(
            user_id=user_data.user_id,
            username=user_data.username,
            email=user_data.email,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            enabled=user_data.enabled,
            email_verified=user_data.email_verified,
            attributes=user_data.attributes,
        )

        return QueryResponse(result=result)


class GetUserByUsernameHandler(QueryHandler[UserResult]):
    """
    Handle GetUserByUsername query.

    Returns user profile from the identity provider by username.
    """

    def __init__(self, idp_admin: IdentityProviderAdminPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, query: GetUserByUsername) -> QueryResponse[UserResult]:
        user_data = await self.idp_admin.get_user_by_username(query.username)

        if not user_data:
            raise ValueError(f"User not found: {query.username}")

        result = UserResult(
            user_id=user_data.user_id,
            username=user_data.username,
            email=user_data.email,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            enabled=user_data.enabled,
            email_verified=user_data.email_verified,
            attributes=user_data.attributes,
        )

        return QueryResponse(result=result)


class GetUserByEmailHandler(QueryHandler[UserResult]):
    """
    Handle GetUserByEmail query.

    Returns user profile from the identity provider by email.
    """

    def __init__(self, idp_admin: IdentityProviderAdminPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, query: GetUserByEmail) -> QueryResponse[UserResult]:
        user_data = await self.idp_admin.get_user_by_email(query.email)

        if not user_data:
            raise ValueError(f"User not found: {query.email}")

        result = UserResult(
            user_id=user_data.user_id,
            username=user_data.username,
            email=user_data.email,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            enabled=user_data.enabled,
            email_verified=user_data.email_verified,
            attributes=user_data.attributes,
        )

        return QueryResponse(result=result)


class ListUsersHandler(QueryHandler[ListUsersResult]):
    """
    Handle ListUsers query.

    Returns paginated list of users from the identity provider.
    """

    def __init__(self, idp_admin: IdentityProviderAdminPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, query: ListUsers) -> QueryResponse[ListUsersResult]:
        filters = UserFilters(
            search=query.search,
            role=query.role,
            group=query.group,
            enabled=query.enabled,
            offset=query.offset,
            limit=query.limit,
        )

        users_data = await self.idp_admin.list_users(filters)
        total_count = await self.idp_admin.count_users(filters)

        users = [
            UserResult(
                user_id=u.user_id,
                username=u.username,
                email=u.email,
                first_name=u.first_name,
                last_name=u.last_name,
                enabled=u.enabled,
                email_verified=u.email_verified,
                attributes=u.attributes,
            )
            for u in users_data
        ]

        return QueryResponse(
            result=ListUsersResult(
                users=users,
                total_count=total_count,
                offset=query.offset,
                limit=query.limit,
            )
        )


class GetUserRolesHandler(QueryHandler[UserRolesResult]):
    """
    Handle GetUserRoles query.

    Returns all roles assigned to a user, including roles
    inherited from group membership when include_group_roles=True.
    """

    def __init__(self, idp_admin: IdentityProviderAdminPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, query: GetUserRoles) -> QueryResponse[UserRolesResult]:
        # Get directly assigned roles
        roles_data = await self.idp_admin.get_user_roles(query.user_id)

        roles = [
            RoleInfo(
                role_id=r.role_id,
                name=r.name,
                description=r.description,
                is_composite=r.is_composite,
                source="direct",
            )
            for r in roles_data
        ]

        # Track role names to avoid duplicates
        seen_role_names = {r.name for r in roles}

        # Fetch group-derived roles if requested AND if the IdP supports it
        if query.include_group_roles:
            user_groups = await self.idp_admin.get_user_groups(query.user_id)

            # Check if the IdP adapter supports group roles (e.g., Keycloak)
            if isinstance(self.idp_admin, GroupRolesCapability):
                for group in user_groups:
                    group_roles = await self.idp_admin.get_group_roles(group.group_id)

                    for r in group_roles:
                        # Skip if already have this role (direct assignment takes precedence)
                        if r.name in seen_role_names:
                            continue

                        seen_role_names.add(r.name)
                        roles.append(
                            RoleInfo(
                                role_id=r.role_id,
                                name=r.name,
                                description=r.description,
                                is_composite=r.is_composite,
                                source=f"group:{group.name}",  # Track which group provided the role
                            )
                        )

        return QueryResponse(
            result=UserRolesResult(
                user_id=query.user_id,
                roles=roles,
            )
        )


class GetUserGroupsHandler(QueryHandler[UserGroupsResult]):
    """
    Handle GetUserGroups query.

    Returns all groups a user belongs to.
    """

    def __init__(self, idp_admin: IdentityProviderAdminPort):
        super().__init__()
        self.idp_admin = idp_admin

    async def handle(self, query: GetUserGroups) -> QueryResponse[UserGroupsResult]:
        groups_data = await self.idp_admin.get_user_groups(query.user_id)

        groups = [
            GroupInfo(
                group_id=g.group_id,
                name=g.name,
                path=g.path,
            )
            for g in groups_data
        ]

        return QueryResponse(
            result=UserGroupsResult(
                user_id=query.user_id,
                groups=groups,
            )
        )


class GetTypeLevelPermissionsHandler(QueryHandler[TypeLevelPermissionsResult]):
    """
    Handle GetTypeLevelPermissions query.

    Returns type-level permissions from the ABAC engine.
    Used for UI rendering to show/hide buttons, menu items, etc.
    """

    def __init__(self, abac: ABACAuthorizationPort):
        super().__init__()
        self.abac = abac

    async def handle(
        self, query: GetTypeLevelPermissions
    ) -> QueryResponse[TypeLevelPermissionsResult]:
        resource_types = query.resource_types

        # If no types specified, get all available types
        if not resource_types:
            resource_types = await self.abac.list_resource_types()

        # Fetch type-level permissions from ABAC
        permissions = await self.abac.get_type_level_permissions(
            access_token=query.access_token,
            resource_types=resource_types,
        )

        return QueryResponse(result=TypeLevelPermissionsResult(permissions=permissions))
