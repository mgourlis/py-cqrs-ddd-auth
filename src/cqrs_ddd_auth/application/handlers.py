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
)
from cqrs_ddd_auth.application.results import (
    AuthResult,
    TokenPair,
    OTPChallengeResult,
    TOTPSetupResult,
    LogoutResult,
)
from cqrs_ddd_auth.domain.aggregates import AuthSession
from cqrs_ddd_auth.domain.value_objects import TOTPSecret
from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.ports.otp import OTPServicePort, TOTPSecretRepository
from cqrs_ddd_auth.ports.session import AuthSessionRepository


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
        session_repo: Optional[AuthSessionRepository] = None,
    ):
        super().__init__()
        self.idp = idp
        self.otp_service = otp_service
        self.session_repo = session_repo
    
    async def handle(self, command: AuthenticateWithCredentials) -> CommandResponse[AuthResult]:
        all_events: List[Any] = []
        session: Optional[AuthSession] = None
        session_id: Optional[str] = None
        
        # Create session if stateful mode
        if command.track_session and self.session_repo:
            modification = AuthSession.create(
                ip_address=command.ip_address,
                user_agent=command.user_agent,
            )
            session = modification.session
            session_id = session.id
            all_events.extend(modification.events)
        
        try:
            # 1. Authenticate with IdP
            token_response = await self.idp.authenticate(
                command.username, 
                command.password
            )
            user_claims = await self.idp.decode_token(token_response.access_token)
            
            # 2. Check required groups (optional)
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
            
            # 3. Check OTP requirement
            requires_otp = False
            available_methods: List[str] = []
            
            if self.otp_service:
                requires_otp = await self.otp_service.is_required_for_user(user_claims)
                if requires_otp:
                    available_methods = await self.otp_service.get_available_methods(user_claims)
            
            # 4. Handle OTP requirement
            if requires_otp:
                # Update session if stateful
                if session:
                    update_mod = session.credentials_validated(
                        user_claims=user_claims,
                        requires_otp=True,
                        available_otp_methods=available_methods,
                        access_token=token_response.access_token,
                        refresh_token=token_response.refresh_token,
                    )
                    all_events.extend(update_mod.events)
                    await self.session_repo.save(session)
                
                # Check if OTP code provided (stateless inline validation)
                if command.otp_code and command.otp_method:
                    # Validate OTP inline (stateless mode)
                    is_valid = await self.otp_service.validate(
                        claims=user_claims,
                        method=command.otp_method,
                        code=command.otp_code,
                    )
                    
                    if not is_valid:
                        if session:
                            fail_mod = session.fail("Invalid OTP code")
                            all_events.extend(fail_mod.events)
                            await self.session_repo.save(session)
                        
                        return CommandResponse(
                            result=AuthResult.failed(
                                error_message="Invalid OTP code",
                                error_code="INVALID_OTP",
                                session_id=session_id,
                            ),
                            events=all_events,
                            correlation_id=command.correlation_id,
                            causation_id=command.command_id,
                        )
                    
                    # OTP valid - mark session if stateful
                    if session:
                        otp_mod = session.otp_validated(method=command.otp_method)
                        all_events.extend(otp_mod.events)
                        await self.session_repo.save(session)
                    
                    # Fall through to return tokens
                
                elif command.otp_method and not command.otp_code:
                    # Method specified but no code - send challenge for email/SMS
                    if command.otp_method in ("email", "sms"):
                        await self.otp_service.send_challenge(user_claims, command.otp_method)
                    
                    return CommandResponse(
                        result=AuthResult.otp_required(
                            available_methods=available_methods,
                            session_id=session_id,
                            message=f"OTP required via {command.otp_method}",
                        ),
                        events=all_events,
                        correlation_id=command.correlation_id,
                        causation_id=command.command_id,
                    )
                
                else:
                    # No OTP method/code - return available methods
                    return CommandResponse(
                        result=AuthResult.otp_required(
                            available_methods=available_methods,
                            session_id=session_id,
                            message="OTP verification required",
                        ),
                        events=all_events,
                        correlation_id=command.correlation_id,
                        causation_id=command.command_id,
                    )
            else:
                # No OTP required - update session if stateful
                if session:
                    update_mod = session.credentials_validated(
                        user_claims=user_claims,
                        requires_otp=False,
                        available_otp_methods=[],
                        access_token=token_response.access_token,
                        refresh_token=token_response.refresh_token,
                    )
                    all_events.extend(update_mod.events)
                    await self.session_repo.save(session)
            
            # 5. Return success with tokens
            tokens = TokenPair(
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token,
                expires_in=token_response.expires_in,
                refresh_expires_in=token_response.refresh_expires_in,
            )
            
            # Include user claims as dict for legacy compatibility
            claims_dict = {
                "sub": user_claims.sub,
                "username": user_claims.username,
                "email": user_claims.email,
                "groups": list(user_claims.groups),
                **user_claims.attributes,
            }
            
            return CommandResponse(
                result=AuthResult.success(
                    tokens=tokens,
                    user_id=user_claims.sub,
                    username=user_claims.username,
                    session_id=session_id,
                    user_claims=claims_dict,
                ),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
            
        except Exception as e:
            if session:
                fail_mod = session.fail(str(e))
                all_events.extend(fail_mod.events)
                await self.session_repo.save(session)
            
            return CommandResponse(
                result=AuthResult.failed(
                    error_message=str(e),
                    error_code="AUTHENTICATION_FAILED",
                    session_id=session_id,
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
        session_repo: AuthSessionRepository,
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
            # Validate OTP
            is_valid = await self.otp_service.validate(
                claims=session.user_claims,
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
            
            claims_dict = {
                "sub": session.user_claims.sub,
                "username": session.user_claims.username,
                "email": session.user_claims.email,
                "groups": list(session.user_claims.groups),
                **session.user_claims.attributes,
            }
            
            return CommandResponse(
                result=AuthResult.success(
                    tokens=tokens,
                    user_id=session.subject_id,
                    username=session.user_claims.username,
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
    
    Works in both modes:
    - Stateful: Uses session_id to get user claims
    - Stateless: Uses access_token to decode claims
    """
    
    def __init__(
        self,
        otp_service: OTPServicePort,
        session_repo: Optional[AuthSessionRepository] = None,
        idp: Optional[IdentityProviderPort] = None,
    ):
        super().__init__()
        self.otp_service = otp_service
        self.session_repo = session_repo
        self.idp = idp
    
    async def handle(self, command: SendOTPChallenge) -> CommandResponse[OTPChallengeResult]:
        user_claims = None
        session_id = command.session_id
        
        # Get user claims from session or token
        if command.session_id and self.session_repo:
            session = await self.session_repo.get(command.session_id)
            if session and session.user_claims:
                user_claims = session.user_claims
        elif command.access_token and self.idp:
            user_claims = await self.idp.decode_token(command.access_token)
        
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


class LogoutHandler(CommandHandler[LogoutResult]):
    """Handle logout."""
    
    def __init__(
        self,
        idp: IdentityProviderPort,
        session_repo: Optional[AuthSessionRepository] = None,
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


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════

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
from cqrs_ddd_auth.ports.identity_provider_admin import (
    IdentityProviderAdminPort as UserMgmtPort,
    CreateUserData,
    UpdateUserData,
)


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
        
        return CommandResponse(
            result=CreateUserResult(
                user_id=user_id,
                username=command.username,
            ),
            events=[],
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
        
        return CommandResponse(
            result=UpdateUserResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[],
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
        
        return CommandResponse(
            result=DeleteUserResult(
                success=True,
                user_id=command.user_id,
            ),
            events=[],
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
    
    async def handle(self, command: SetUserPassword) -> CommandResponse[SetPasswordResult]:
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
    
    async def handle(self, command: SendPasswordReset) -> CommandResponse[SendPasswordResetResult]:
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
    
    async def handle(self, command: SendVerifyEmail) -> CommandResponse[SendVerifyEmailResult]:
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
        
        return CommandResponse(
            result=AssignRolesResult(
                success=True,
                user_id=command.user_id,
                roles_assigned=command.role_names,
            ),
            events=[],
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
        
        return CommandResponse(
            result=RemoveRolesResult(
                success=True,
                user_id=command.user_id,
                roles_removed=command.role_names,
            ),
            events=[],
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
        
        return CommandResponse(
            result=AddToGroupsResult(
                success=True,
                user_id=command.user_id,
                groups_added=command.group_ids,
            ),
            events=[],
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
    
    async def handle(self, command: RemoveFromGroups) -> CommandResponse[RemoveFromGroupsResult]:
        await self.idp_admin.remove_from_groups(command.user_id, command.group_ids)
        
        return CommandResponse(
            result=RemoveFromGroupsResult(
                success=True,
                user_id=command.user_id,
                groups_removed=command.group_ids,
            ),
            events=[],
            correlation_id=command.correlation_id,
            causation_id=command.command_id,
        )


# ═══════════════════════════════════════════════════════════════
# QUERY HANDLERS
# ═══════════════════════════════════════════════════════════════

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
    
    async def handle(self, query: GetAvailableOTPMethods) -> QueryResponse[AvailableOTPMethodsResult]:
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
                        obfuscated = local[0] + "****" if len(local) > 1 else local + "****"
                        destination = f"{obfuscated}@{domain}"
                elif method == "sms":
                    # Would need phone number from claims/attributes
                    phone = user_claims.attributes.get("phone_number", "")
                    enabled = bool(phone)
                    if phone:
                        destination = phone[:3] + "****" + phone[-2:] if len(phone) > 5 else "****"
                
                methods.append(OTPMethodInfo(
                    method=method,
                    enabled=enabled,
                    destination=destination,
                ))
        
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
    
    def __init__(self, session_repo: AuthSessionRepository):
        super().__init__()
        self.session_repo = session_repo
    
    async def handle(self, query: ListActiveSessions) -> QueryResponse[ListSessionsResult]:
        sessions = await self.session_repo.get_by_user_id(
            user_id=query.user_id,
            active_only=not query.include_expired,
        )
        
        session_infos = []
        for session in sessions:
            session_infos.append(SessionInfo(
                session_id=session.id,
                status=session.status.value if hasattr(session.status, 'value') else str(session.status),
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                created_at=session.created_at,
                expires_at=session.expires_at,
                is_current=session.id == query.current_session_id,
                otp_method=session.otp_method,
            ))
        
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
    
    def __init__(self, session_repo: AuthSessionRepository):
        super().__init__()
        self.session_repo = session_repo
    
    async def handle(self, query: GetSessionDetails) -> QueryResponse[SessionInfo]:
        session = await self.session_repo.get(query.session_id)
        
        if not session:
            raise ValueError(f"Session not found: {query.session_id}")
        
        result = SessionInfo(
            session_id=session.id,
            status=session.status.value if hasattr(session.status, 'value') else str(session.status),
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            created_at=session.created_at,
            expires_at=session.expires_at,
            is_current=False,
            otp_method=session.otp_method,
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
from cqrs_ddd_auth.ports.identity_provider_admin import (
    IdentityProviderAdminPort,
    GroupRolesCapability,
    UserFilters,
)
from cqrs_ddd_auth.ports.authorization import ABACAuthorizationPort


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
    
    async def handle(self, query: GetTypeLevelPermissions) -> QueryResponse[TypeLevelPermissionsResult]:
        resource_types = query.resource_types
        
        # If no types specified, get all available types
        if not resource_types:
            resource_types = await self.abac.list_resource_types()
        
        # Fetch type-level permissions from ABAC
        permissions = await self.abac.get_type_level_permissions(
            access_token=query.access_token,
            resource_types=resource_types,
        )
        
        return QueryResponse(
            result=TypeLevelPermissionsResult(permissions=permissions)
        )


