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
