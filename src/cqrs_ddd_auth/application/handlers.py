"""
Authentication command handlers.

Handlers orchestrate the authentication flow by coordinating
between domain aggregates and infrastructure ports.

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
    
    Flow:
    1. Create AuthSession
    2. Validate credentials with IdP
    3. Check if OTP is required
    4. Either complete auth or request OTP
    """
    
    def __init__(
        self,
        idp: IdentityProviderPort,
        otp_service: OTPServicePort,
        session_repo: AuthSessionRepository,
    ):
        super().__init__()
        self.idp = idp
        self.otp_service = otp_service
        self.session_repo = session_repo
    
    async def handle(self, command: AuthenticateWithCredentials) -> CommandResponse[AuthResult]:
        # Create session via factory
        modification = AuthSession.create(
            ip_address=command.ip_address,
            user_agent=command.user_agent,
        )
        session = modification.session
        all_events: List[Any] = modification.events.copy()
        
        try:
            # Authenticate with IdP
            token_response = await self.idp.authenticate(
                command.username, 
                command.password
            )
            user_claims = await self.idp.decode_token(token_response.access_token)
            
            # Check OTP requirement
            requires_otp = await self.otp_service.is_required_for_user(user_claims)
            available_methods = []
            
            if requires_otp:
                available_methods = await self.otp_service.get_available_methods(user_claims)
            
            # Update session
            update_mod = session.credentials_validated(
                user_claims=user_claims,
                requires_otp=requires_otp,
                available_otp_methods=available_methods,
            )
            all_events.extend(update_mod.events)
            
            # Save session
            await self.session_repo.save(session)
            
            if requires_otp:
                result = AuthResult.otp_required(
                    session_id=session.id,
                    available_methods=available_methods,
                )
            else:
                # Authentication complete
                tokens = TokenPair(
                    access_token=token_response.access_token,
                    refresh_token=token_response.refresh_token,
                    expires_in=token_response.expires_in,
                    refresh_expires_in=token_response.refresh_expires_in,
                )
                result = AuthResult.success(
                    session_id=session.id,
                    tokens=tokens,
                    user_id=user_claims.sub,
                    username=user_claims.username,
                )
            
            return CommandResponse(
                result=result,
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
            
        except Exception as e:
            fail_mod = session.fail(str(e))
            all_events.extend(fail_mod.events)
            await self.session_repo.save(session)
            
            result = AuthResult.failed(
                session_id=session.id,
                error_message=str(e),
            )
            return CommandResponse(
                result=result,
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class ValidateOTPHandler(CommandHandler[AuthResult]):
    """Handle OTP validation."""
    
    def __init__(
        self,
        otp_service: OTPServicePort,
        session_repo: AuthSessionRepository,
        idp: IdentityProviderPort,
    ):
        super().__init__()
        self.otp_service = otp_service
        self.session_repo = session_repo
        self.idp = idp
    
    async def handle(self, command: ValidateOTP) -> CommandResponse[AuthResult]:
        session = await self.session_repo.get(command.session_id)
        if not session:
            return CommandResponse(
                result=AuthResult.failed(
                    session_id=command.session_id,
                    error_message="Session not found",
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        
        if session.is_expired():
            return CommandResponse(
                result=AuthResult.failed(
                    session_id=command.session_id,
                    error_message="Session expired",
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
                        session_id=session.id,
                        error_message="Invalid OTP code",
                    ),
                    events=all_events,
                    correlation_id=command.correlation_id,
                    causation_id=command.command_id,
                )
            
            # Complete authentication
            otp_mod = session.otp_validated(method=command.method)
            all_events.extend(otp_mod.events)
            await self.session_repo.save(session)
            
            # Re-authenticate to get fresh tokens
            token_response = await self.idp.authenticate(
                session.user_claims.username,
                "",  # Password not needed - session is authenticated
            )
            
            tokens = TokenPair(
                access_token=token_response.access_token,
                refresh_token=token_response.refresh_token,
                expires_in=token_response.expires_in,
                refresh_expires_in=token_response.refresh_expires_in,
            )
            
            return CommandResponse(
                result=AuthResult.success(
                    session_id=session.id,
                    tokens=tokens,
                    user_id=session.subject_id,
                    username=session.user_claims.username,
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
                    session_id=session.id,
                    error_message=str(e),
                ),
                events=all_events,
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )


class SendOTPChallengeHandler(CommandHandler[OTPChallengeResult]):
    """Handle sending OTP challenges (email/SMS)."""
    
    def __init__(
        self,
        otp_service: OTPServicePort,
        session_repo: AuthSessionRepository,
    ):
        super().__init__()
        self.otp_service = otp_service
        self.session_repo = session_repo
    
    async def handle(self, command: SendOTPChallenge) -> CommandResponse[OTPChallengeResult]:
        session = await self.session_repo.get(command.session_id)
        if not session or not session.user_claims:
            return CommandResponse(
                result=OTPChallengeResult(
                    success=False,
                    message="Session not found",
                    method=command.method,
                    session_id=command.session_id,
                ),
                events=[],
                correlation_id=command.correlation_id,
                causation_id=command.command_id,
            )
        
        try:
            message = await self.otp_service.send_challenge(
                claims=session.user_claims,
                method=command.method,
            )
            
            return CommandResponse(
                result=OTPChallengeResult(
                    success=True,
                    message=message,
                    method=command.method,
                    session_id=session.id,
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
                    session_id=session.id,
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
        session_repo: AuthSessionRepository,
    ):
        super().__init__()
        self.idp = idp
        self.session_repo = session_repo
    
    async def handle(self, command: Logout) -> CommandResponse[LogoutResult]:
        all_events: List[Any] = []
        
        try:
            await self.idp.logout(command.refresh_token)
            
            if command.session_id:
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
