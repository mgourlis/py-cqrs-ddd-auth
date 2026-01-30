"""
Dependency Injector integration for cqrs-ddd-auth.

Provides an optional IoC Container with pre-configured auth services.
Host applications can extend this container or use it directly.

Usage:
    from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
    
    class AppContainer(AuthContainer):
        # Provide implementations for required dependencies
        identity_provider = providers.Singleton(KeycloakAdapter, ...)
        session_repo = providers.Singleton(SQLAlchemySessionRepo, ...)
"""

from dependency_injector import containers, providers

from cqrs_ddd_auth.application.handlers import (
    AuthenticateWithCredentialsHandler,
    ValidateOTPHandler,
    SendOTPChallengeHandler,
    RefreshTokensHandler,
    LogoutHandler,
    SetupTOTPHandler,
    ConfirmTOTPSetupHandler,
)
from cqrs_ddd_auth.adapters.otp import (
    TOTPService,
    EmailOTPService,
    SMSOTPService,
    CompositeOTPService,
)


class AuthContainer(containers.DeclarativeContainer):
    """
    IoC Container for authentication services.
    
    External dependencies (must be provided by host app):
    - identity_provider: IdentityProviderPort implementation
    - session_repo: AuthSessionRepository implementation
    - totp_secret_repo: TOTPSecretRepository implementation (optional)
    - otp_challenge_repo: OTPChallengeRepository implementation (optional)
    - email_sender: EmailSenderPort implementation (optional)
    - sms_sender: SMSSenderPort implementation (optional)
    """
    
    wiring_config = containers.WiringConfiguration(
        modules=[
            "cqrs_ddd_auth.contrib.fastapi",
            "cqrs_ddd_auth.contrib.django",
        ]
    )
    
    config = providers.Configuration()
    
    # ═══════════════════════════════════════════════════════════════
    # EXTERNAL DEPENDENCIES (must be provided by host app)
    # ═══════════════════════════════════════════════════════════════
    
    # Required
    identity_provider = providers.Dependency()
    session_repo = providers.Dependency()
    
    # Optional (required only for specific OTP methods)
    totp_secret_repo = providers.Dependency(default=None)
    otp_challenge_repo = providers.Dependency(default=None)
    email_sender = providers.Dependency(default=None)
    sms_sender = providers.Dependency(default=None)
    
    # ═══════════════════════════════════════════════════════════════
    # OTP SERVICES
    # ═══════════════════════════════════════════════════════════════
    
    totp_service = providers.Singleton(
        TOTPService,
        secret_repository=totp_secret_repo,
        issuer_name=config.otp.issuer_name.as_(str) | "MyApp",
        valid_window=config.otp.valid_window.as_int() | 1,
    )
    
    email_otp_service = providers.Singleton(
        EmailOTPService,
        otp_repository=otp_challenge_repo,
        email_sender=email_sender,
        token_length=config.otp.token_length.as_int() | 6,
        expiration_seconds=config.otp.expiration_seconds.as_int() | 120,
        app_name=config.otp.app_name.as_(str) | "MyApp",
    )
    
    sms_otp_service = providers.Singleton(
        SMSOTPService,
        otp_repository=otp_challenge_repo,
        sms_sender=sms_sender,
        token_length=config.otp.token_length.as_int() | 6,
        expiration_seconds=config.otp.expiration_seconds.as_int() | 120,
        app_name=config.otp.app_name.as_(str) | "MyApp",
    )
    
    # Composite service that delegates to the appropriate OTP method
    otp_service = providers.Singleton(
        CompositeOTPService,
        totp_service=totp_service,
        email_service=email_otp_service,
        sms_service=sms_otp_service,
    )
    
    # ═══════════════════════════════════════════════════════════════
    # COMMAND HANDLERS
    # ═══════════════════════════════════════════════════════════════
    
    authenticate_handler = providers.Factory(
        AuthenticateWithCredentialsHandler,
        idp=identity_provider,
        otp_service=otp_service,
        session_repo=session_repo,
    )
    
    validate_otp_handler = providers.Factory(
        ValidateOTPHandler,
        otp_service=otp_service,
        session_repo=session_repo,
        idp=identity_provider,
    )
    
    send_otp_challenge_handler = providers.Factory(
        SendOTPChallengeHandler,
        otp_service=otp_service,
        session_repo=session_repo,
    )
    
    refresh_tokens_handler = providers.Factory(
        RefreshTokensHandler,
        idp=identity_provider,
    )
    
    logout_handler = providers.Factory(
        LogoutHandler,
        idp=identity_provider,
        session_repo=session_repo,
    )
    
    setup_totp_handler = providers.Factory(
        SetupTOTPHandler,
        issuer_name=config.otp.issuer_name.as_(str) | "MyApp",
    )
    
    confirm_totp_handler = providers.Factory(
        ConfirmTOTPSetupHandler,
        totp_repo=totp_secret_repo,
    )
