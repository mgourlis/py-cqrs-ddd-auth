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

try:
    from cqrs_ddd.contrib.dependency_injector import Container as ToolkitContainer
except ImportError:
    class ToolkitContainer(containers.DeclarativeContainer):
        """Fallback base container when toolkit is not available."""
        pass

from cqrs_ddd_auth.application.handlers import (
    # Auth command handlers
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
    # User management query handlers
    GetUserHandler,
    GetUserByUsernameHandler,
    GetUserByEmailHandler,
    ListUsersHandler,
    GetUserRolesHandler,
    GetUserGroupsHandler,
)
from cqrs_ddd_auth.adapters.otp import (
    TOTPService,
    EmailOTPService,
    SMSOTPService,
    CompositeOTPService,
)


class AuthContainer(ToolkitContainer):
    """
    IoC Container for authentication services.
    
    External dependencies (must be provided by host app):
    - identity_provider: IdentityProviderPort implementation
    - idp_admin: IdentityProviderAdminPort implementation (for user management)
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
    # DEFAULT ADAPTERS (can be overridden)
    # ═══════════════════════════════════════════════════════════════
    
    # Required - defaults to Keycloak if config is present
    identity_provider = providers.Singleton(
        "cqrs_ddd_auth.adapters.keycloak.KeycloakAdapter",
        config=providers.Factory(
            "cqrs_ddd_auth.adapters.keycloak.KeycloakConfig",
            server_url=config.keycloak.server_url,
            realm=config.keycloak.realm,
            client_id=config.keycloak.client_id,
            client_secret=config.keycloak.client_secret,
        ),
    )
    
    # Required for user management - defaults to Keycloak Admin if config is present
    idp_admin = providers.Singleton(
        "cqrs_ddd_auth.adapters.keycloak_admin.KeycloakAdminAdapter",
        config=providers.Factory(
            "cqrs_ddd_auth.adapters.keycloak_admin.KeycloakAdminConfig",
            server_url=config.keycloak.server_url,
            realm=config.keycloak.realm,
            client_id=config.keycloak.admin_client_id | config.keycloak.client_id,
            client_secret=config.keycloak.admin_client_secret | config.keycloak.client_secret,
        ),
    )
    
    # Required - defaults to In-Memory
    session_repo = providers.Singleton(
        "cqrs_ddd_auth.adapters.repositories.InMemorySessionRepository"
    )
    
    # Optional - defaults to In-Memory
    totp_secret_repo = providers.Singleton(
        "cqrs_ddd_auth.adapters.repositories.InMemoryTOTPSecretRepository"
    )
    
    # Optional - defaults to In-Memory
    otp_challenge_repo = providers.Singleton(
        "cqrs_ddd_auth.adapters.repositories.InMemoryOTPChallengeRepository"
    )
    
    # Optional - must be provided by app if needed
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
    
    # ═══════════════════════════════════════════════════════════════
    # USER MANAGEMENT COMMAND HANDLERS
    # ═══════════════════════════════════════════════════════════════
    
    create_user_handler = providers.Factory(
        CreateUserHandler,
        idp_admin=idp_admin,
    )
    
    update_user_handler = providers.Factory(
        UpdateUserHandler,
        idp_admin=idp_admin,
    )
    
    delete_user_handler = providers.Factory(
        DeleteUserHandler,
        idp_admin=idp_admin,
    )
    
    set_user_password_handler = providers.Factory(
        SetUserPasswordHandler,
        idp_admin=idp_admin,
    )
    
    send_password_reset_handler = providers.Factory(
        SendPasswordResetHandler,
        idp_admin=idp_admin,
    )
    
    send_verify_email_handler = providers.Factory(
        SendVerifyEmailHandler,
        idp_admin=idp_admin,
    )
    
    assign_roles_handler = providers.Factory(
        AssignRolesHandler,
        idp_admin=idp_admin,
    )
    
    remove_roles_handler = providers.Factory(
        RemoveRolesHandler,
        idp_admin=idp_admin,
    )
    
    add_to_groups_handler = providers.Factory(
        AddToGroupsHandler,
        idp_admin=idp_admin,
    )
    
    remove_from_groups_handler = providers.Factory(
        RemoveFromGroupsHandler,
        idp_admin=idp_admin,
    )
    
    # ═══════════════════════════════════════════════════════════════
    # USER MANAGEMENT QUERY HANDLERS
    # ═══════════════════════════════════════════════════════════════
    
    get_user_handler = providers.Factory(
        GetUserHandler,
        idp_admin=idp_admin,
    )
    
    get_user_by_username_handler = providers.Factory(
        GetUserByUsernameHandler,
        idp_admin=idp_admin,
    )
    
    get_user_by_email_handler = providers.Factory(
        GetUserByEmailHandler,
        idp_admin=idp_admin,
    )
    
    list_users_handler = providers.Factory(
        ListUsersHandler,
        idp_admin=idp_admin,
    )
    
    get_user_roles_handler = providers.Factory(
        GetUserRolesHandler,
        idp_admin=idp_admin,
    )
    
    get_user_groups_handler = providers.Factory(
        GetUserGroupsHandler,
        idp_admin=idp_admin,
    )
