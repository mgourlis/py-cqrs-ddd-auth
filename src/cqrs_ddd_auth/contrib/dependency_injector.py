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
    RevokeSessionHandler,
    RevokeAllSessionsHandler,
    SetupTOTPHandler,
    ConfirmTOTPSetupHandler,
    # Step-up auth / saga command handlers
    GrantTemporaryElevationHandler,
    RevokeElevationHandler,
    ResumeSensitiveOperationHandler,
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
from cqrs_ddd_auth.infrastructure.adapters.otp import (
    TOTPService,
    EmailOTPService,
    SMSOTPService,
    CompositeOTPService,
)
from cqrs_ddd_auth.infrastructure.adapters.sqlalchemy_storage import (
    SQLAlchemySessionAdapter,
    SQLAlchemyOTPChallengeAdapter,
    SQLAlchemyTOTPSecretAdapter,
)
from cqrs_ddd_auth.infrastructure.adapters.elevation import RedisElevationStore
from cqrs_ddd_auth.event_store import AuthInMemoryEventStore
from cqrs_ddd_auth.undo import AuthUndoService

try:
    from cqrs_ddd_auth.infrastructure.persistence.sqlalchemy_event_store import (
        AuthSQLAlchemyEventStore,
    )

    HAS_SA_STORE = True
except ImportError:
    HAS_SA_STORE = False
    AuthSQLAlchemyEventStore = None


class AuthContainer(ToolkitContainer):
    """
    IoC Container for authentication services.

    External dependencies (can be overridden by host app):

    Required:
    - identity_provider: IdentityProviderPort implementation (default: KeycloakAdapter)
    - idp_admin: IdentityProviderAdminPort implementation (default: KeycloakAdminAdapter)
    - session_repo: AuthSessionPort implementation (default: InMemorySessionAdapter)

    Optional:
    - totp_secret_repo: TOTPSecretRepository implementation (default: InMemoryTOTPSecretAdapter)
    - otp_challenge_repo: OTPChallengeRepository implementation (default: InMemoryOTPChallengeAdapter)
    - email_sender: EmailSenderPort implementation (default: None)
    - sms_sender: SMSSenderPort implementation (default: None)
    - elevation_store: Cache/DB for step-up auth elevation grants (default: None)
    - operation_store: Store for suspended operations (default: None)
    - abac_authorization: ABACAuthorizationPort for type-level permissions (default: None)

    Config requirements (under config.keycloak.*):
    - server_url: Keycloak server URL
    - realm: Keycloak realm name
    - client_id: OAuth client ID
    - client_secret: OAuth client secret
    - admin_client_id: Admin client ID (for user management)
    - admin_client_secret: Admin client secret

    Config requirements (under config.otp.*):
    - issuer_name: TOTP issuer name (e.g., "MyApp")
    - valid_window: TOTP validation window (default: 1)
    - token_length: OTP code length (default: 6)
    - expiration_seconds: OTP expiration time (default: 120)
    - app_name: App name for OTP messages

    Usage:
        from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer

        class AppContainer(AuthContainer):
            # Override with production adapters
            session_repo = providers.Singleton(
                SQLAlchemySessionAdapter,
                session_factory=my_session_factory
            )

        container = AppContainer()
        container.config.from_dict({
            "keycloak": {...},
            "otp": {"issuer_name": "MyApp", ...}
        })

        # Register handlers with mediator
        for cmd, handler in container.get_all_command_handlers().items():
            mediator.register(cmd, handler())
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
        "cqrs_ddd_auth.infrastructure.adapters.keycloak.KeycloakAdapter",
        config=providers.Factory(
            "cqrs_ddd_auth.infrastructure.adapters.keycloak.KeycloakConfig",
            server_url=config.keycloak.server_url,
            realm=config.keycloak.realm,
            client_id=config.keycloak.client_id,
            client_secret=config.keycloak.client_secret,
            username_claim=config.keycloak.username_claim.as_default(
                "preferred_username"
            ),
            email_claim=config.keycloak.email_claim.as_default("email"),
            groups_claim=config.keycloak.groups_claim.as_default("groups"),
            verify=config.keycloak.verify.as_default(True),
            merge_groups_as_roles=config.keycloak.merge_groups_as_roles.as_default(
                True
            ),
            group_path_strategy=config.keycloak.group_path_strategy.as_default(
                "full_path"
            ),
            group_prefix=config.keycloak.group_prefix.as_default(""),
            tenant_id_claim=config.keycloak.tenant_id_claim.as_default("tenant_id"),
            use_realm_as_tenant=config.keycloak.use_realm_as_tenant.as_default(False),
            phone_number_claim=config.keycloak.phone_number_claim.as_default(
                "phone_number"
            ),
        ),
    )

    # Required for user management - defaults to Keycloak Admin if config is present
    # Note: admin_client_id and admin_client_secret should be provided in config
    # if they differ from regular client credentials
    idp_admin = providers.Singleton(
        "cqrs_ddd_auth.infrastructure.adapters.keycloak_admin.KeycloakAdminAdapter",
        config=providers.Factory(
            "cqrs_ddd_auth.infrastructure.adapters.keycloak_admin.KeycloakAdminConfig",
            server_url=config.keycloak.server_url,
            realm=config.keycloak.realm,
            client_id=config.keycloak.admin_client_id,
            client_secret=config.keycloak.admin_client_secret,
            verify=config.keycloak.verify.as_default(True),
        ),
    )

    # Required - defaults to In-Memory
    session_repo = providers.Singleton(
        "cqrs_ddd_auth.infrastructure.adapters.session.InMemorySessionAdapter"
    )

    # Optional - defaults to In-Memory
    totp_secret_repo = providers.Singleton(
        "cqrs_ddd_auth.infrastructure.adapters.otp_storage.InMemoryTOTPSecretAdapter"
    )

    # Optional - defaults to In-Memory
    otp_challenge_repo = providers.Singleton(
        "cqrs_ddd_auth.infrastructure.adapters.otp_storage.InMemoryOTPChallengeAdapter"
    )

    # Optional - must be provided by app if needed
    email_sender = providers.Dependency(default=None)
    sms_sender = providers.Dependency(default=None)

    # Optional - for step-up auth / saga handlers
    elevation_store = providers.Dependency(default=None)
    operation_store = providers.Dependency(default=None)

    # Optional - for ABAC authorization queries
    abac_authorization = providers.Dependency(default=None)

    # ═══════════════════════════════════════════════════════════════
    # TOOLKIT OVERRIDES (Identity-Aware)
    # ═══════════════════════════════════════════════════════════════

    event_store = providers.Singleton(AuthInMemoryEventStore)

    undo_service = providers.Singleton(
        AuthUndoService,
        event_store=event_store,
        executor_registry=ToolkitContainer.undo_registry,
        cache_service=ToolkitContainer.cache_service,
    )

    # ═══════════════════════════════════════════════════════════════
    # OTP SERVICES
    # ═══════════════════════════════════════════════════════════════

    # OTP config - host app must provide these in config.otp.*
    # Defaults: issuer_name="MyApp", valid_window=1, token_length=6,
    # expiration_seconds=120, app_name="MyApp"

    totp_service = providers.Singleton(
        TOTPService,
        secret_repository=totp_secret_repo,
        issuer_name=config.otp.issuer_name,
        valid_window=config.otp.valid_window,
    )

    email_otp_service = providers.Singleton(
        EmailOTPService,
        otp_repository=otp_challenge_repo,
        email_sender=email_sender,
        token_length=config.otp.token_length,
        expiration_seconds=config.otp.expiration_seconds,
        app_name=config.otp.app_name,
    )

    sms_otp_service = providers.Singleton(
        SMSOTPService,
        otp_repository=otp_challenge_repo,
        sms_sender=sms_sender,
        token_length=config.otp.token_length,
        expiration_seconds=config.otp.expiration_seconds,
        app_name=config.otp.app_name,
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
        idp=identity_provider,
        idp_admin=idp_admin,
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

    revoke_session_handler = providers.Factory(
        RevokeSessionHandler,
        session_repo=session_repo,
    )

    revoke_all_sessions_handler = providers.Factory(
        RevokeAllSessionsHandler,
        session_repo=session_repo,
    )

    setup_totp_handler = providers.Factory(
        SetupTOTPHandler,
        issuer_name=config.otp.issuer_name,
    )

    confirm_totp_handler = providers.Factory(
        ConfirmTOTPSetupHandler,
        totp_repo=totp_secret_repo,
    )

    # ═══════════════════════════════════════════════════════════════
    # STEP-UP AUTH / SAGA COMMAND HANDLERS
    # ═══════════════════════════════════════════════════════════════

    grant_temporary_elevation_handler = providers.Factory(
        GrantTemporaryElevationHandler,
        elevation_store=elevation_store,
    )

    revoke_elevation_handler = providers.Factory(
        RevokeElevationHandler,
        elevation_store=elevation_store,
    )

    resume_sensitive_operation_handler = providers.Factory(
        ResumeSensitiveOperationHandler,
        operation_store=operation_store,
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
    # AUTH QUERY HANDLERS
    # ═══════════════════════════════════════════════════════════════

    get_user_info_handler = providers.Factory(
        GetUserInfoHandler,
        idp=identity_provider,
        totp_repo=totp_secret_repo,
    )

    get_available_otp_methods_handler = providers.Factory(
        GetAvailableOTPMethodsHandler,
        idp=identity_provider,
        otp_service=otp_service,
        totp_repo=totp_secret_repo,
    )

    list_active_sessions_handler = providers.Factory(
        ListActiveSessionsHandler,
        session_repo=session_repo,
    )

    get_session_details_handler = providers.Factory(
        GetSessionDetailsHandler,
        session_repo=session_repo,
    )

    check_totp_enabled_handler = providers.Factory(
        CheckTOTPEnabledHandler,
        totp_repo=totp_secret_repo,
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

    get_type_level_permissions_handler = providers.Factory(
        GetTypeLevelPermissionsHandler,
        abac=abac_authorization,
    )

    # ═══════════════════════════════════════════════════════════════
    # HANDLER REGISTRATION HELPERS
    # ═══════════════════════════════════════════════════════════════

    def get_all_command_handlers(self) -> dict:
        """
        Return a mapping of Command classes to their handlers.

        Useful for registering all handlers with a Mediator.

        Usage:
            container = AuthContainer()
            for cmd_class, handler_provider in container.get_all_command_handlers().items():
                mediator.register(cmd_class, handler_provider())
        """
        from cqrs_ddd_auth.application.commands import (
            AuthenticateWithCredentials,
            ValidateOTP,
            SendOTPChallenge,
            RefreshTokens,
            Logout,
            RevokeSession,
            RevokeAllSessions,
            SetupTOTP,
            ConfirmTOTPSetup,
            GrantTemporaryElevation,
            RevokeElevation,
            ResumeSensitiveOperation,
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

        return {
            AuthenticateWithCredentials: self.authenticate_handler,
            ValidateOTP: self.validate_otp_handler,
            SendOTPChallenge: self.send_otp_challenge_handler,
            RefreshTokens: self.refresh_tokens_handler,
            Logout: self.logout_handler,
            RevokeSession: self.revoke_session_handler,
            RevokeAllSessions: self.revoke_all_sessions_handler,
            SetupTOTP: self.setup_totp_handler,
            ConfirmTOTPSetup: self.confirm_totp_handler,
            GrantTemporaryElevation: self.grant_temporary_elevation_handler,
            RevokeElevation: self.revoke_elevation_handler,
            ResumeSensitiveOperation: self.resume_sensitive_operation_handler,
            CreateUser: self.create_user_handler,
            UpdateUser: self.update_user_handler,
            DeleteUser: self.delete_user_handler,
            SetUserPassword: self.set_user_password_handler,
            SendPasswordReset: self.send_password_reset_handler,
            SendVerifyEmail: self.send_verify_email_handler,
            AssignRoles: self.assign_roles_handler,
            RemoveRoles: self.remove_roles_handler,
            AddToGroups: self.add_to_groups_handler,
            RemoveFromGroups: self.remove_from_groups_handler,
        }

    def get_all_query_handlers(self) -> dict:
        """
        Return a mapping of Query classes to their handlers.

        Useful for registering all handlers with a Mediator.
        """
        from cqrs_ddd_auth.application.queries import (
            GetUserInfo,
            GetAvailableOTPMethods,
            ListActiveSessions,
            GetSessionDetails,
            CheckTOTPEnabled,
            GetUser,
            GetUserByUsername,
            GetUserByEmail,
            ListUsers,
            GetUserRoles,
            GetUserGroups,
            GetTypeLevelPermissions,
        )

        return {
            GetUserInfo: self.get_user_info_handler,
            GetAvailableOTPMethods: self.get_available_otp_methods_handler,
            ListActiveSessions: self.list_active_sessions_handler,
            GetSessionDetails: self.get_session_details_handler,
            CheckTOTPEnabled: self.check_totp_enabled_handler,
            GetUser: self.get_user_handler,
            GetUserByUsername: self.get_user_by_username_handler,
            GetUserByEmail: self.get_user_by_email_handler,
            ListUsers: self.list_users_handler,
            GetUserRoles: self.get_user_roles_handler,
            GetUserGroups: self.get_user_groups_handler,
            GetTypeLevelPermissions: self.get_type_level_permissions_handler,
        }


class SQLAlchemyAuthContainer(containers.DeclarativeContainer):
    """
    Mixin Container for SQLAlchemy-based persistence.

    Usage:
        class AppContainer(SQLAlchemyAuthContainer, AuthContainer):
            session_factory = providers.Dependency()
    """

    # Dependencies that must be provided by the app
    session_factory = providers.Dependency()

    # Overrides
    session_repo = providers.Singleton(
        SQLAlchemySessionAdapter,
        session_factory=session_factory,
    )

    otp_challenge_repo = providers.Singleton(
        SQLAlchemyOTPChallengeAdapter,
        session_factory=session_factory,
    )

    totp_secret_repo = providers.Singleton(
        SQLAlchemyTOTPSecretAdapter,
        session_factory=session_factory,
    )

    if HAS_SA_STORE:
        event_store = providers.Singleton(
            AuthSQLAlchemyEventStore,
            uow_factory=ToolkitContainer.uow_factory,
        )


class RedisAuthContainer(containers.DeclarativeContainer):
    """
    Mixin Container for Redis-based components.

    Usage:
        class AppContainer(RedisAuthContainer, AuthContainer):
            redis_client = providers.Dependency()
    """

    # Dependencies
    redis_client = providers.Dependency()

    # Overrides
    elevation_store = providers.Singleton(
        RedisElevationStore,
        redis_client=redis_client,
    )
