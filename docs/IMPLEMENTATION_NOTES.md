# Implementation Notes: py-cqrs-ddd-auth

This document outlines the detailed implementation roadmap for the `py-cqrs-ddd-auth` library, based on the `authentication_implementation_proposal.md`.

---

## Step 1: [DONE] Project Scaffolding

Create the core project structure following the `py-cqrs-ddd-toolkit` pattern.

**Files and Structure:**
```
py-cqrs-ddd-auth/
├── pyproject.toml              # Build config + dependencies
├── README.md
├── LICENSE
├── src/
│   └── cqrs_ddd_auth/
│       ├── __init__.py         # Package exports
│       ├── identity.py         # Identity Protocol + AnonymousIdentity + SystemIdentity
│       ├── context.py          # RequestContext + ContextVars
│       ├── domain/             # Domain Layer
│       │   └── __init__.py
│       ├── application/        # Application Layer (Commands/Queries/Handlers)
│       │   └── __init__.py
│       ├── ports/              # Abstract ports (Protocols)
│       │   └── __init__.py
│       ├── adapters/           # Concrete implementations (Keycloak, ABAC, etc.)
│       │   └── __init__.py
│       └── contrib/            # Framework-specific adapters (FastAPI, Django)
│           └── __init__.py
└── tests/
    ├── __init__.py
    └── conftest.py
```

**Dependencies:**
- Core: `py-cqrs-ddd-toolkit` (peer dependency)
- Optional: `python-keycloak`, `python-jose[cryptography]`, `httpx`, `pydantic`, `pyotp`

---

## Step 2: [DONE] Identity Protocol & Context

Implement the core identity abstractions from Section 2 of the proposal.

**Files to create:**
1. `src/cqrs_ddd_auth/identity.py`
   - `Identity` Protocol
   - `AnonymousIdentity` class
   - `SystemIdentity` class
   - `AuthenticatedIdentity` dataclass

2. `src/cqrs_ddd_auth/context.py`
   - `RequestContext` dataclass
   - `request_context` ContextVar
   - `get_identity()` helper
   - `get_access_token()` helper

**Key Design Decisions:**
- Identity is a **Protocol**, not a base class—host apps can use their own implementations
- Context uses `contextvars` for request-scoped identity propagation
- Access token is stored in context for downstream ABAC calls

---

## Step 3: [DONE] Domain Layer - Value Objects & Aggregates

Implement the core domain model from Section 3 of the proposal.

**Files to create:**
1. `src/cqrs_ddd_auth/domain/value_objects.py`
   - `Credentials` (frozen dataclass)
   - `TOTPSecret` (pyotp-based with verify_code/generate methods)
   - `UserClaims` (decoded JWT representation)
   - `OTPChallenge` (for email/SMS challenges)

2. `src/cqrs_ddd_auth/domain/aggregates.py`
   - `AuthSessionStatus` enum
   - `AuthSession` AggregateRoot
     - Factory method `create()`
     - State transitions: `credentials_validated()`, `otp_validated()`, `fail()`, `revoke()`

3. `src/cqrs_ddd_auth/domain/events.py`
   - `AuthSessionCreated`, `OTPRequired`, `AuthenticationSucceeded`, `AuthenticationFailed`, `SessionRevoked`

---

## Step 4: [DONE] Ports (Infrastructure Interfaces)

Define the abstract protocols that infrastructure adapters must implement (Section 5.1).

**Files to create:**
1. `src/cqrs_ddd_auth/ports/identity_provider.py`
   - `IdentityProviderPort` Protocol
     - `authenticate(username, password) -> TokenResponse`
     - `refresh(refresh_token) -> TokenResponse`
     - `decode_token(access_token) -> UserClaims`
     - `logout(refresh_token) -> None`

2. `src/cqrs_ddd_auth/ports/otp.py`
   - `OTPServicePort` Protocol
     - `is_required_for_user(claims) -> bool`
     - `get_available_methods(claims) -> list[str]`
     - `send_challenge(claims, method) -> str`
     - `validate(claims, method, code) -> bool`

3. `src/cqrs_ddd_auth/ports/authorization.py`
   - `ABACAuthorizationPort` Protocol
     - `check_access(token, action, resource_type, resource_ids) -> list[str]`
     - `get_permitted_actions(token, resource_type, resource_ids) -> dict`

4. `src/cqrs_ddd_auth/ports/token_issuer.py`
   - `TokenIssuerPort` Protocol
     - `issue(user_claims, session_id, token_response) -> TokenPair`

---

## Step 5: [DONE] Application Layer - Command & Query Definitions

Implement the primary authentication commands and results (Section 4.1).

**Files to create:**
1. `src/cqrs_ddd_auth/application/commands.py`
   - `AuthenticateWithCredentials`: Supports stateless/stateful modes and inline OTP.
   - `ValidateOTP`: For stateful multi-step flows.
   - `RefreshTokens`: Token refresh via IdP.
   - `Logout`: Identity and session termination.

2. `src/cqrs_ddd_auth/application/results.py`
   - `AuthResult`: DTO for success/fail/otp_required with metadata.
   - `TokenPair`: DTO for access/refresh tokens.

3. `src/cqrs_ddd_auth/application/handlers.py`
   - `AuthenticateWithCredentialsHandler`: Orcherstrates the dual-mode flow.

---

## Step 6: [DONE] Core Authentication Saga (Step-Up Auth)

Implement saga for multi-step step-up authentication (Section 4.3).

**Files to create:**
1. `src/cqrs_ddd_auth/application/sagas.py`
   - `StepUpAuthenticationSaga`: Handles temporary elevation for sensitive operations.
   - Steps: `on_sensitive_operation_requested`, `on_otp_validated`, `on_operation_completed`.
   - Compensation: `revoke_elevation` on failure.

---

## Step 7: [DONE] OTP Adapters & Dependency Injection

Implement concrete OTP service implementations and setup IoC wiring.

**Files to create:**
1. `src/cqrs_ddd_auth/adapters/otp.py`
   - `TOTPService`: Authenticator app support using `pyotp`.
   - `EmailOTPService`: Delivery via `EmailSenderPort`.
   - `SMSOTPService`: Delivery via `SMSSenderPort`.
   - `CompositeOTPService`: Delegation pattern based on requested method.

2. `src/cqrs_ddd_auth/contrib/dependency_injector.py`
   - `AuthContainer`: Pre-configured container for wiring all auth components.

---

## Step 8: [DONE] In-Memory Repositories

Create in-memory implementations for development and testing.

**Files to create:**
1. `src/cqrs_ddd_auth/adapters/repositories.py`
   - `InMemorySessionRepository`: Stores `AuthSession` aggregates.
   - `InMemoryTOTPSecretRepository`: Stores persistent 2FA secrets.
   - `InMemoryOTPChallengeRepository`: Stores transient email/SMS codes.

---

## Step 9: [DONE] Keycloak Adapter

Implement the `IdentityProviderPort` with Keycloak as the backend (Section 5.2).

**Files to create:**
1. `src/cqrs_ddd_auth/adapters/keycloak.py`
   - `KeycloakAdapter`: Uses `python-keycloak` for direct grant and token management.
   - `decode_token`: Validates signatures and maps claims to `UserClaims`.

---

## Step 10: [DONE] Framework Integrations

Implement thin bridges for FastAPI and Django (Section 7).

**Files to create:**
1. `src/cqrs_ddd_auth/contrib/fastapi.py`
   - `get_identity`: Dependency for endpoint protection.
   - Middleware: Context setup and token extraction.

2. `src/cqrs_ddd_auth/contrib/django.py`
   - `AuthenticationMiddleware`: Context propagation for Django/DRF.
   - Decorators: `@require_authenticated`, `@require_groups`.

---

## Step 11: [DONE] TOTP Setup Handlers

Implement handlers for user 2FA enrollment.

**Files to modify:**
1. `src/cqrs_ddd_auth/application/commands.py`: Add `SetupTOTP`, `ConfirmTOTPSetup`.
2. `src/cqrs_ddd_auth/application/handlers.py`: Add `SetupTOTPHandler`, `ConfirmTOTPSetupHandler`.

**Logic:**
- `SetupTOTP`: Generates a secret and provisioning URI (QR code).
- `ConfirmTOTPSetup`: Validates the first code before persisting the secret.

---

## Step 11: [DONE] Queries & Query Handlers

Implement read-side queries for user info and session management.

**Files created/modified:**
1. `src/cqrs_ddd_auth/application/queries.py`
   - `GetUserInfo` Query - Get user profile from access token
   - `GetAvailableOTPMethods` Query - List available 2FA methods
   - `ListActiveSessions` Query - For session management UI
   - `GetSessionDetails` Query - Get specific session info
   - `CheckTOTPEnabled` Query - Check if user has TOTP configured

2. `src/cqrs_ddd_auth/application/results.py`
   - `UserInfoResult` - User profile with claims and 2FA status
   - `AvailableOTPMethodsResult` - List of OTP methods with status
   - `OTPMethodInfo` - Individual OTP method info
   - `ListSessionsResult` - List of sessions
   - `SessionInfo` - Individual session details
   - `TOTPStatusResult` - TOTP enabled status

3. `src/cqrs_ddd_auth/application/handlers.py`
   - `GetUserInfoHandler` - Returns user claims + TOTP status
   - `GetAvailableOTPMethodsHandler` - Returns available 2FA methods
   - `ListActiveSessionsHandler` - Lists user's active sessions
   - `GetSessionDetailsHandler` - Returns session details
   - `CheckTOTPEnabledHandler` - Returns TOTP enabled status

---

## Step 12: [DONE] ABAC Authorization Port

Implement the ABAC SDK client adapter for authorization.

**Files created:**
1. `src/cqrs_ddd_auth/adapters/abac.py`
   - `ABACClientConfig` - Configuration for ABAC client
     - `mode`: "http" or "db" (for different deployment scenarios)
     - `base_url`: API endpoint for HTTP mode
     - `database_url`: Connection string for DB mode
     - `realm`: ABAC realm name
     - Caching options for resource types and actions
   - `StatefulABACAdapter` implements `ABACAuthorizationPort`
     - `check_access()` - Check if user can access specific resources
     - `get_permitted_actions()` - Get allowed actions per resource
     - `list_resource_types()` - List available resource types (cached)
     - `list_actions()` - List actions for a resource type (cached)
     - `get_type_level_permissions()` - Get type-level permissions for UI
     - `get_authorization_conditions()` - Get conditions for single-query auth
     - `sync_from_idp()` - Trigger IdP sync
     - Async context manager support

2. `src/cqrs_ddd_auth/adapters/__init__.py` (updated)
   - Added optional exports for `StatefulABACAdapter`, `ABACClientConfig`
   - Uses try/except for optional `stateful-abac-sdk` dependency

**Integration Notes:**
- Uses `stateful-abac-sdk` package (optional dependency)
- Passes `access_token` via `set_token()` for role extraction
- Supports dual mode:
  - HTTP mode: REST API calls (standard deployment)
  - DB mode: Direct SQL (10-100x faster for co-located services)
- Caches resource types and actions for performance

**Usage Example:**
```python
from cqrs_ddd_auth.adapters import StatefulABACAdapter, ABACClientConfig

# HTTP mode (standard deployment)
config = ABACClientConfig(
    mode="http",
    base_url="http://abac-engine:8000/api/v1",
    realm="my-realm",
)
adapter = StatefulABACAdapter(config)

# Check access
async with adapter:
    adapter.set_token(access_token)
    
    # Check specific resource access
    allowed_ids = await adapter.check_access(
        access_token=token,
        action="read",
        resource_type="document",
        resource_ids=["doc-1", "doc-2"],
    )
    
    # Get type-level permissions for UI
    permissions = await adapter.get_type_level_permissions(
        access_token=token,
        resource_types=["document", "user", "report"],
    )
    # {"document": ["read", "create"], "user": ["read"], "report": []}
    
    # Get authorization conditions for single-query auth
    conditions = await adapter.get_authorization_conditions(
        access_token=token,
        resource_type="document",
        action="read",
    )
    if conditions.granted_all:
        # User has blanket access
        pass
    elif conditions.denied_all:
        # User has no access
        raise PermissionDenied()
    else:
        # Use conditions.conditions_dsl to filter query
        pass
```

---

## Step 13: AuthorizationMiddleware (CQRS)

Implement CQRS middleware for fine-grained authorization checks.

**Files to create:**
1. `src/cqrs_ddd_auth/middleware/authorization.py`
   - `AuthorizationMiddleware` - Pre/post execution authorization
     - Pre-check: Validate before handler runs
     - Post-filter: Filter results based on permissions
   - `PermittedActionsMiddleware` - Enrich results with allowed actions

**Usage:**
```python
@middleware.authorize(
    resource_type="element",
    required_permissions=["view"],
)
class GetElementHandler(QueryHandler):
    ...
```

---

## Step 14: [DONE] Role Unification (Groups as Roles)

Implement unified role model merging IdP groups and roles.

**Architecture Decision:** Keep domain generic, move IdP-specific logic to adapters.

**Files modified:**

1. `src/cqrs_ddd_auth/domain/value_objects.py` (Generic domain layer)
   - `RoleSource` enum - Generic sources: `IDP_ROLE`, `IDP_CLIENT_ROLE`, `DERIVED`, `CUSTOM`
   - `AuthRole` ValueObject - Simple role with name, source, and attributes
   - `UserClaims` - Pure data container with role checking methods:
     - `role_names`, `idp_roles`, `client_roles`, `derived_roles` properties
     - `has_role()`, `has_any_role()`, `has_all_roles()` methods

2. `src/cqrs_ddd_auth/adapters/keycloak.py` (Keycloak-specific)
   - `GroupPathStrategy` enum - Keycloak group path handling:
     - `FULL_PATH`: `/web/admin/editor` → `"web/admin/editor"`
     - `LAST_SEGMENT`: `/web/admin/editor` → `"editor"`
     - `ALL_SEGMENTS`: `/web/admin/editor` → `["web", "admin", "editor"]`
   - `KeycloakConfig` enhanced with:
     - `merge_groups_as_roles: bool = True`
     - `group_path_strategy: GroupPathStrategy`
     - `group_prefix: str`
   - `_payload_to_claims()` - Keycloak-specific token parsing logic
   - `_group_path_to_roles()` - Group path conversion

3. Exports:
   - `domain/__init__.py` - Exports `RoleSource`, `AuthRole`
   - `adapters/__init__.py` - Exports `GroupPathStrategy` with Keycloak adapter

**Usage Examples:**
```python
# Given Keycloak groups: ["/web/admin/editor", "/api/reader"]

# Strategy: FULL_PATH (default) - precise, hierarchical
# roles = ["web/admin/editor", "api/reader"]
claims.has_role("web/admin/editor")  # ✓
claims.has_role("editor")             # ✗

# Strategy: LAST_SEGMENT - simple, flat
# roles = ["editor", "reader"]
claims.has_role("editor")  # ✓
claims.has_role("web/admin/editor")  # ✗

# Strategy: ALL_SEGMENTS - flexible, multiple roles per group
# roles = ["web", "admin", "editor", "api", "reader"]
claims.has_role("admin")   # ✓
claims.has_role("editor")  # ✓
claims.has_role("web")     # ✓
```

---

## Step 15: Authentication Saga (Step-Up Auth)

Implement saga for multi-step step-up authentication.

**Files to create:**
1. `src/cqrs_ddd_auth/application/sagas.py`
   - `StepUpAuthenticationSaga`
     - Triggered by `SensitiveOperationRequested` event
     - Issues OTP challenge
     - Grants temporary elevation on success
     - Revokes on completion or timeout

**Events:**
- `SensitiveOperationRequested`
- `OTPChallengeValidated`
- `TemporaryElevationGranted`
- `TemporaryElevationRevoked`

---

## Step 16: Communication Ports (Email/SMS)

Define ports for OTP delivery mechanisms.

**Files to create/modify:**
1. `src/cqrs_ddd_auth/ports/communication.py`
   - `EmailSenderPort` Protocol - Send verification emails
   - `SMSSenderPort` Protocol - Send verification SMS

2. `src/cqrs_ddd_auth/adapters/communication.py` (optional)
   - `ConsoleEmailSender` - For development/testing
   - `ConsoleSMSSender` - For development/testing

---

## Step 17: Session Management Commands

Implement commands for session lifecycle management.

**Files to modify:**
1. `src/cqrs_ddd_auth/application/commands.py`
   - `RevokeSession` Command - Terminate specific session
   - `RevokeAllSessions` Command - "Sign out all devices"

2. `src/cqrs_ddd_auth/application/handlers.py`
   - `RevokeSessionHandler`
   - `RevokeAllSessionsHandler`

**Endpoints:**
- `DELETE /auth/sessions/{session_id}`
- `DELETE /auth/sessions`

---

## Step 18: SQLAlchemy Repositories

Implement persistent storage with SQLAlchemy.

**Files to create:**
1. `src/cqrs_ddd_auth/adapters/sqlalchemy.py`
   - `SQLAlchemySessionRepository`
   - `SQLAlchemyTOTPSecretRepository`
   - `SQLAlchemyOTPChallengeRepository`

2. `src/cqrs_ddd_auth/adapters/models.py`
   - `AuthSessionModel` - SQLAlchemy model
   - `TOTPSecretModel` - SQLAlchemy model
   - `OTPChallengeModel` - SQLAlchemy model

---

## Step 19: SendOTPChallenge Command

Implement OTP challenge sending for email/SMS methods.

**Files to create/modify:**
1. `src/cqrs_ddd_auth/application/commands.py`
   - `SendOTPChallenge` Command - Request OTP via email/SMS

2. `src/cqrs_ddd_auth/application/handlers.py`
   - `SendOTPChallengeHandler`
     - Generates challenge code
     - Stores in `OTPChallengeRepository`
     - Sends via `EmailSenderPort` or `SMSSenderPort`

---

## Step 20: PermittedActionsMiddleware

Enrich query results with per-entity permitted actions.

**Files to create:**
1. `src/cqrs_ddd_auth/middleware/permitted_actions.py`
   - `PermittedActionsMiddleware`
     - After query handler runs, fetches permitted actions per entity
     - Attaches `permitted_actions` attribute to each result

**Usage:**
```python
@middleware.permitted_actions(
    result_entities_attr="items",
    resource_type="document",
)
class ListDocumentsHandler(QueryHandler):
    ...
```

---

## Step 21: [DONE] User Management via IdP

Implement ports for user management through the identity provider.

**Files created:**
1. `src/cqrs_ddd_auth/ports/identity_provider_admin.py`
   - `IdentityProviderAdminPort` Protocol
     - `create_user()`, `get_user()`, `get_user_by_username()`, `get_user_by_email()`
     - `update_user()`, `delete_user()`
     - `set_password()`, `send_password_reset()`
     - `assign_roles()`, `remove_roles()`, `get_user_roles()`, `list_roles()`
     - `join_groups()`, `leave_groups()`, `get_user_groups()`, `list_groups()`
     - `list_users()` with filtering and pagination
   - DTOs: `CreateUserData`, `UpdateUserData`, `UserData`, `RoleData`, `GroupData`, `UserFilters`

2. `src/cqrs_ddd_auth/ports/authorization.py` (enhanced)
   - Added `list_actions()` - List available actions from ABAC
   - Added `get_type_level_permissions()` - Get type-level permissions for action checking
   - Added `get_authorization_conditions()` - Get authorization conditions for single-query authorization
   - Added `AuthorizationConditionsResult` dataclass for conditions response

**Note:** Commands for user management are in Step 21c.

---

## Step 21c: [DONE] User Management Commands

Implement commands for user CRUD, password management, role assignment, and group management.

**Files modified:**

1. `src/cqrs_ddd_auth/application/commands.py`
   - `CreateUser` - Create a new user in the IdP
   - `UpdateUser` - Update user attributes
   - `DeleteUser` - Delete a user
   - `SetUserPassword` - Set user password (admin action)
   - `SendPasswordReset` - Trigger password reset email
   - `SendVerifyEmail` - Send email verification
   - `AssignRoles` - Assign roles to a user
   - `RemoveRoles` - Remove roles from a user
   - `AddToGroups` - Add user to groups
   - `RemoveFromGroups` - Remove user from groups

2. `src/cqrs_ddd_auth/application/results.py`
   - `CreateUserResult` - Returns user_id and username
   - `UpdateUserResult` - Returns success and user_id
   - `DeleteUserResult` - Returns success and user_id
   - `SetPasswordResult` - Returns success and user_id
   - `SendPasswordResetResult` - Returns success and user_id
   - `SendVerifyEmailResult` - Returns success and user_id
   - `AssignRolesResult` - Returns success, user_id, roles_assigned
   - `RemoveRolesResult` - Returns success, user_id, roles_removed
   - `AddToGroupsResult` - Returns success, user_id, groups_added
   - `RemoveFromGroupsResult` - Returns success, user_id, groups_removed

3. `src/cqrs_ddd_auth/application/handlers.py`
   - `CreateUserHandler` - Creates user via IdP admin port
   - `UpdateUserHandler` - Updates user via IdP admin port
   - `DeleteUserHandler` - Deletes user via IdP admin port
   - `SetUserPasswordHandler` - Sets password via IdP admin port
   - `SendPasswordResetHandler` - Triggers reset email via IdP
   - `SendVerifyEmailHandler` - Sends verification via IdP
   - `AssignRolesHandler` - Assigns roles via IdP admin port
   - `RemoveRolesHandler` - Removes roles via IdP admin port
   - `AddToGroupsHandler` - Adds to groups via IdP admin port
   - `RemoveFromGroupsHandler` - Removes from groups via IdP admin port

4. `src/cqrs_ddd_auth/application/__init__.py`
   - Updated exports for all new commands, results, and handlers

**Usage Example:**
```python
from cqrs_ddd_auth.application import (
    CreateUser,
    CreateUserHandler,
    AssignRoles,
    AssignRolesHandler,
)

# Create user
handler = CreateUserHandler(idp_admin=keycloak_admin_adapter)
result = await handler.handle(CreateUser(
    username="newuser",
    email="newuser@example.com",
    first_name="New",
    last_name="User",
    temporary_password="Welcome123!",
))
user_id = result.result.user_id

# Assign roles
roles_handler = AssignRolesHandler(idp_admin=keycloak_admin_adapter)
await roles_handler.handle(AssignRoles(
    user_id=user_id,
    role_names=["app-user", "viewer"],
))
```

---

## Step 21b: [DONE] Keycloak Admin Adapter

Implement the Keycloak adapter for `IdentityProviderAdminPort`.

**Files created:**
1. `src/cqrs_ddd_auth/adapters/keycloak_admin.py`
   - `KeycloakAdminConfig` - Configuration for admin operations
   - `KeycloakAdminAdapter` - Full implementation of `IdentityProviderAdminPort`
     - Also implements `GroupRolesCapability` (Keycloak-specific feature)
     - User CRUD: `create_user()`, `get_user()`, `get_user_by_username()`, `get_user_by_email()`, `update_user()`, `delete_user()`, `list_users()`, `count_users()`
     - Password management: `set_password()`, `send_password_reset()`, `send_verify_email()`
     - Role management: `list_roles()`, `get_user_roles()`, `assign_roles()`, `remove_roles()`
     - Group management: `list_groups()`, `get_user_groups()`, `add_to_groups()`, `remove_from_groups()`
     - Keycloak-specific: `get_group_roles()` - Groups can have roles assigned to them
   - `UserManagementError` - Exception for admin operations
   - `UserNotFoundError` - Exception for missing users

2. `src/cqrs_ddd_auth/adapters/__init__.py` (updated)
   - Added exports for `KeycloakAdminAdapter`, `KeycloakAdminConfig`, `UserManagementError`, `UserNotFoundError`

**Design Decision - Groups and Group Roles:**
Groups are universal across IdPs, but with varying semantics:
- **Hierarchy:** Some IdPs use paths (Keycloak: `/parent/child`), others use flat groups
- **Group Roles:** Keycloak-specific feature where groups can have roles assigned

This is handled via:
- Generic `GroupData` with optional `path` and `parent_id`
- `GroupRolesCapability` Protocol for IdPs that support group-to-role mapping
- Runtime check: `isinstance(adapter, GroupRolesCapability)` before using `get_group_roles()`

**Usage Example:**
```python
from cqrs_ddd_auth.adapters import KeycloakAdminAdapter, KeycloakAdminConfig
from cqrs_ddd_auth.ports import CreateUserData

config = KeycloakAdminConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="admin-cli",
    client_secret="admin-secret",
)
adapter = KeycloakAdminAdapter(config)

# Create user
user_id = await adapter.create_user(CreateUserData(
    username="newuser",
    email="user@example.com",
    first_name="New",
    last_name="User",
))

# Assign roles
await adapter.assign_roles(user_id, ["app-user", "viewer"])

# Add to groups
groups = await adapter.list_groups()
await adapter.add_to_groups(user_id, [groups[0].group_id])
```

---

## Step 22: [DONE] User Management Queries

Implement queries for user listing, details, and authorization info.

**Files modified:**
1. `src/cqrs_ddd_auth/application/queries.py`
   - `GetUser(user_id)` Query - Get user by ID
   - `GetUserByUsername(username)` Query - Get user by username
   - `GetUserByEmail(email)` Query - Get user by email
   - `ListUsers(search, enabled, role_name, group_name, first, max)` Query with filters
   - `GetUserRoles(user_id)` Query - Get user's assigned roles
   - `GetUserGroups(user_id)` Query - Get user's group memberships
   - `GetTypeLevelPermissions(resource_type)` Query - Get type-level permissions from ABAC

2. `src/cqrs_ddd_auth/application/results.py`
   - `UserResult` - User details (id, username, email, first_name, last_name, enabled, created_timestamp)
   - `ListUsersResult` - Paginated user list with total count
   - `RoleInfo` - Role details (id, name, description, composite)
   - `UserRolesResult` - List of user roles
   - `GroupInfo` - Group details (id, name, path - path is Optional for IdP-agnostic support)
   - `UserGroupsResult` - List of user groups
   - `TypeLevelPermissionsResult` - ABAC permissions info (action, access_type, can_perform, requires_filter)

3. `src/cqrs_ddd_auth/application/handlers.py`
   - `GetUserHandler` - Retrieves user by ID via IdP admin port
   - `GetUserByUsernameHandler` - Retrieves user by username
   - `GetUserByEmailHandler` - Retrieves user by email
   - `ListUsersHandler` - Lists users with filtering and pagination
   - `GetUserRolesHandler` - Lists user's roles (uses `GroupRolesCapability` check for group-derived roles)
   - `GetUserGroupsHandler` - Lists user's group memberships
   - `GetTypeLevelPermissionsHandler` - Gets type-level permissions from ABAC

---

## Step 23: ABAC Filter Integration (search_query_dsl)

Implement authorization filter for single-query authorization.

**Files to create:**
1. `src/cqrs_ddd_auth/contrib/abac_dsl/converter.py`
   - `FieldMapping` - Maps ABAC attributes to DSL field names
   - `ABACConditionConverter` - Converts JSON DSL to `SearchQuery`
   - Operator mapping: `st_dwithin` → `dwithin`, etc.

2. `src/cqrs_ddd_auth/contrib/stateful_abac/adapter.py`
   - `StatefulABACAuthorizationAdapter` implements `AuthorizationPort`
     - `get_authorization_filter()` → Returns `AuthorizationFilter`
     - `check_access()` - Traditional ID-based check
     - `sync()` - Trigger IdP sync

**Key pattern:**
```python
# Get authorization as SearchQuery
auth_filter = await authorization.get_authorization_filter(...)

# Merge with user query
if not auth_filter.granted_all:
    combined = user_query.merge(auth_filter.search_query)
```

---

## Step 24: ABAC SDK Dual Mode Support

Support both HTTP and DB modes for the ABAC SDK client.

**Files to modify:**
1. `src/cqrs_ddd_auth/contrib/stateful_abac/adapter.py`
   - HTTP mode: REST API calls (standard deployment)
   - DB mode: Direct SQL (10-100x faster for co-located services)

2. `src/cqrs_ddd_auth/contrib/dependency_injector.py`
   - `ABACClientFactory` with mode configuration
   - Environment-based mode selection

---

## Step 25: Identity Sync Command

Implement scheduled sync of IdP data to ABAC cache.

**Files to create:**
1. `src/cqrs_ddd_auth/application/sync_commands.py`
   - `SyncIdentityProvider` Command
   - `SyncIdentityProviderHandler`
     - Syncs roles, groups, users from IdP to ABAC

2. `src/cqrs_ddd_auth/contrib/scheduler.py` (optional)
   - Cron-based scheduler integration for background sync

---

## Step 26: Auth Router Factory

Create factory functions for framework-specific auth routers.

**Files to create:**
1. `src/cqrs_ddd_auth/contrib/fastapi/router.py`
   - `create_auth_router()` - Factory for FastAPI router
   - Endpoints: `/login`, `/refresh`, `/logout`, `/me`, `/totp/setup`, `/users`

2. `src/cqrs_ddd_auth/contrib/django/views.py`
   - `AuthViewSet` or function-based views
   - URL patterns factory

---

## Step 27: Package Reorganization

Reorganize package structure per proposal Section 12.

**Structure:**
```
cqrs_ddd_auth/
├── domain/               # Aggregates, value objects, events
├── application/          # Commands, queries, handlers, sagas
├── infrastructure/       # Ports and adapters
│   ├── ports.py
│   └── adapters/
│       ├── keycloak/
│       └── otp/
├── middleware/           # AuthorizationMiddleware, PermittedActionsMiddleware
├── refresh/              # TokenRefreshAdapter
├── context.py            # RequestContext, get_identity()
├── identity.py           # Identity Protocol
└── contrib/              # Framework adapters
    ├── stateful_abac/
    ├── fastapi/
    └── django/
```

---

## Step 28: Error Handling & Domain Errors

Implement comprehensive error types.

**Files to create:**
1. `src/cqrs_ddd_auth/domain/errors.py`
   - `AuthenticationError` - Invalid credentials, expired session
   - `AuthorizationError` - Access denied
   - `InvalidTokenError` - JWT validation failed
   - `OTPError` - OTP validation failed, too many attempts
   - `UserManagementError` - IdP operation failed

2. Error mapping in framework adapters (HTTP status codes)

---

## Step 31: TokenRefreshAdapter

Implement framework-agnostic token refresh logic.

**Files to create:**
1. `src/cqrs_ddd_auth/refresh/adapter.py`
   - `TokenRefreshAdapter` - Delegates refresh to mediator/handler
   - `TokenExtractionResult` - Contains tokens and detected source
   - `TokenRefreshResult` - Result with new tokens or needs_auth flag

2. `src/cqrs_ddd_auth/refresh/middleware.py`
   - Framework-agnostic base middleware logic
   - Auto-detect token source (header vs cookie)
   - Inject refreshed tokens into request

---

## Step 32: AuthResult & TokenPair DTOs

Implement result types for authentication commands.

**Files to create/modify:**
1. `src/cqrs_ddd_auth/application/results.py`
   - `TokenPair` DTO - access_token, refresh_token, expires_in
   - `AuthResult` - Success/failed/otp_required factory methods
   - `TokenResult` - For refresh operations
   - `UserInfoResult` - For GetUserInfo query

---

## Step 33: CompositeOTPService

Implement composite service that delegates to multiple OTP methods.

**Files to modify:**
1. `src/cqrs_ddd_auth/adapters/otp.py`
   - `CompositeOTPService` implements `OTPServicePort`
     - Combines TOTP, Email, SMS services
     - Routes to appropriate service based on method
     - Aggregates available methods from all services

**Usage:**
```python
composite = CompositeOTPService([
    totp_service,
    email_otp_service,
    sms_otp_service,
])
```

---

## Step 34: Simple RBAC Adapter

Implement simple role-based adapter for non-ABAC deployments.

**Files to create:**
1. `src/cqrs_ddd_auth/adapters/rbac.py`
   - `SimpleRBACAdapter` implements `AuthorizationPort`
   - Permission checks based on role membership
   - No external service dependency
   - Configurable role→permissions mapping

**Usage:**
```python
rbac = SimpleRBACAdapter({
    "admin": ["*"],
    "editor": ["view", "edit"],
    "viewer": ["view"],
})
```

---

## Step 35: DisableTOTP Command

Implement TOTP removal for account security settings.

**Files to modify:**
1. `src/cqrs_ddd_auth/application/commands.py`
   - `DisableTOTP` Command - Remove TOTP from account

2. `src/cqrs_ddd_auth/application/handlers.py`
   - `DisableTOTPHandler` - Deletes TOTP secret
   - May require current password or OTP verification

---

## Step 36: Testing Suite

Comprehensive test coverage for all components.

**Files to create:**
1. `tests/unit/test_domain.py`
   - Test aggregates, value objects, state transitions

2. `tests/unit/test_handlers.py`
   - Test handlers with mocked ports
   - Cover success, failure, OTP flows

3. `tests/unit/test_middleware.py`
   - Test authorization and permitted actions middleware

4. `tests/integration/test_auth_flow.py`
   - End-to-end auth flow with in-memory adapters

5. `tests/integration/test_abac_integration.py`
   - Test ABAC adapter with SDK

---

## Step 37: Documentation & Examples

Complete documentation and example applications.

**Files to create:**
1. `README.md` - Installation, quick start, configuration
2. `docs/CONFIGURATION.md` - Environment variables guide
3. `docs/API.md` - Endpoint documentation
4. `docs/KEYCLOAK_SETUP.md` - Keycloak realm configuration
5. `docs/ABAC_INTEGRATION.md` - ABAC policy engine integration
6. `examples/fastapi_app/` - Complete FastAPI example
7. `examples/django_app/` - Complete Django example
8. `CHANGELOG.md` - Version history

---



## Implementation Details

### Dual-Mode Authentication

The library supports two authentication modes via `track_session` flag:

**Stateless Mode** (`track_session=False`, default):
- Best for APIs, SPAs, mobile apps
- OTP validated inline with credentials
- No session persistence needed
- Single request/response flow

**Stateful Mode** (`track_session=True`):
- Best for traditional web apps, banking, high-security
- Multi-step flow with session persistence
- Session ID returned for subsequent OTP validation

```python
# Stateless (inline OTP)
cmd = AuthenticateWithCredentials(
    username="user", password="pass",
    otp_method="totp", otp_code="123456",
    track_session=False,  # default
)

# Stateful (multi-step)
cmd = AuthenticateWithCredentials(
    username="user", password="pass",
    track_session=True,  # creates session
)
# Returns session_id → use ValidateOTP with session_id
```

---

### Token Storage in Multi-Step Auth

For stateful mode, tokens must be preserved across the OTP phase:

1. `AuthSession` aggregate has `pending_access_token` and `pending_refresh_token` fields
2. `credentials_validated()` stores tokens when OTP is required
3. `ValidateOTPHandler` retrieves stored tokens after OTP validation

**Flow:**
```
Step 1: Credentials → IdP → tokens stored in session.pending_*
Step 2: ValidateOTP → session.pending_* tokens returned
```

---

### Token Delivery (Header vs Cookie)

Token delivery is handled at the **framework adapter layer**, not in handlers.

**Key components in `adapters/tokens.py`:**
- `TokenSource` enum: `HEADER` or `COOKIE`
- `TokenExtractionResult`: Contains tokens and detected source
- `TokenRefreshAdapter`: Handles transparent token refresh

**Framework integrations:**
- `contrib/django.py`: `TokenRefreshMiddleware`, `AuthenticationMiddleware`
- `contrib/fastapi.py`: `TokenRefreshMiddleware`, `get_current_user` dependency

**Auto-detection pattern:**
```
Request via Authorization header → Response via X-New-Access-Token header
Request via cookies → Response via Set-Cookie
```

---

### Claim Mapping (IdP Normalization)

Different IdPs use different claim names. Mapping happens in the **adapter**:

| IdP | Username Claim | Groups Claim |
|-----|----------------|--------------|
| Keycloak | `preferred_username` | `realm_access.roles` |
| Auth0 | `nickname` | `https://app.com/roles` |
| Cognito | `cognito:username` | `cognito:groups` |

**UserClaims** is the normalized domain representation:
```python
@dataclass(frozen=True)
class UserClaims(ValueObject):
    sub: str        # Standard JWT subject
    username: str   # Mapped from IdP-specific claim
    email: str
    groups: tuple[str, ...]  # Mapped from IdP-specific location
    attributes: dict  # Additional claims
```

**Adapter responsibility:**
```python
# In KeycloakAdapter.decode_token():
return UserClaims(
    sub=payload["sub"],
    username=payload.get("preferred_username", ""),  # ← IdP-specific
    email=payload.get("email", ""),
    groups=tuple(payload.get("realm_access", {}).get("roles", [])),  # ← IdP-specific
    attributes={"tenant_id": payload.get("tenant_id")},
)
```

The application layer only works with normalized `UserClaims`.

---

### Identity Context Management

Request-scoped identity via `contextvars`:

```python
from cqrs_ddd_auth.identity import (
    get_identity,      # Get current identity
    set_identity,      # Set by middleware
    get_access_token,  # For downstream ABAC calls
    set_access_token,  # Set by middleware
)
```

Middleware sets identity at request start, handlers access via `get_identity()`.
