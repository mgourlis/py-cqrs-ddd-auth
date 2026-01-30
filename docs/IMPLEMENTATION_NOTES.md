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

## Step 11: Queries & Query Handlers

Implement read-side queries for user info and session management.

**Files to create/modify:**
1. `src/cqrs_ddd_auth/application/queries.py`
   - `GetUserInfo` Query
   - `GetAvailableOTPMethods` Query
   - `ListActiveSessions` Query (for session management UI)

2. `src/cqrs_ddd_auth/application/handlers.py`
   - `GetUserInfoHandler` - Returns user claims + type-level permissions
   - `GetAvailableOTPMethodsHandler` - Returns available 2FA methods
   - `ListActiveSessionsHandler` - Lists user's active sessions

---

## Step 12: ABAC Authorization Port

Implement the ABAC SDK client adapter for authorization.

**Files to create:**
1. `src/cqrs_ddd_auth/adapters/abac.py`
   - `ABACEngineClient` implements `ABACAuthorizationPort`
     - `check_access()` - Check if user can perform action on resources
     - `get_permitted_actions()` - Get allowed actions per resource
     - `list_resource_types()` - List available resource types

**Integration Notes:**
- Uses `stateful-abac-sdk` package
- Passes `access_token` from identity context
- Caches resource type list for performance

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

## Step 14: Role Unification (Groups as Roles)

Implement unified role model merging Keycloak groups and roles.

**Files to modify:**
1. `src/cqrs_ddd_auth/domain/value_objects.py`
   - `AuthRole` ValueObject - Unified role representation
   - `RoleSource` enum - `REALM_ROLE`, `CLIENT_ROLE`, `GROUP`, `CUSTOM`
   - `GroupPathStrategy` enum - `FULL_PATH`, `LAST_SEGMENT`, `ALL_SEGMENTS`

2. `src/cqrs_ddd_auth/adapters/keycloak.py`
   - Update `decode_token()` to merge groups as roles
   - Add `KeycloakConfig.merge_groups_as_roles` option
   - Add `KeycloakConfig.group_path_strategy` option

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

## Step 21: User Management via IdP

Implement commands for user management through the identity provider.

**Files to create/modify:**
1. `src/cqrs_ddd_auth/ports/identity_provider_admin.py`
   - `IdentityProviderAdminPort` Protocol
     - `create_user()`, `get_user()`, `update_user()`, `delete_user()`
     - `set_password()`, `send_password_reset()`
     - `assign_roles()`, `remove_roles()`
     - `join_groups()`, `leave_groups()`

2. `src/cqrs_ddd_auth/application/user_commands.py`
   - `CreateUser`, `UpdateUser`, `DeleteUser` Commands
   - `ResetPassword`, `SendPasswordResetEmail` Commands
   - `AssignRoles`, `RemoveRoles` Commands
   - `AssignGroups`, `RemoveFromGroups` Commands

3. `src/cqrs_ddd_auth/adapters/keycloak_admin.py`
   - `KeycloakAdminAdapter` implements `IdentityProviderAdminPort`

---

## Step 22: User Management Queries

Implement queries for user listing and details.

**Files to create:**
1. `src/cqrs_ddd_auth/application/user_queries.py`
   - `GetUser`, `GetUserByUsername` Queries
   - `ListUsers` Query with filters (search, role, group, enabled)
   - `GetUserRoles`, `GetUserGroups` Queries

2. `src/cqrs_ddd_auth/application/handlers.py`
   - `GetUserHandler`, `ListUsersHandler`
   - `GetUserRolesHandler`, `GetUserGroupsHandler`

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
