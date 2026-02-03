# py-cqrs-ddd-auth

[![PyPI version](https://badge.fury.io/py/py-cqrs-ddd-auth.svg)](https://badge.fury.io/py/py-cqrs-ddd-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI Status](https://github.com/yourusername/py-cqrs-ddd-auth/workflows/CI/badge.svg)](https://github.com/yourusername/py-cqrs-ddd-auth/actions)

**A toolkit-native authentication and authorization library built using CQRS, DDD, and Saga patterns.**

---

## Value Proposition

Why use this over standard auth libraries?
1.  **Strict DDD/CQRS Separation**: Authentication logic is decoupled from frameworks, making your core domain pure and testable.
2.  **Native Saga Support**: Complex flows like "Step-Up Authentication" (MFA on demand) are first-class citizens.
3.  **Decoupled Infrastructure**: Easily swap Identity Providers (Keycloak, Auth0) or storage backends without changing business logic.
4.  **Toolkit Synergy**: Designed to integrate seamlessly with `py-cqrs-ddd-toolkit` for unified transactions and audit logging.

---

## Key Features

*   **Domain-Driven**: Aggregates for `AuthSession`, `TokenPair`, `OTPChallenge`.
*   **Infrastructure Agnostic**: Support for Keycloak (`python-keycloak`) out of the box.
*   **Multi-Factor Authentication**: Built-in support for TOTP, Email, and SMS OTP.
*   **Step-Up Auth**: Dedicated OTP endpoints for on-demand privilege elevation.
*   **Stateful & Stateless Modes**: Flexible session management (DB-backed or signed JWE).
*   **Authorization**: Integrated RBAC and Attribute-Based Access Control (ABAC) with ownership awareness.
*   **Framework Integrations**: Drop-in support for **FastAPI** and **Django**.

---

## Installation

```bash
pip install py-cqrs-ddd-auth
```

**Extras:**
*   `pip install py-cqrs-ddd-auth[keycloak]` (Recommended)
*   `pip install py-cqrs-ddd-auth[fastapi]`
*   `pip install py-cqrs-ddd-auth[django]`
*   `pip install py-cqrs-ddd-auth[all]`

---

## Configuration Modes

The library supports two distinct authentication strategies. Choose the one that fits your architecture.

### 1. Stateful Authentication (Default)
Best for standard web apps where server-side session management is desired (e.g., for "List Active Sessions" features, or resolving user identity via session ID).

**Configuration:**
```python
# Create a container that uses SQLAlchemy for session storage
# This replaces the default InMemorySessionAdapter
class StatefulAuthContainer(AuthContainer):
    session_repo = providers.Singleton(
        SQLAlchemySessionAdapter,
        session_factory=db.session_factory
    )

container = StatefulAuthContainer()
```

**Flow:**
1.  **Login**: `AuthenticateWithCredentials(username="...", track_session=True)`
2.  **Result**: Returns `tokens` AND `session_id`. If OTP is required, the session waits in `PENDING_OTP` state.
3.  **OTP**: Client provides `ValidateOTP(session_id="...", code="123456")`.
4.  **Storage**: Session state is persisted in DB or Redis.

### 2. Stateless Authentication
Best for high-scale APIs where you want to avoid DB writes during login or don't need session tracking (JWTs are self-contained).

**Configuration:**
```python
# 1. Register PreAuthTokenService with a secret key
class StatelessAuthContainer(AuthContainer):
    pre_auth_service = providers.Factory(
        PreAuthTokenService,
        secret_key="YOUR_32_BYTE_SECRET_KEY..." # Used to encrypt JWE
    )

container = StatelessAuthContainer()
```

**Flow:**
1.  **Login**: `AuthenticateWithCredentials(username="...", track_session=False)`
2.  **Result**: Returns `tokens`. If OTP is required, returns `AuthResult.otp_required` containing a `pre_auth_token` (JWE). This token securely holds the "User Credentials Validated" state.
3.  **OTP**: Client resends credentials *automatically* or prompts user for code, then calls:
    `AuthenticateWithCredentials(otp_code="123456", pre_auth_token="<JWE_TOKEN>")`
    *Note: The client handles the token echo; the server is stateless.*
4.  **Storage**: Context is restored from the decrypted JWE; no session is created in the DB.

---

## Framework Implementation Examples

Here are concrete examples of how to implement the different modes in your application code.

### A. FastAPI Implementation

**1. Stateless Login (Client manages token)**
```python
@app.post("/login/stateless")
async def login_stateless(
    username: str = Body(...),
    password: str = Body(...),
    mediator: Mediator = Depends(Provide[AuthContainer.mediator])
):
    # track_session=False (default) -> Returns tokens directly
    result = await mediator.send(AuthenticateWithCredentials(
        username=username,
        password=password,
        track_session=False
    ))
    return result
```

**2. Stateful Login (Server manages session)**
```python
@app.post("/login/stateful")
async def login_stateful(
    username: str = Body(...),
    password: str = Body(...),
    mediator: Mediator = Depends(Provide[AuthContainer.mediator])
):
    # track_session=True -> Returns session_id
    result = await mediator.send(AuthenticateWithCredentials(
        username=username,
        password=password,
        track_session=True
    ))
    return result
```

**3. MFA Step-Up Flow (concept)**
For sensitive operations, the API returns a 403 error, and the client uses the dedicated OTP endpoints to elevate privileges.

```python
@app.post("/transfer")
async def transfer_funds(
    amount: Decimal,
    user: Identity = Depends(require_authenticated),
    # Custom dependency or middleware that checks for MFA elevation
    is_elevated: bool = Depends(verify_elevation("transfer_funds"))
):
    # This point is only reached if the user has verified their identity via OTP
    # for this specific operation within the last 5 minutes.
    await mediator.send(TransferFundsCommand(user_id=user.user_id, amount=amount))
    return {"status": "transferred"}
```
> [!NOTE]
> When `verify_elevation` fails, it raises an `AuthorizationError(code="MFA_REQUIRED")` and emits a `SensitiveOperationRequested` event to trigger the Step-Up Saga.

### B. Django Implementation

**1. Stateless Login View**
```python
class StatelessLoginView(CQRSView):
    async def post(self, request):
        data = json.loads(request.body)
        result = await self.dispatch_command(AuthenticateWithCredentials(
            username=data['username'],
            password=data['password'],
            track_session=False
        ))
        return self.success(result)
```

**2. Stateful Login View**
```python
class StatefulLoginView(CQRSView):
    async def post(self, request):
        data = json.loads(request.body)
        # Returns session_id, which client usually stores in Cookie or LocalStorage
        result = await self.dispatch_command(AuthenticateWithCredentials(
            username=data['username'],
            password=data['password'],
            track_session=True
        ))
        return self.success(result)
```

**3. MFA Step-Up Flow (concept)**
```python
class TransferFundsView(CQRSView):
    @require_authenticated
    @verify_elevation("transfer_funds") # Custom decorator
    async def post(self, request):
        data = json.loads(request.body)
        await self.dispatch_command(TransferFundsCommand(
            user_id=get_identity().user_id,
            amount=data['amount']
        ))
        return JsonResponse({"status": "transferred"})
```

---

## Usage Models

### 1. Quick Start (FastAPI)

The fastest way to get started is using the `contrib.fastapi` module.

```python
# main.py
from fastapi import FastAPI
from cqrs_ddd_auth.contrib.fastapi import (
    create_auth_router,
    TokenRefreshMiddleware,
    AuthenticationMiddleware,
    register_exception_handlers
)
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer

# 1. Initialize Container
container = AuthContainer()
container.config.keycloak.server_url.from_env("KEYCLOAK_URL")
container.wire(modules=["cqrs_ddd_auth.contrib.fastapi.router"])

# 2. Setup App
app = FastAPI()
register_exception_handlers(app)

# 3. Add Middleware (Order matters!)
app.add_middleware(AuthenticationMiddleware)  # Populates user
app.add_middleware(TokenRefreshMiddleware)    # Auto-refreshes tokens

# 4. Include Router
app.include_router(create_auth_router())
```

### 2. Quick Start (Django)

For Django, integration is done via settings and URL configuration.

```python
# settings.py
INSTALLED_APPS = [
    ...,
    "cqrs_ddd_auth.contrib.django",
]

MIDDLEWARE = [
    ...,
    "cqrs_ddd_auth.contrib.django.AuthenticationMiddleware",
    "cqrs_ddd_auth.contrib.django.TokenRefreshMiddleware",
]

# Configure Container (e.g., in apps.py ready())
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
container = AuthContainer()
container.wire(modules=["cqrs_ddd_auth.contrib.django.views"])
```

```python
# urls.py
from django.urls import path, include
from cqrs_ddd_auth.contrib.django import get_auth_urls

urlpatterns = [
    # Adds /login, /refresh, /me, etc. automatically
    path("api/auth/", include(get_auth_urls())),
]
```

### API Reference

Both FastAPI and Django integrations expose the following endpoints:

| Endpoint | Method | Description | Step-Up Support |
| :--- | :--- | :--- | :--- |
| `/login` | `POST` | Primary authentication (password/credentials) | - |
| `/refresh` | `POST` | Refresh access token using refresh token | - |
| `/logout` | `POST` | Revoke current/specified session | - |
| `/me` | `GET` | Get current user profile and TOTP status | - |
| `/otp/challenge` | `POST` | Trigger an OTP challenge (email/sms) | Yes (via Token) |
| `/otp/validate` | `POST` | Validate OTP code to elevate privileges | Yes (via Token) |
| `/totp/setup` | `POST` | Initialize/Confirm TOTP (Google Authenticator) | - |
| `/users` | `GET` | List users (Admin only) | - |

---

### 3. Protecting Endpoints (FastAPI)

Use the provided dependencies to secure your own endpoints.

```python
from fastapi import Depends
from cqrs_ddd_auth.contrib.fastapi import require_authenticated, require_groups
from cqrs_ddd_auth.identity import Identity

@app.get("/secure-data")
async def get_secure_data(
    user: Identity = Depends(require_authenticated)
):
    return {"message": f"Hello, {user.username}!"}

@app.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: Identity = Depends(require_groups("admin"))
):
    # Only reachable by users with "admin" group
    ...
```

### 4. Protecting Endpoints (Django)

Use decorators for function-based views or mixins (if you create them) for CBVs.

```python
from django.http import JsonResponse
from cqrs_ddd_auth.contrib.django.decorators import require_authenticated, require_groups
from cqrs_ddd_auth.identity import get_identity

@require_authenticated
async def get_secure_data(request):
    user = get_identity()
    return JsonResponse({"message": f"Hello, {user.username}!"})

@require_groups("admin")
async def delete_user(request, user_id):
    # Only reachable by users with "admin" group
    ...
```

### 5. Step-Up Authentication (Distributed Saga)

The library uses an event-driven choreography (Saga pattern) to handle step-up authentication. This avoids blocking handlers and provides a clean way to resume operations.

1.  **Operation Request**: User calls a sensitive endpoint.
2.  **MFA Check**: System detects higher assurance is needed. It raises `MFA_REQUIRED` and emits `SensitiveOperationRequested`.
3.  **Saga Activation**: `StepUpAuthenticationSaga` starts, listening for the event.
4.  **Client Verification**: Frontend calls `/auth/otp/validate` with `correlation_id` (the `operation_id` from the 403 error).
5.  **Completion**: Saga receives `OTPValidated`, grants temporary elevation, and (optionally) resumes the original operation.

#### Dedicated OTP Endpoints

Use these endpoints for standalone OTP verification (Step-Up flows) or custom login screens.

**FastAPI / Django Paths:**
- `POST /auth/otp/challenge`: Request a new code (supports `email`, `sms`).
- `POST /auth/otp/validate`: Validate a code.

**Schema (Validate):**
```json
{
  "code": "123456",
  "method": "totp",
  "correlation_id": "original-operation-id"
}
```
> [!IMPORTANT]
> Always pass the `correlation_id` from the sensitive operation's error response. This allows the Saga to correctly route the `OTPValidated` event back to the original request context.

### 6. High-Performance ABAC Query Filtering

Instead of fetching all rows and filtering in Python, use the `StatefulABACAdapter` to push permissions down to the database using `search_query_dsl`.

```python
from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAdapter

@inject
async def list_documents(
    user: Identity,
    abac: StatefulABACAdapter = Provide[AuthContainer.authorization_adapter]
):
    # 1. Get Authorization Filter (lazily converts ABAC DSL -> SearchQuery)
    auth_filter = await abac.get_authorization_filter(
        access_token=user.access_token,
        resource_type="document",
        action="read",
        field_mapping=FieldMapping(external_id_field="id") # Map SQL 'id' to ABAC 'external_id'
    )

    if auth_filter.denied_all:
        return [] # User has no access

    # 2. Merge with User Query
    user_query = SearchQuery(filter={"status": "published"})

    if not auth_filter.granted_all:
        # e.g., adds "AND (created_by_id = 'user_123' OR department = 'IT')"
        final_query = user_query.merge(auth_filter.search_query)
    else:
        final_query = user_query # Blanket access (e.g., admin)

    # 3. Execute efficient DB query
    return await repository.search(final_query)
```

### 7. Integration with `py-cqrs-ddd-toolkit`

When using the recommended toolkit, you can merge containers and share the Mediator.

```python
from dependency_injector import containers, providers
from cqrs_ddd.mediator import Mediator
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer, SQLAlchemyAuthContainer

# 1. Define Combined Container
class ApplicationContainer(SQLAlchemyAuthContainer, AuthContainer):
    # Core app dependencies
    session_factory = providers.Dependency()

    # ... your app's other dependencies ...

# 2. Setup (e.g., in main.py)
container = ApplicationContainer()
container.session_factory.override(my_db_session_factory)

# 3. Register Auth Handlers with Core Mediator
mediator = Mediator(uow_factory=...)

# Register all Auth commands automatically
for cmd, handler_provider in container.get_all_command_handlers().items():
    mediator.register(cmd, handler_provider())

# Register all Auth queries automatically
for query, handler_provider in container.get_all_query_handlers().items():
    mediator.register(query, handler_provider())

# Now the mediator can handle auth commands!
await mediator.send(AuthenticateWithCredentials(...))
```


### 8. ABAC Middleware (CQRS Pipeline)

For declarative authorization at the Command Handler level, use the provided middleware.

**1. Register the Middleware:**
At application startup (e.g., `main.py`), replacing the toolkit's default skeletons:

```python
from cqrs_ddd_auth.middleware import register_abac_middleware
from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAdapter

# Initialize your ABAC adapter
abac_adapter = StatefulABACAdapter(...)

# Registers `@middleware.authorize` and `@middleware.permitted_actions`
# Monkey-patches the toolkit registry to support 'permitted_actions'
register_abac_middleware(authorization_port=abac_adapter)
```

**2. Use Decorators:**

```python
from cqrs_ddd.middleware import middleware

@middleware.authorize(
    resource_type="document",
    required_actions=["read"],
    # Extracts 'document_id' from command attributes to check ownership/permissions
    resource_id_attr="document_id"
)
class ReadDocumentHandler:
    ...

@middleware.permitted_actions(
    resource_type="document",
    # Populates 'item.permitted_actions' (e.g., ["read", "delete"]) on result entities
    result_entities_attr="items"
)
class ListDocumentsHandler:
    ...
```

---

## Architecture

The `src/cqrs_ddd_auth` directory follows a clean **Domain-Driven Design (DDD)** structure.

### `domain/` (The Core)
Contains the heart of the system.
*   **Aggregates**: `AuthSession`, `TokenPair`.
*   **Events**: `AuthSessionCreated`, `OTPRequired`.
*   **Value Objects**: `UserClaims`, `AuthRole`.

### `application/` (Use Cases)
Orchestrates domain objects.
*   **Command Handlers**: `AuthenticateWithCredentials`, `ValidateOTP`.
*   **Query Handlers**: `GetUserInfo`, `ListActiveSessions`.
*   **Sagas**: `StepUpAuthenticationSaga`.

### `infrastructure/` (Adapters)
*   **Identity**: `KeycloakAdapter` (OIDC), `KeycloakAdminAdapter` (User Mgmt).
*   **Authorization**: `StatefulABACAdapter`, `OwnershipAwareRBACAdapter`.
*   **Persistence**: `SQLAlchemySessionAdapter`, `RedisElevationStore`.

### `contrib/` (Integration)
*   **`dependency_injector.py`**: Pre-wired IoC Container.
*   **`fastapi/`**: Middleware, Router, Dependencies.
*   **`django/`**: Middleware, Views, Decorators.

---

## Utilities

### Request Context
We use `contextvars` to manage request-scoped identity safely in async environments.

*   `get_identity()`: Returns the current `Identity` (Authenticated or Anonymous).
*   `get_access_token()`: Returns the raw token string.

### Factory Configuration
The library favors "Convention over Configuration".
*   `create_default_idp()`: Auto-detects Keycloak settings from Env Vars or Django Settings.

---

## License

MIT License.
