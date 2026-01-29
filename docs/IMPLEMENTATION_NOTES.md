# Implementation Notes: py-cqrs-ddd-auth

Based on the Architecture Proposal, these are the first 5 implementation steps.

---

## Step 1: Project Scaffolding

Create the core project structure following the `py-cqrs-ddd-toolkit` pattern.

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
- Optional: `python-keycloak`, `python-jose[cryptography]`, `httpx`, `pydantic`

---

## Step 2: Identity Protocol & Context

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

## Step 3: Domain Layer - Value Objects & Aggregates

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
   - `AuthSessionCreated`
   - `OTPRequired`
   - `AuthenticationSucceeded`
   - `AuthenticationFailed`
   - `SessionRevoked`


---

## Step 4: Ports (Infrastructure Interfaces)

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

## Step 5: Application Layer - Commands & Handlers

Implement the primary authentication command and handler (Section 4.1).

**Files to create:**
1. `src/cqrs_ddd_auth/application/commands.py`
   - `AuthenticateWithCredentials` Command
   - `ValidateOTP` Command
   - `RefreshTokens` Command
   - `Logout` Command

2. `src/cqrs_ddd_auth/application/results.py`
   - `AuthResult` (success/failed/otp_required factory methods)
   - `TokenPair` DTO

3. `src/cqrs_ddd_auth/application/handlers.py`
   - `AuthenticateWithCredentialsHandler`
     - Inject: `IdentityProviderPort`, `OTPServicePort`, `AuthSessionRepository`, `TokenIssuerPort`
     - Flow: Create session → Validate IdP → Check roles → Handle OTP → Issue tokens

**Testing Strategy:**
- Unit test handlers with mocked ports
- Integration test with in-memory adapters
