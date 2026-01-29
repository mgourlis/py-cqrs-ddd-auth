# py-cqrs-ddd-auth: Architecture Proposal

A **toolkit-native** authentication and authorization library built using CQRS, DDD, and Saga patterns. This is not a port of legacy code—it's a ground-up design that treats authentication as a **first-class domain** within the toolkit's architectural paradigm.

---

## 1. Design Philosophy

### What This Is NOT
- ❌ A collection of Django/FastAPI middleware
- ❌ A wrapper around existing auth libraries
- ❌ Framework-specific code that happens to use the toolkit

### What This IS
- ✅ A **domain-driven** authentication module with proper Aggregates, Commands, and Events
- ✅ **Pluggable identity providers** modeled as infrastructure adapters (not baked-in)
- ✅ **Authorization as a query** leveraging the ABAC engine's SQL compilation
- ✅ **2FA as a Saga** managing multi-step authentication flows
- ✅ Thin **framework adapters** that delegate to the domain layer

---

## 2. Core Principles

### 2.1 Identity as a Protocol, Not an Entity
The toolkit defines `Identity` as a **Protocol**—a contract that the host application fulfills. The domain layer never knows *how* the identity was resolved.

```python
# In py-cqrs-ddd-toolkit (core.py or identity.py)
from typing import Protocol, Optional

class Identity(Protocol):
    """Protocol for identity information passed to handlers."""
    @property
    def user_id(self) -> str: ...
    
    @property
    def username(self) -> str: ...
    
    @property
    def groups(self) -> list[str]: ...
    
    @property
    def permissions(self) -> list[str]: ...
    
    @property
    def tenant_id(self) -> Optional[str]: ...
    
    @property
    def is_authenticated(self) -> bool: ...
    
    @property
    def is_system(self) -> bool: ...

class AnonymousIdentity:
    """Default identity for unauthenticated requests."""
    user_id = "anonymous"
    username = "anonymous"
    groups = []
    permissions = []
    tenant_id = None
    is_authenticated = False
    is_system = False

class SystemIdentity:
    """Identity for internal system processes (event handlers, sagas)."""
    user_id = "system"
    username = "system"
    groups = ["*"]
    permissions = ["*"]
    tenant_id = None
    is_authenticated = True
    is_system = True
```

### 2.2 Context Propagation via ContextVars
The toolkit uses `contextvars` for request-scoped data. Identity flows through this mechanism:

```python
from contextvars import ContextVar
from dataclasses import dataclass

@dataclass
class RequestContext:
    identity: Identity
    correlation_id: str
    causation_id: Optional[str] = None
    access_token: Optional[str] = None
    metadata: dict = field(default_factory=dict)

request_context: ContextVar[RequestContext] = ContextVar('request_context')

def get_identity() -> Identity:
    """Get current identity from context."""
    ctx = request_context.get(None)
    return ctx.identity if ctx else AnonymousIdentity()

def get_access_token() -> Optional[str]:
    """Get access token for downstream authorization calls."""
    ctx = request_context.get(None)
    return ctx.access_token if ctx else None
```

---

## 3. Domain Layer: Authentication as a Bounded Context

### 3.1 Domain Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Domain                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Aggregates:                                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐ │
│  │ AuthSession     │  │ OTPChallenge    │  │ TokenPair        │ │
│  │                 │  │                 │  │                  │ │
│  │ - session_id    │  │ - challenge_id  │  │ - access_token   │ │
│  │ - user_id       │  │ - user_id       │  │ - refresh_token  │ │
│  │ - status        │  │ - method        │  │ - expires_at     │ │
│  │ - created_at    │  │ - code_hash     │  │ - user_claims    │ │
│  │ - expires_at    │  │ - attempts      │  │                  │ │
│  │ - metadata      │  │ - expires_at    │  │                  │ │
│  └─────────────────┘  └─────────────────┘  └──────────────────┘ │
│                                                                 │
│  Value Objects:                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐ │
│  │ Credentials     │  │ OTPCode         │  │ UserClaims       │ │
│  │ - username      │  │ - value         │  │ - sub            │ │
│  │ - password      │  │ - hash()        │  │ - email          │ │
│  │                 │  │ - verify()      │  │ - groups         │ │
│  └─────────────────┘  └─────────────────┘  └──────────────────┘ │
│                                                                 │
│  Domain Events:                                                 │
│  • AuthenticationRequested                                      │
│  • CredentialsValidated                                         │
│  • OTPChallengeIssued                                           │
│  • OTPValidated / OTPFailed                                     │
│  • AuthenticationSucceeded / AuthenticationFailed               │
│  • SessionCreated / SessionRevoked                              │
│  • TokenRefreshed / TokenExpired                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Value Objects

```python
from dataclasses import dataclass
from cqrs_ddd.ddd import ValueObject
import hashlib
import secrets

@dataclass(frozen=True)
class Credentials(ValueObject):
    """Username/password pair for direct grant authentication."""
    username: str
    password: str  # Never persisted, only used in-memory


@dataclass(frozen=True)
class TOTPSecret(ValueObject):
    """
    TOTP secret for time-based OTP using pyotp.
    
    This is used for authenticator app-based 2FA (Google Authenticator, Authy, etc.).
    """
    secret: str  # Base32 encoded secret
    
    @classmethod
    def generate(cls) -> "TOTPSecret":
        """Generate a new random TOTP secret."""
        import pyotp
        return cls(secret=pyotp.random_base32())
    
    def get_provisioning_uri(self, username: str, issuer: str) -> str:
        """
        Generate a provisioning URI for QR code display.
        
        Users scan this with their authenticator app to set up 2FA.
        """
        import pyotp
        totp = pyotp.TOTP(self.secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    
    def verify_code(self, code: str, valid_window: int = 1) -> bool:
        """
        Verify a TOTP code against this secret.
        
        Args:
            code: The 6-digit code from the user's authenticator app
            valid_window: Number of time periods before/after current to accept (default: 1)
        
        Returns:
            True if the code is valid
        """
        import pyotp
        totp = pyotp.TOTP(self.secret)
        return totp.verify(code, valid_window=valid_window)
    
    def get_current_code(self) -> str:
        """Get the current TOTP code (useful for testing)."""
        import pyotp
        totp = pyotp.TOTP(self.secret)
        return totp.now()

@dataclass(frozen=True)
class UserClaims(ValueObject):
    """Decoded JWT claims."""
    sub: str
    username: str
    email: str
    groups: tuple[str, ...]
    attributes: dict
    
    def to_identity(self) -> Identity:
        return AuthenticatedIdentity(
            user_id=self.sub,
            username=self.username,
            groups=list(self.groups),
            permissions=[],  # Fetched separately from ABAC
            tenant_id=self.attributes.get("tenant_id")
        )
```

### 3.3 Aggregates

```python
from cqrs_ddd.ddd import AggregateRoot, DomainEvent
from enum import Enum
from datetime import datetime, timedelta
import uuid

class AuthSessionStatus(Enum):
    PENDING_CREDENTIALS = "pending_credentials"
    PENDING_OTP = "pending_otp"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    REVOKED = "revoked"

class AuthSession(AggregateRoot):
    """
    Aggregate representing an authentication session.
    Tracks the multi-step authentication process.
    
    Note: This aggregate is transport-agnostic. Token delivery (header vs cookie)
    is handled at the framework adapter layer, not here.
    """
    def __init__(
        self,
        session_id: str,
        ip_address: str,
        user_agent: str,
    ):
        super().__init__(id=session_id)
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.status = AuthSessionStatus.PENDING_CREDENTIALS
        self.user_id: Optional[str] = None
        self.user_claims: Optional[UserClaims] = None
        self.otp_challenge_id: Optional[str] = None
        self.failure_reason: Optional[str] = None
        self.expires_at = datetime.utcnow() + timedelta(minutes=30)
    
    @classmethod
    def create(cls, ip_address: str, user_agent: str) -> "AuthSession":
        session = cls(
            session_id=str(uuid.uuid4()),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add_domain_event(AuthSessionCreated(
            session_id=session.id,
            ip_address=ip_address
        ))
        return session
    
    def credentials_validated(self, user_claims: UserClaims, requires_otp: bool):
        """Called when primary credentials are valid."""
        self.user_id = user_claims.sub
        self.user_claims = user_claims
        
        if requires_otp:
            self.status = AuthSessionStatus.PENDING_OTP
            self.add_domain_event(OTPRequired(
                session_id=self.id,
                user_id=self.user_id
            ))
        else:
            self._complete_authentication()
    
    def otp_validated(self):
        """Called when OTP is successfully validated."""
        if self.status != AuthSessionStatus.PENDING_OTP:
            raise DomainError("Session not awaiting OTP")
        self._complete_authentication()
    
    def fail(self, reason: str):
        """Mark authentication as failed."""
        self.status = AuthSessionStatus.FAILED
        self.failure_reason = reason
        self.add_domain_event(AuthenticationFailed(
            session_id=self.id,
            user_id=self.user_id,
            reason=reason
        ))
    
    def revoke(self):
        """Revoke an active session (logout)."""
        self.status = AuthSessionStatus.REVOKED
        self.add_domain_event(SessionRevoked(session_id=self.id))
    
    def _complete_authentication(self):
        self.status = AuthSessionStatus.AUTHENTICATED
        self.add_domain_event(AuthenticationSucceeded(
            session_id=self.id,
            user_id=self.user_id,
            user_claims=self.user_claims
        ))
```

---

## 4. Application Layer: Commands, Queries, and Sagas

### 4.1 Commands & Handlers

```python
from cqrs_ddd.core import Command, CommandHandler, CommandResponse
from cqrs_ddd.middleware import middleware

# ═══════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════

@dataclass
class AuthenticateWithCredentials(Command):
    """
    Initiate authentication with username/password.
    
    Note: Token delivery format (header vs cookie) is determined by the
    framework adapter based on TokenSource, not by this command.
    """
    username: str
    password: str
    otp_method: Optional[str] = None
    otp_code: Optional[str] = None
    required_roles: Optional[list[str]] = None  # User must have ALL of these (if specified)

@dataclass
class ValidateOTP(Command):
    """Validate OTP for pending session."""
    session_id: str
    otp_code: str

@dataclass
class RefreshTokens(Command):
    """Refresh expired access token."""
    refresh_token: str

@dataclass
class Logout(Command):
    """Terminate user session."""
    refresh_token: Optional[str] = None

# ═══════════════════════════════════════════════════════════════
# HANDLERS
# ═══════════════════════════════════════════════════════════════

@middleware.log()
@middleware.persist_events()
class AuthenticateWithCredentialsHandler(CommandHandler):
    """
    Handles the complete authentication flow.
    
    1. Validate credentials with IdP (Keycloak)
    2. Optionally check required roles/groups
    3. Check if user requires 2FA
    4. If OTP required: issue challenge
    5. If OTP provided: validate and complete
    6. Return tokens or challenge
    
    Note: Token delivery (header vs cookie) is handled by the framework
    adapter layer, not by this handler.
    """
    
    def __init__(
        self,
        idp_adapter: IdentityProviderPort,
        otp_service: OTPServicePort,
        session_repo: AuthSessionRepository,
        token_issuer: TokenIssuerPort,
    ):
        self.idp = idp_adapter
        self.otp = otp_service
        self.sessions = session_repo
        self.tokens = token_issuer
    
    async def handle(self, cmd: AuthenticateWithCredentials) -> CommandResponse[AuthResult]:
        # 1. Create auth session (transport-agnostic)
        ctx = request_context.get()
        session = AuthSession.create(
            ip_address=ctx.metadata.get("ip_address", "unknown"),
            user_agent=ctx.metadata.get("user_agent", "unknown")
        )
        
        # 2. Validate with IdP
        try:
            token_response = await self.idp.authenticate(
                username=cmd.username,
                password=cmd.password
            )
            user_claims = await self.idp.decode_token(token_response.access_token)
        except InvalidCredentialsError:
            session.fail("Invalid credentials")
            return CommandResponse(
                result=AuthResult.failed("Invalid credentials"),
                events=session.clear_domain_events()
            )
        
        # 3. Optional: Check required roles/groups
        if cmd.required_roles:
            missing = self._get_missing_roles(cmd.required_roles, user_claims)
            if missing:
                session.fail(f"Missing required roles: {missing}")
                return CommandResponse(
                    result=AuthResult.failed("Unauthorized"),
                    events=session.clear_domain_events()
                )
        
        # 4. Check if OTP required
        requires_otp = await self.otp.is_required_for_user(user_claims)
        session.credentials_validated(user_claims, requires_otp)
        
        if requires_otp and not cmd.otp_code:
            # Issue OTP challenge
            available_methods = await self.otp.get_available_methods(user_claims)
            
            if cmd.otp_method:
                await self.otp.send_challenge(user_claims, cmd.otp_method)
            
            return CommandResponse(
                result=AuthResult.otp_required(
                    session_id=session.id,
                    methods=available_methods
                ),
                events=session.clear_domain_events()
            )
        
        if requires_otp and cmd.otp_code:
            # Validate OTP
            is_valid = await self.otp.validate(
                user_claims, cmd.otp_method, cmd.otp_code
            )
            if not is_valid:
                session.fail("Invalid OTP")
                return CommandResponse(
                    result=AuthResult.failed("Invalid OTP"),
                    events=session.clear_domain_events()
                )
            session.otp_validated()
        
        # 5. Issue tokens
        tokens = await self.tokens.issue(
            user_claims=user_claims,
            session_id=session.id,
            token_response=token_response
        )
        
        return CommandResponse(
            result=AuthResult.success(tokens),
            events=session.clear_domain_events()
        )
    
    def _get_missing_roles(self, required: list[str], claims: UserClaims) -> list[str]:
        """
        Check which required roles the user is missing.
        Works with both roles and groups (since they're unified in UserClaims.role_names).
        """
        user_roles = set(claims.role_names)
        return [r for r in required if r not in user_roles]
```

### 4.2 Queries & Handlers

```python
from cqrs_ddd.core import Query, QueryHandler, QueryResponse

@dataclass
class GetUserInfo(Query):
    """Get current user info with type-level permissions."""
    pass

@dataclass
class GetAvailableOTPMethods(Query):
    """Get OTP methods available for current user."""
    pass

class GetUserInfoHandler(QueryHandler):
    """
    Returns user claims and type-level permissions.
    Demonstrates integration with ABAC engine.
    """
    
    def __init__(self, abac_client: ABACAuthorizationPort):
        self.abac = abac_client
    
    async def handle(self, query: GetUserInfo) -> QueryResponse[UserInfoResult]:
        identity = get_identity()
        access_token = get_access_token()
        
        if not identity.is_authenticated:
            raise AuthenticationError("Not authenticated")
        
        # Fetch type-level permissions from ABAC
        permissions = {}
        if access_token:
            resource_types = await self.abac.list_resource_types()
            permissions = await self.abac.get_type_level_permissions(
                access_token=access_token,
                resource_types=resource_types
            )
        
        return QueryResponse(result=UserInfoResult(
            user_id=identity.user_id,
            username=identity.username,
            groups=identity.groups,
            permissions=permissions
        ))
```

### 4.3 Authentication Saga (Multi-Step 2FA)

For complex authentication flows that span multiple requests (e.g., step-up authentication):

```python
from cqrs_ddd.saga import Saga, saga_step, SagaContext

class StepUpAuthenticationSaga(Saga):
    """
    Handles step-up authentication for sensitive operations.
    
    Flow:
    1. Sensitive operation requested → Issue OTP challenge
    2. OTP validated → Grant temporary elevated access
    3. Operation completed OR timeout → Revoke elevation
    """
    
    @saga_step(SensitiveOperationRequested)
    async def on_sensitive_operation_requested(self, event: SensitiveOperationRequested):
        self.context.state["operation_id"] = event.operation_id
        self.context.state["user_id"] = event.user_id
        self.context.state["required_action"] = event.action
        
        self.dispatch_command(IssueOTPChallenge(
            user_id=event.user_id,
            reason=f"Confirm {event.action}"
        ))
    
    @saga_step(OTPChallengeValidated)
    async def on_otp_validated(self, event: OTPChallengeValidated):
        if event.user_id != self.context.state["user_id"]:
            return  # Not our saga
        
        self.dispatch_command(GrantTemporaryElevation(
            user_id=event.user_id,
            action=self.context.state["required_action"],
            ttl_seconds=300
        ))
        
        self.dispatch_command(ResumeSensitiveOperation(
            operation_id=self.context.state["operation_id"]
        ))
    
    @saga_step(SensitiveOperationCompleted)
    async def on_operation_completed(self, event: SensitiveOperationCompleted):
        self.dispatch_command(RevokeElevation(
            user_id=self.context.state["user_id"]
        ))
        self.complete()
    
    async def compensate(self):
        """Revoke elevation if saga fails."""
        if "user_id" in self.context.state:
            self.dispatch_command(RevokeElevation(
                user_id=self.context.state["user_id"]
            ))
```

---

## 5. Infrastructure Layer: Ports & Adapters

### 5.1 Ports (Interfaces)

```python
from typing import Protocol

class IdentityProviderPort(Protocol):
    """Port for identity provider operations."""
    
    async def authenticate(self, username: str, password: str) -> TokenResponse:
        """Authenticate with username/password."""
        ...
    
    async def refresh(self, refresh_token: str) -> TokenResponse:
        """Refresh access token."""
        ...
    
    async def decode_token(self, access_token: str) -> UserClaims:
        """Decode and validate JWT."""
        ...
    
    async def logout(self, refresh_token: str) -> None:
        """Terminate IdP session."""
        ...

class OTPServicePort(Protocol):
    """Port for OTP operations."""
    
    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """Check if user requires 2FA."""
        ...
    
    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """Get OTP methods available for user."""
        ...
    
    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """Send OTP via specified method. Returns challenge ID."""
        ...
    
    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate OTP code."""
        ...

class ABACAuthorizationPort(Protocol):
    """Port for ABAC authorization checks."""
    
    async def check_access(
        self,
        access_token: str,
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None
    ) -> list[str]:
        """Check which resources user can access. Returns authorized IDs."""
        ...
    
    async def get_permitted_actions(
        self,
        access_token: str,
        resource_type: str,
        resource_ids: list[str]
    ) -> dict[str, list[str]]:
        """Get permitted actions per resource."""
        ...
    
    async def list_resource_types(self) -> list[str]:
        """List all resource types."""
        ...
```

### 5.2 Adapters (Implementations)

```python
# ═══════════════════════════════════════════════════════════════
# KEYCLOAK ADAPTER
# ═══════════════════════════════════════════════════════════════

class KeycloakIdentityProvider(IdentityProviderPort):
    """Keycloak implementation of IdentityProviderPort."""
    
    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
    ):
        self.keycloak = KeycloakOpenID(
            server_url=server_url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=client_secret
        )
    
    async def authenticate(self, username: str, password: str) -> TokenResponse:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "username": username,
                    "password": password,
                }
            )
            if response.status_code != 200:
                raise InvalidCredentialsError()
            return TokenResponse(**response.json())
    
    async def decode_token(self, access_token: str) -> UserClaims:
        # Validate signature against Keycloak's public key
        decoded = self.keycloak.decode_token(
            access_token,
            options={"verify_signature": True}
        )
        return UserClaims(
            sub=decoded["sub"],
            username=decoded.get("preferred_username", decoded["sub"]),
            email=decoded.get("email", ""),
            groups=tuple(decoded.get("groups", [])),
            attributes=decoded
        )

# ═══════════════════════════════════════════════════════════════
# ABAC ENGINE ADAPTER
# ═══════════════════════════════════════════════════════════════

class ABACEngineClient(ABACAuthorizationPort):
    """Adapter for Stateful ABAC Policy Engine."""
    
    def __init__(self, base_url: str, realm: str):
        self.base_url = base_url
        self.realm = realm
        self._client: Optional[FWSAuthClient] = None
    
    async def check_access(
        self,
        access_token: str,
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None
    ) -> list[str]:
        client = await self._get_client()
        client.set_token(access_token)
        
        response = await client.auth.check_access(
            resources=[CheckAccessItem(
                resource_type_name=resource_type,
                action_name=action,
                external_resource_ids=resource_ids,
                return_type="id_list" if resource_ids else "decision"
            )]
        )
        
        if response and response.results:
            answer = response.results[0].answer
            if isinstance(answer, list):
                return answer
            elif answer is True:
                return resource_ids or []
        return []

# ═══════════════════════════════════════════════════════════════
# TOTP SERVICE ADAPTER (using pyotp)
# ═══════════════════════════════════════════════════════════════

class TOTPService(OTPServicePort):
    """
    TOTP implementation using pyotp for authenticator app-based 2FA.
    
    Supports Google Authenticator, Authy, Microsoft Authenticator, etc.
    """
    
    def __init__(
        self,
        secret_repository: TOTPSecretRepository,
        issuer_name: str = "MyApp",
        valid_window: int = 1,
    ):
        self.secrets = secret_repository
        self.issuer_name = issuer_name
        self.valid_window = valid_window
    
    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """Check if user has TOTP enabled."""
        secret = await self.secrets.get_by_user_id(claims.sub)
        return secret is not None
    
    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """TOTP only supports 'totp' method."""
        secret = await self.secrets.get_by_user_id(claims.sub)
        return ["totp"] if secret else []
    
    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """
        TOTP doesn't require sending a challenge.
        The code is generated on the user's device.
        """
        # No-op for TOTP - code is already on user's authenticator app
        return "totp-challenge"
    
    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate a TOTP code from the user's authenticator app."""
        import pyotp
        
        secret = await self.secrets.get_by_user_id(claims.sub)
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret.secret)
        return totp.verify(code, valid_window=self.valid_window)
    
    async def setup_totp(self, claims: UserClaims) -> tuple[TOTPSecret, str]:
        """
        Generate a new TOTP secret for a user.
        
        Returns:
            Tuple of (TOTPSecret, provisioning_uri for QR code)
        """
        import pyotp
        
        secret = TOTPSecret.generate()
        totp = pyotp.TOTP(secret.secret)
        uri = totp.provisioning_uri(name=claims.email, issuer_name=self.issuer_name)
        
        # Store the secret
        await self.secrets.save(claims.sub, secret)
        
        return secret, uri
    
    async def verify_setup(self, claims: UserClaims, code: str) -> bool:
        """
        Verify the initial TOTP code during setup.
        
        This confirms the user has correctly configured their authenticator.
        """
        return await self.validate(claims, "totp", code)


class TOTPSecretRepository(Protocol):
    """Repository for storing user TOTP secrets."""
    
    async def get_by_user_id(self, user_id: str) -> Optional[TOTPSecret]:
        """Get TOTP secret for a user."""
        ...
    
    async def save(self, user_id: str, secret: TOTPSecret) -> None:
        """Save TOTP secret for a user."""
        ...
    
    async def delete(self, user_id: str) -> None:
        """Remove TOTP secret (disable 2FA)."""
        ...


# ═══════════════════════════════════════════════════════════════
# EMAIL OTP SERVICE ADAPTER (using pyotp)
# ═══════════════════════════════════════════════════════════════

class EmailOTPService(OTPServicePort):
    """
    Email-based OTP implementation using pyotp.
    
    Generates a TOTP code and sends it via email. The code is valid
    for a configurable time window (default: 2 minutes).
    """
    
    def __init__(
        self,
        otp_repository: OTPChallengeRepository,
        email_sender: EmailSenderPort,
        token_length: int = 6,
        expiration_seconds: int = 120,
        app_name: str = "MyApp",
    ):
        self.otp_repo = otp_repository
        self.email_sender = email_sender
        self.token_length = token_length
        self.expiration_seconds = expiration_seconds
        self.app_name = app_name
    
    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """Email OTP is available if user has a verified email."""
        return bool(claims.email)
    
    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """Return email method if user has email."""
        return ["email"] if claims.email else []
    
    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """Generate and send OTP code via email."""
        import pyotp
        from datetime import datetime, timedelta, timezone
        
        # Generate secret and code
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, digits=self.token_length, interval=self.expiration_seconds)
        code = totp.now()
        
        # Store challenge
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.expiration_seconds)
        await self.otp_repo.save_challenge(
            user_id=claims.sub,
            method="email",
            secret=secret,
            expires_at=expires_at
        )
        
        # Send email
        await self.email_sender.send(
            to=claims.email,
            subject=f"{self.app_name} - Your Verification Code",
            body=f"Your verification code is: {code}\n\nThis code expires in {self.expiration_seconds // 60} minutes."
        )
        
        # Return obfuscated email for UI display
        return f"Code sent to {self._obfuscate_email(claims.email)}"
    
    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate the emailed OTP code."""
        import pyotp
        from datetime import datetime, timezone
        
        challenge = await self.otp_repo.get_challenge(claims.sub, "email")
        if not challenge:
            return False
        
        # Check expiration
        if datetime.now(timezone.utc) > challenge.expires_at:
            return False
        
        # Validate with pyotp
        interval = int((challenge.expires_at - challenge.created_at).total_seconds())
        totp = pyotp.TOTP(challenge.secret, digits=len(code), interval=interval)
        
        if totp.verify(code, valid_window=1):
            await self.otp_repo.mark_used(claims.sub, "email")
            return True
        
        await self.otp_repo.increment_attempts(claims.sub, "email")
        return False
    
    def _obfuscate_email(self, email: str) -> str:
        """Obfuscate email for display: j****@example.com"""
        local, domain = email.split("@")
        obfuscated = local[0] + "****" if len(local) > 1 else local + "****"
        return f"{obfuscated}@{domain}"


# ═══════════════════════════════════════════════════════════════
# SMS OTP SERVICE ADAPTER (using pyotp)
# ═══════════════════════════════════════════════════════════════

class SMSOTPService(OTPServicePort):
    """
    SMS-based OTP implementation using pyotp.
    
    Generates a TOTP code and sends it via SMS. The code is valid
    for a configurable time window (default: 2 minutes).
    """
    
    def __init__(
        self,
        otp_repository: OTPChallengeRepository,
        sms_sender: SMSSenderPort,
        token_length: int = 6,
        expiration_seconds: int = 120,
        app_name: str = "MyApp",
    ):
        self.otp_repo = otp_repository
        self.sms_sender = sms_sender
        self.token_length = token_length
        self.expiration_seconds = expiration_seconds
        self.app_name = app_name
    
    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """SMS OTP is available if user has a verified phone number."""
        return bool(claims.attributes.get("phone_number"))
    
    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """Return sms method if user has phone number."""
        return ["sms"] if claims.attributes.get("phone_number") else []
    
    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """Generate and send OTP code via SMS."""
        import pyotp
        from datetime import datetime, timedelta, timezone
        
        phone = claims.attributes.get("phone_number")
        if not phone:
            raise ValueError("User has no phone number configured")
        
        # Generate secret and code
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, digits=self.token_length, interval=self.expiration_seconds)
        code = totp.now()
        
        # Store challenge
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.expiration_seconds)
        await self.otp_repo.save_challenge(
            user_id=claims.sub,
            method="sms",
            secret=secret,
            expires_at=expires_at
        )
        
        # Send SMS
        await self.sms_sender.send(
            to=phone,
            message=f"Your {self.app_name} code is: {code}"
        )
        
        # Return obfuscated phone for UI display
        return f"Code sent to {self._obfuscate_phone(phone)}"
    
    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate the SMS OTP code."""
        import pyotp
        from datetime import datetime, timezone
        
        challenge = await self.otp_repo.get_challenge(claims.sub, "sms")
        if not challenge:
            return False
        
        # Check expiration
        if datetime.now(timezone.utc) > challenge.expires_at:
            return False
        
        # Validate with pyotp
        interval = int((challenge.expires_at - challenge.created_at).total_seconds())
        totp = pyotp.TOTP(challenge.secret, digits=len(code), interval=interval)
        
        if totp.verify(code, valid_window=1):
            await self.otp_repo.mark_used(claims.sub, "sms")
            return True
        
        await self.otp_repo.increment_attempts(claims.sub, "sms")
        return False
    
    def _obfuscate_phone(self, phone: str) -> str:
        """Obfuscate phone for display: +1***-**56"""
        if len(phone) <= 4:
            return "****"
        return phone[:3] + "***-**" + phone[-2:]


# ═══════════════════════════════════════════════════════════════
# COMMON PORTS FOR OTP SERVICES
# ═══════════════════════════════════════════════════════════════

@dataclass
class OTPChallenge:
    """Stored OTP challenge record."""
    user_id: str
    method: str
    secret: str
    created_at: datetime
    expires_at: datetime
    attempts: int = 0
    status: str = "pending"  # pending, used, expired


class OTPChallengeRepository(Protocol):
    """Repository for storing OTP challenges (email/SMS)."""
    
    async def save_challenge(
        self, user_id: str, method: str, secret: str, expires_at: datetime
    ) -> None:
        """Save a new OTP challenge."""
        ...
    
    async def get_challenge(self, user_id: str, method: str) -> Optional[OTPChallenge]:
        """Get active OTP challenge for user."""
        ...
    
    async def mark_used(self, user_id: str, method: str) -> None:
        """Mark challenge as used after successful validation."""
        ...
    
    async def increment_attempts(self, user_id: str, method: str) -> None:
        """Increment failed attempts counter."""
        ...


class EmailSenderPort(Protocol):
    """Port for sending emails."""
    
    async def send(self, to: str, subject: str, body: str) -> None:
        """Send an email."""
        ...


class SMSSenderPort(Protocol):
    """Port for sending SMS messages."""
    
    async def send(self, to: str, message: str) -> None:
        """Send an SMS."""
        ...
```

---

## 6. Authorization Middleware

Authorization is implemented as **toolkit middleware** that integrates with the ABAC engine.

### 6.1 AuthorizationMiddleware

```python
from cqrs_ddd.middleware import Middleware

class AuthorizationMiddleware(Middleware):
    """
    CQRS middleware for fine-grained authorization.
    
    Modes:
    - Pre-execution: Check before handler runs, fail fast
    - Post-execution: Run handler, then filter results
    
    Resolution Order:
    1. Type-level public check (is_public flag)
    2. Type-level ACL (resource_id=NULL)
    3. Resource-level ACL (specific IDs)
    """
    
    def __init__(
        self,
        abac: ABACAuthorizationPort,
        resource_type: str | None = None,
        resource_type_attr: str | None = None,
        resource_id_attr: str | None = None,
        required_permissions: list[str] = None,
        filter_result_attr: str | None = None,
    ):
        self.abac = abac
        self.resource_type = resource_type
        self.resource_type_attr = resource_type_attr
        self.resource_id_attr = resource_id_attr
        self.required_permissions = required_permissions or []
        self.filter_result_attr = filter_result_attr
    
    def apply(self, handler_func, command):
        async def wrapped(*args, **kwargs):
            identity = get_identity()
            access_token = get_access_token()
            
            # Skip for system identity
            if identity.is_system:
                return await handler_func(*args, **kwargs)
            
            # Resolve resource type
            resource_type = self._resolve_resource_type(command)
            
            if self.filter_result_attr:
                # Post-execution filtering
                return await self._filter_result(
                    handler_func, args, kwargs,
                    resource_type, access_token
                )
            else:
                # Pre-execution check
                return await self._check_access(
                    handler_func, args, kwargs, command,
                    resource_type, access_token
                )
        
        return wrapped
    
    async def _check_access(self, handler_func, args, kwargs, command, resource_type, token):
        """Pre-execution authorization check."""
        resource_ids = self._resolve_resource_ids(command)
        
        for permission in self.required_permissions:
            authorized_ids = await self.abac.check_access(
                access_token=token,
                action=permission,
                resource_type=resource_type,
                resource_ids=resource_ids
            )
            
            if resource_ids and not all(rid in authorized_ids for rid in resource_ids):
                raise AuthorizationError(f"Access denied for {permission} on {resource_type}")
        
        return await handler_func(*args, **kwargs)
    
    async def _filter_result(self, handler_func, args, kwargs, resource_type, token):
        """Post-execution result filtering."""
        result = await handler_func(*args, **kwargs)
        
        # Extract candidates from result
        candidates = self._get_attr_by_path(result, self.filter_result_attr)
        if not candidates:
            return result
        
        # Check per-permission
        allowed_ids = set(candidates)
        for permission in self.required_permissions:
            authorized = await self.abac.check_access(
                access_token=token,
                action=permission,
                resource_type=resource_type,
                resource_ids=list(allowed_ids)
            )
            allowed_ids &= set(authorized)
        
        # Filter result
        filtered = [c for c in candidates if c in allowed_ids]
        self._set_attr_by_path(result, self.filter_result_attr, filtered)
        
        return result
```

### 6.2 PermittedActionsMiddleware

```python
class PermittedActionsMiddleware(Middleware):
    """
    Enrich query results with permitted actions per entity.
    
    After the query handler runs, this middleware fetches what actions
    the current user can perform on each returned entity and attaches
    a 'permitted_actions' attribute.
    """
    
    def __init__(
        self,
        abac: ABACAuthorizationPort,
        result_entities_attr: str,
        resource_type_attr: str | None = None,
        entity_id_attr: str = "id",
    ):
        self.abac = abac
        self.result_entities_attr = result_entities_attr
        self.resource_type_attr = resource_type_attr
        self.entity_id_attr = entity_id_attr
    
    def apply(self, handler_func, command):
        async def wrapped(*args, **kwargs):
            result = await handler_func(*args, **kwargs)
            
            entities = self._get_attr_by_path(result, self.result_entities_attr)
            if not entities:
                return result
            
            access_token = get_access_token()
            if not access_token:
                return result
            
            # Group entities by resource type
            by_type = self._group_by_type(entities)
            
            # Fetch permitted actions per type
            for resource_type, type_entities in by_type.items():
                entity_ids = [self._get_id(e) for e in type_entities]
                
                actions_map = await self.abac.get_permitted_actions(
                    access_token=access_token,
                    resource_type=resource_type,
                    resource_ids=entity_ids
                )
                
                # Attach to entities
                for entity in type_entities:
                    eid = self._get_id(entity)
                    entity.permitted_actions = actions_map.get(eid, [])
            
            return result
        
        return wrapped
```

---

## 7. Framework Adapters

Framework adapters are **thin bridges** that extract identity and inject it into the toolkit's context. They delegate all logic to the domain layer.

### 7.1 FastAPI

```python
from fastapi import Depends, Request
from cqrs_ddd_auth.context import RequestContext, request_context

def create_auth_dependency(
    idp: IdentityProviderPort,
    cookie_name: str = "access_token",
    header_name: str = "Authorization"
):
    """
    Factory for FastAPI auth dependency.
    Extracts token, validates, and sets up context.
    """
    
    async def get_identity(request: Request) -> Identity:
        # Extract token (header or cookie)
        token = _extract_token(request, cookie_name, header_name)
        
        if not token:
            return AnonymousIdentity()
        
        try:
            claims = await idp.decode_token(token)
            identity = claims.to_identity()
        except InvalidTokenError:
            return AnonymousIdentity()
        
        # Set up request context
        ctx = RequestContext(
            identity=identity,
            correlation_id=request.headers.get("X-Correlation-ID", str(uuid.uuid4())),
            access_token=token,
            metadata={
                "ip_address": request.client.host,
                "user_agent": request.headers.get("user-agent", "")
            }
        )
        request_context.set(ctx)
        
        return identity
    
    return get_identity

# Usage in FastAPI
from cqrs_ddd_auth.contrib.fastapi import create_auth_router

auth_router = create_auth_router(
    idp=keycloak_adapter,
    otp_service=otp_service,
    mediator=mediator,
)

app.include_router(auth_router, prefix="/auth")
```

### 7.2 Django (ASGI Middleware)

```python
@async_only_middleware
class AuthenticationMiddleware:
    """
    Django ASGI middleware that extracts identity and sets context.
    All authentication logic is delegated to the domain layer.
    """
    
    def __init__(self, get_response, idp: IdentityProviderPort):
        self.get_response = get_response
        self.idp = idp
    
    async def __call__(self, request):
        # Skip public paths
        if self._is_public(request.path):
            return await self.get_response(request)
        
        # Extract token
        token = self._extract_token(request)
        
        # Decode and validate
        if token:
            try:
                claims = await self.idp.decode_token(token)
                identity = claims.to_identity()
            except InvalidTokenError:
                identity = AnonymousIdentity()
        else:
            identity = AnonymousIdentity()
        
        # Set request context
        ctx = RequestContext(
            identity=identity,
            correlation_id=request.headers.get("X-Correlation-ID", str(uuid.uuid4())),
            access_token=token
        )
        request_context.set(ctx)
        
        return await self.get_response(request)
```

---

## 8. Transparent Token Refresh

Token refresh should be **invisible to the application layer**—expired tokens are automatically refreshed before reaching handlers.

### 8.1 Command: RefreshTokens

```python
@dataclass
class RefreshTokens(Command):
    """Refresh expired access token using refresh token."""
    refresh_token: str

@middleware.log()
class RefreshTokensHandler(CommandHandler):
    """
    Refreshes tokens via the identity provider.
    Emits TokenRefreshed event for audit trail.
    """
    
    def __init__(self, idp: IdentityProviderPort):
        self.idp = idp
    
    async def handle(self, cmd: RefreshTokens) -> CommandResponse[TokenResult]:
        try:
            new_tokens = await self.idp.refresh(cmd.refresh_token)
            claims = await self.idp.decode_token(new_tokens.access_token)
            
            return CommandResponse(
                result=TokenResult(
                    access_token=new_tokens.access_token,
                    refresh_token=new_tokens.refresh_token,
                    expires_in=new_tokens.expires_in,
                    user_claims=claims
                ),
                events=[TokenRefreshed(user_id=claims.sub)]
            )
        except InvalidRefreshTokenError:
            return CommandResponse(
                result=TokenResult.expired(),
                events=[TokenRefreshFailed(reason="Invalid refresh token")]
            )
```

### 8.2 Token Source & Extraction

Instead of a custom `X-Client-Type` header, **auto-detect** where tokens came from and respond via the same channel:

```python
from enum import Enum

class TokenSource(Enum):
    """Where tokens were extracted from—determines response format."""
    HEADER = "header"   # Authorization header → respond with headers
    COOKIE = "cookie"   # httpOnly cookie → respond with cookies

@dataclass
class TokenExtractionResult:
    """Result of extracting tokens from request."""
    access_token: str | None = None
    refresh_token: str | None = None
    source: TokenSource | None = None
    
    @property
    def is_present(self) -> bool:
        return self.access_token is not None
```

### 8.3 Token Refresh Adapter

Framework-agnostic logic—**no client_type concept**, just pure token handling:

```python
@dataclass
class TokenRefreshResult:
    """Result of token refresh check."""
    needs_auth: bool = False           # User must re-authenticate
    current_token: str | None = None   # No refresh needed, use this token
    new_access_token: str | None = None
    new_refresh_token: str | None = None
    user_claims: UserClaims | None = None

class TokenRefreshAdapter:
    """
    Framework-agnostic token refresh logic.
    Framework middlewares delegate to this adapter.
    """
    
    def __init__(self, mediator: Mediator):
        self.mediator = mediator
    
    async def process_request(
        self,
        access_token: str | None,
        refresh_token: str | None,
    ) -> TokenRefreshResult:
        """
        Check if refresh is needed and perform it transparently.
        
        Returns:
            TokenRefreshResult with new tokens or indication to re-auth
        """
        if not access_token or not refresh_token:
            return TokenRefreshResult(needs_auth=True)
        
        # Check expiration without full signature validation
        if not self._is_expired(access_token):
            return TokenRefreshResult(current_token=access_token)
        
        # Refresh via Command (goes through full CQRS pipeline)
        result = await self.mediator.send(RefreshTokens(refresh_token=refresh_token))
        
        if result.result.expired:
            return TokenRefreshResult(needs_auth=True)
        
        return TokenRefreshResult(
            new_access_token=result.result.access_token,
            new_refresh_token=result.result.refresh_token,
            user_claims=result.result.user_claims
        )
    
    def _is_expired(self, token: str, buffer_seconds: int = 30) -> bool:
        """
        Decode token WITHOUT signature verification to check expiration.
        Returns True if token expires within buffer_seconds.
        """
        import jwt
        from datetime import datetime
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get("exp", 0)
            return exp < (datetime.utcnow().timestamp() + buffer_seconds)
        except Exception:
            return True  # Treat decode errors as expired
```

### 8.4 Framework Integration: Django

```python
@async_only_middleware
class TokenRefreshMiddleware:
    """
    Django ASGI middleware for transparent token refresh.
    
    Auto-detects token source (header vs cookie) and responds accordingly.
    No custom headers required from clients.
    """
    
    def __init__(self, get_response, refresh_adapter: TokenRefreshAdapter):
        self.get_response = get_response
        self.adapter = refresh_adapter
    
    async def __call__(self, request):
        if self._is_public(request.path):
            return await self.get_response(request)
        
        # Auto-detect: extract tokens and remember where they came from
        tokens = self._extract_tokens(request)
        
        if not tokens.is_present:
            # No tokens found, let auth middleware handle 401
            return await self.get_response(request)
        
        # Delegate to adapter (no client_type needed)
        result = await self.adapter.process_request(
            tokens.access_token,
            tokens.refresh_token
        )
        
        if result.needs_auth:
            return JsonResponse({"error": "Unauthorized"}, status=401)
        
        if result.new_access_token:
            # Inject refreshed token for downstream middleware
            self._inject_token(request, result.new_access_token)
            
            # Process request with fresh token
            response = await self.get_response(request)
            
            # Return tokens via the same channel they arrived
            self._attach_tokens(response, result, tokens.source)
            return response
        
        return await self.get_response(request)
    
    def _extract_tokens(self, request) -> TokenExtractionResult:
        """
        Extract tokens and detect their source.
        Priority: Header > Cookie
        """
        # 1. Check Authorization header first (API/mobile clients)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return TokenExtractionResult(
                access_token=auth_header[7:],
                refresh_token=request.headers.get("X-Refresh-Token"),
                source=TokenSource.HEADER
            )
        
        # 2. Fall back to cookies (web clients)
        access = request.COOKIES.get("access_token")
        if access:
            return TokenExtractionResult(
                access_token=access,
                refresh_token=request.COOKIES.get("refresh_token"),
                source=TokenSource.COOKIE
            )
        
        return TokenExtractionResult()
    
    def _inject_token(self, request, token: str):
        """Inject refreshed token for downstream KeycloakMiddleware."""
        request._refreshed_access_token = token
    
    def _attach_tokens(self, response, result: TokenRefreshResult, source: TokenSource):
        """Return tokens via the same channel they arrived."""
        if source == TokenSource.HEADER:
            # API/mobile: Return in response headers
            response["X-New-Access-Token"] = result.new_access_token
            response["X-New-Refresh-Token"] = result.new_refresh_token
        else:
            # Web: Set httpOnly cookies
            response.set_cookie(
                "access_token",
                result.new_access_token,
                httponly=True,
                secure=settings.AUTH_COOKIE_SECURE,
                samesite=settings.AUTH_COOKIE_SAMESITE,
                max_age=settings.AUTH_COOKIE_MAX_AGE
            )
            response.set_cookie(
                "refresh_token",
                result.new_refresh_token,
                httponly=True,
                secure=settings.AUTH_COOKIE_SECURE,
                samesite=settings.AUTH_COOKIE_SAMESITE,
                max_age=settings.AUTH_COOKIE_MAX_AGE
            )
```

---

## 9. Unified Role Model (Groups as Roles)

Keycloak **groups** and **roles** can be treated interchangeably for authorization. This is configurable per-deployment.

### 9.1 Role Source & Group Path Strategy

```python
from enum import Enum

class RoleSource(Enum):
    """Origin of a role for audit and debugging."""
    REALM_ROLE = "realm_role"      # Keycloak realm role
    CLIENT_ROLE = "client_role"    # Keycloak client-specific role
    GROUP = "group"                 # Keycloak group (treated as role)
    CUSTOM = "custom"               # Application-defined role

class GroupPathStrategy(Enum):
    """
    How to convert Keycloak group paths to role names.
    
    Example group path: /web/admin/editor
    """
    FULL_PATH = "full_path"         # → "web/admin/editor" (default, preserves hierarchy)
    LAST_SEGMENT = "last_segment"   # → "editor" (simple, loses context)
    ALL_SEGMENTS = "all_segments"   # → ["web", "admin", "editor"] (flexible, adds multiple roles)
```

### 9.2 AuthRole Value Object

```python
@dataclass(frozen=True)
class AuthRole(ValueObject):
    """
    Unified role representation that can originate from:
    - Keycloak realm roles
    - Keycloak client roles
    - Keycloak groups (when merge_groups_as_roles=True)
    - Custom application roles
    
    For authorization purposes, the source is irrelevant—
    only the name matters for ACL matching.
    """
    name: str
    source: RoleSource
    attributes: dict = field(default_factory=dict)
    
    @classmethod
    def from_keycloak_role(cls, data: dict) -> "AuthRole":
        return cls(
            name=data["name"],
            source=RoleSource.REALM_ROLE,
            attributes=data.get("attributes", {})
        )
    
    @classmethod
    def from_keycloak_group(
        cls,
        group_path: str,
        strategy: GroupPathStrategy,
        prefix: str = ""
    ) -> list["AuthRole"]:
        """
        Convert Keycloak group path to one or more roles.
        
        Args:
            group_path: Full group path, e.g., "/web/admin/editor"
            strategy: How to handle the path
            prefix: Optional prefix for role names
        
        Returns:
            List of AuthRole objects (usually 1, but may be multiple for ALL_SEGMENTS)
        """
        path = group_path.strip("/")
        segments = path.split("/") if path else []
        
        if not segments:
            return []
        
        roles = []
        
        if strategy == GroupPathStrategy.FULL_PATH:
            # /web/admin/editor → "web/admin/editor"
            name = f"{prefix}{path}" if prefix else path
            roles.append(cls(name=name, source=RoleSource.GROUP))
        
        elif strategy == GroupPathStrategy.LAST_SEGMENT:
            # /web/admin/editor → "editor"
            name = f"{prefix}{segments[-1]}" if prefix else segments[-1]
            roles.append(cls(name=name, source=RoleSource.GROUP))
        
        elif strategy == GroupPathStrategy.ALL_SEGMENTS:
            # /web/admin/editor → ["web", "admin", "editor"]
            for segment in segments:
                name = f"{prefix}{segment}" if prefix else segment
                roles.append(cls(name=name, source=RoleSource.GROUP))
        
        return roles
```

### 9.3 Enhanced UserClaims with Group Merging

```python
@dataclass(frozen=True)
class UserClaims(ValueObject):
    """
    Decoded JWT claims with unified role handling.
    Groups can be merged as roles based on configuration.
    """
    sub: str
    username: str
    email: str
    roles: tuple[AuthRole, ...]  # Merged from realm_roles + groups
    attributes: dict
    
    @classmethod
    def from_keycloak_token(
        cls,
        decoded: dict,
        merge_groups_as_roles: bool = True,
        group_path_strategy: GroupPathStrategy = GroupPathStrategy.FULL_PATH,
        group_prefix: str = ""
    ) -> "UserClaims":
        """
        Parse Keycloak JWT token into UserClaims.
        
        Args:
            decoded: Decoded JWT payload
            merge_groups_as_roles: If True, groups become authorization roles
            group_path_strategy: How to convert group paths to role names
            group_prefix: Optional prefix for group-derived roles
        
        Examples (with group /web/admin/editor):
            FULL_PATH:    roles=["web/admin/editor"]
            LAST_SEGMENT: roles=["editor"]
            ALL_SEGMENTS: roles=["web", "admin", "editor"]
        """
        roles = []
        
        # 1. Realm roles from realm_access
        realm_access = decoded.get("realm_access", {})
        for role_name in realm_access.get("roles", []):
            roles.append(AuthRole(name=role_name, source=RoleSource.REALM_ROLE))
        
        # 2. Client roles from resource_access (optional)
        resource_access = decoded.get("resource_access", {})
        for client, client_data in resource_access.items():
            for role_name in client_data.get("roles", []):
                roles.append(AuthRole(
                    name=f"{client}:{role_name}",
                    source=RoleSource.CLIENT_ROLE
                ))
        
        # 3. Groups as roles (if configured)
        if merge_groups_as_roles:
            for group_path in decoded.get("groups", []):
                group_roles = AuthRole.from_keycloak_group(
                    group_path,
                    strategy=group_path_strategy,
                    prefix=group_prefix
                )
                roles.extend(group_roles)
        
        return cls(
            sub=decoded["sub"],
            username=decoded.get("preferred_username", decoded["sub"]),
            email=decoded.get("email", ""),
            roles=tuple(roles),
            attributes=decoded
        )
    
    @property
    def role_names(self) -> list[str]:
        """All role names regardless of source."""
        return [r.name for r in self.roles]
    
    @property
    def realm_roles(self) -> list[str]:
        """Only realm roles."""
        return [r.name for r in self.roles if r.source == RoleSource.REALM_ROLE]
    
    @property
    def group_roles(self) -> list[str]:
        """Only group-derived roles."""
        return [r.name for r in self.roles if r.source == RoleSource.GROUP]
    
    def has_role(self, role_name: str, source: RoleSource | None = None) -> bool:
        """Check if user has a role, optionally filtered by source."""
        for role in self.roles:
            if role.name == role_name:
                if source is None or role.source == source:
                    return True
        return False
```

### 9.4 Configuration

```python
@dataclass
class IdentityProviderConfig:
    """Configuration for identity provider integration."""
    server_url: str
    realm: str
    client_id: str
    client_secret: str
    verify_ssl: bool = True
    
    # ═══════ GROUP HANDLING ═══════
    merge_groups_as_roles: bool = True                              # Groups become authorization roles
    group_path_strategy: GroupPathStrategy = GroupPathStrategy.FULL_PATH  # Default: preserve hierarchy
    group_prefix: str = ""                                          # Optional prefix for group roles
```

### 9.5 Usage Examples

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

## 10. User Management via IdP

The toolkit provides **transparent user management** through CQRS commands, with Keycloak (or other IdPs) as the backend.

### 10.1 User Management Commands

```python
# ═══════════════════════════════════════════════════════════════
# CREATE / UPDATE / DELETE
# ═══════════════════════════════════════════════════════════════

@dataclass
class CreateUser(Command):
    """Create a new user in the identity provider."""
    username: str
    email: str
    password: str
    first_name: str = ""
    last_name: str = ""
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    attributes: dict = field(default_factory=dict)
    email_verified: bool = False
    enabled: bool = True

@dataclass
class UpdateUser(Command):
    """Update an existing user's attributes."""
    user_id: str
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    attributes: dict | None = None
    enabled: bool | None = None

@dataclass
class DeleteUser(Command):
    """Delete a user from the identity provider."""
    user_id: str

# ═══════════════════════════════════════════════════════════════
# PASSWORD MANAGEMENT
# ═══════════════════════════════════════════════════════════════

@dataclass
class ResetPassword(Command):
    """Reset a user's password."""
    user_id: str
    new_password: str
    temporary: bool = False  # Force change on next login

@dataclass
class SendPasswordResetEmail(Command):
    """Trigger password reset email via IdP."""
    user_id: str

# ═══════════════════════════════════════════════════════════════
# ROLE & GROUP MANAGEMENT
# ═══════════════════════════════════════════════════════════════

@dataclass
class AssignRoles(Command):
    """Assign realm roles to a user."""
    user_id: str
    roles: list[str]
    replace: bool = False  # True = replace all, False = add

@dataclass
class RemoveRoles(Command):
    """Remove roles from a user."""
    user_id: str
    roles: list[str]

@dataclass
class AssignGroups(Command):
    """Add user to groups."""
    user_id: str
    groups: list[str]  # Group names or paths
    replace: bool = False

@dataclass
class RemoveFromGroups(Command):
    """Remove user from groups."""
    user_id: str
    groups: list[str]
```

### 10.2 User Management Queries

```python
@dataclass
class GetUser(Query):
    """Get user by ID."""
    user_id: str

@dataclass
class GetUserByUsername(Query):
    """Get user by username."""
    username: str

@dataclass
class ListUsers(Query):
    """List users with optional filters."""
    search: str | None = None      # Search in username, email, name
    role: str | None = None        # Filter by role
    group: str | None = None       # Filter by group
    enabled: bool | None = None    # Filter by enabled status
    offset: int = 0
    limit: int = 100

@dataclass
class GetUserRoles(Query):
    """Get all roles assigned to a user."""
    user_id: str
    include_groups: bool = True    # Include group-derived roles

@dataclass
class GetUserGroups(Query):
    """Get all groups a user belongs to."""
    user_id: str
```

### 10.3 Identity Provider Admin Port

```python
class IdentityProviderAdminPort(Protocol):
    """
    Port for administrative identity provider operations.
    Implementations: KeycloakAdminAdapter, Auth0AdminAdapter, etc.
    """
    
    # ═══════ USER CRUD ═══════
    async def create_user(self, user: CreateUserData) -> str:
        """Create user, return user_id."""
        ...
    
    async def get_user(self, user_id: str) -> UserData | None:
        """Get user by ID."""
        ...
    
    async def get_user_by_username(self, username: str) -> UserData | None:
        """Get user by username."""
        ...
    
    async def update_user(self, user_id: str, updates: UpdateUserData) -> None:
        """Update user attributes."""
        ...
    
    async def delete_user(self, user_id: str) -> None:
        """Delete user."""
        ...
    
    async def list_users(self, filters: UserFilters) -> list[UserData]:
        """List users with filters."""
        ...
    
    # ═══════ PASSWORD ═══════
    async def set_password(self, user_id: str, password: str, temporary: bool = False) -> None:
        """Set user password."""
        ...
    
    async def send_password_reset(self, user_id: str) -> None:
        """Trigger password reset email."""
        ...
    
    # ═══════ ROLES ═══════
    async def get_user_roles(self, user_id: str) -> list[RoleData]:
        """Get user's realm roles."""
        ...
    
    async def assign_roles(self, user_id: str, role_names: list[str]) -> None:
        """Assign realm roles to user."""
        ...
    
    async def remove_roles(self, user_id: str, role_names: list[str]) -> None:
        """Remove realm roles from user."""
        ...
    
    # ═══════ GROUPS ═══════
    async def get_user_groups(self, user_id: str) -> list[GroupData]:
        """Get user's groups."""
        ...
    
    async def join_groups(self, user_id: str, group_ids: list[str]) -> None:
        """Add user to groups."""
        ...
    
    async def leave_groups(self, user_id: str, group_ids: list[str]) -> None:
        """Remove user from groups."""
        ...
    
    # ═══════ SYNC ═══════
    async def get_all_roles(self) -> list[RoleData]:
        """Get all realm roles."""
        ...
    
    async def get_all_groups(self) -> list[GroupData]:
        """Get all groups."""
        ...
    
    async def get_all_users(self) -> list[UserData]:
        """Get all users (for sync)."""
        ...
```

### 10.4 Keycloak Admin Adapter

```python
class KeycloakAdminAdapter(IdentityProviderAdminPort):
    """
    Keycloak implementation of admin operations.
    Uses python-keycloak's KeycloakAdmin client.
    """
    
    def __init__(self, config: IdentityProviderConfig):
        self.config = config
        self._admin: KeycloakAdmin | None = None
    
    async def _get_admin(self) -> KeycloakAdmin:
        if not self._admin:
            self._admin = KeycloakAdmin(
                server_url=self.config.server_url,
                client_id=self.config.client_id,
                client_secret_key=self.config.client_secret,
                realm_name=self.config.realm,
                verify=self.config.verify_ssl
            )
        return self._admin
    
    async def create_user(self, user: CreateUserData) -> str:
        admin = await self._get_admin()
        loop = asyncio.get_running_loop()
        
        # Create user in Keycloak
        user_id = await loop.run_in_executor(None, lambda: admin.create_user({
            "username": user.username,
            "email": user.email,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "enabled": user.enabled,
            "emailVerified": user.email_verified,
            "attributes": user.attributes,
            "credentials": [{
                "type": "password",
                "value": user.password,
                "temporary": False
            }]
        }))
        
        # Assign roles if provided
        if user.roles:
            await self.assign_roles(user_id, user.roles)
        
        # Join groups if provided
        if user.groups:
            await self.join_groups(user_id, user.groups)
        
        return user_id
    
    async def assign_roles(self, user_id: str, role_names: list[str]) -> None:
        admin = await self._get_admin()
        loop = asyncio.get_running_loop()
        
        # Get all realm roles to map names to role objects
        all_roles = await loop.run_in_executor(None, admin.get_realm_roles)
        roles_to_assign = [r for r in all_roles if r["name"] in role_names]
        
        if roles_to_assign:
            await loop.run_in_executor(
                None,
                lambda: admin.assign_realm_roles(user_id=user_id, roles=roles_to_assign)
            )
    
    async def join_groups(self, user_id: str, group_names: list[str]) -> None:
        admin = await self._get_admin()
        loop = asyncio.get_running_loop()
        
        # Get all groups to map names to IDs
        all_groups = await loop.run_in_executor(None, admin.get_groups)
        
        for group in all_groups:
            if group["name"] in group_names:
                await loop.run_in_executor(
                    None,
                    lambda g=group: admin.group_user_add(user_id=user_id, group_id=g["id"])
                )
    
    async def list_users(self, filters: UserFilters) -> list[UserData]:
        admin = await self._get_admin()
        loop = asyncio.get_running_loop()
        
        query = {}
        if filters.search:
            query["search"] = filters.search
        if filters.enabled is not None:
            query["enabled"] = filters.enabled
        
        users = await loop.run_in_executor(
            None,
            lambda: admin.get_users(query)
        )
        
        # Post-filter by role/group if needed
        if filters.role:
            users = [u for u in users if await self._user_has_role(u["id"], filters.role)]
        if filters.group:
            users = [u for u in users if await self._user_in_group(u["id"], filters.group)]
        
        return [UserData.from_keycloak(u) for u in users[filters.offset:filters.offset + filters.limit]]
```

### 10.5 Handler Example: CreateUser with ABAC Sync

```python
from stateful_abac_sdk import StatefulABACClient

@middleware.log()
@middleware.persist_events()
class CreateUserHandler(CommandHandler):
    """
    Creates a user in the identity provider.
    Optionally triggers ABAC sync for immediate availability.
    """
    
    def __init__(
        self,
        idp_admin: IdentityProviderAdminPort,
        abac_client: StatefulABACClient | None = None,  # Optional: ABAC SDK client
    ):
        self.idp = idp_admin
        self.abac = abac_client
    
    async def handle(self, cmd: CreateUser) -> CommandResponse[str]:
        # Validate unique username (optional, IdP will also check)
        existing = await self.idp.get_user_by_username(cmd.username)
        if existing:
            raise DomainError(f"Username '{cmd.username}' already exists")
        
        # Create in IdP
        user_id = await self.idp.create_user(CreateUserData(
            username=cmd.username,
            email=cmd.email,
            password=cmd.password,
            first_name=cmd.first_name,
            last_name=cmd.last_name,
            roles=cmd.roles,
            groups=cmd.groups,
            attributes=cmd.attributes,
            enabled=cmd.enabled,
            email_verified=cmd.email_verified
        ))
        
        # Optionally trigger ABAC sync for immediate availability
        # Without this, ABAC's background scheduler will sync eventually
        if self.abac:
            await self.abac.realms.sync()
        
        return CommandResponse(
            result=user_id,
            events=[UserCreated(
                user_id=user_id,
                username=cmd.username,
                email=cmd.email,
                roles=cmd.roles,
                groups=cmd.groups
            )]
        )
```

> **Note**: The ABAC SDK provides `client.realms.sync()` to trigger Keycloak sync on-demand.
> This is optional—if omitted, ABAC's internal scheduler (`SchedulerWorker`) will sync on its
> configured cron schedule. Use on-demand sync for operations that require immediate consistency.

### 10.6 Identity Sync Command (Background)

```python
@dataclass
class SyncIdentityProvider(Command):
    """
    Synchronize identity provider data to local ABAC cache.
    Typically run on a schedule (cron) or triggered manually.
    """
    sync_roles: bool = True
    sync_groups: bool = True
    sync_users: bool = True

@middleware.log()
class SyncIdentityProviderHandler(CommandHandler):
    """
    Syncs roles, groups, and users from IdP to ABAC engine.
    Runs as scheduled background task.
    """
    
    def __init__(
        self,
        idp_admin: IdentityProviderAdminPort,
        role_repo: RoleRepository,
        principal_repo: PrincipalRepository,
        config: IdentityProviderConfig,
    ):
        self.idp = idp_admin
        self.roles = role_repo
        self.principals = principal_repo
        self.config = config
    
    async def handle(self, cmd: SyncIdentityProvider) -> CommandResponse[SyncResult]:
        synced_roles = 0
        synced_groups = 0
        synced_users = 0
        
        # 1. Sync roles
        if cmd.sync_roles:
            roles = await self.idp.get_all_roles()
            for role_data in roles:
                await self.roles.upsert(AuthRole.from_keycloak_role(role_data))
                synced_roles += 1
        
        # 2. Sync groups (as roles if configured)
        if cmd.sync_groups and self.config.sync_groups:
            groups = await self.idp.get_all_groups()
            for group_data in groups:
                await self.roles.upsert(AuthRole.from_keycloak_group(
                    group_data,
                    strip_path=self.config.strip_group_path
                ))
                synced_groups += 1
        
        # 3. Sync users with role assignments
        if cmd.sync_users:
            users = await self.idp.get_all_users()
            for user_data in users:
                # Get user's roles and groups
                user_roles = await self.idp.get_user_roles(user_data["id"])
                user_groups = await self.idp.get_user_groups(user_data["id"]) if self.config.sync_groups else []
                
                # Merge roles and groups
                all_roles = [r["name"] for r in user_roles]
                if self.config.merge_groups_as_roles:
                    all_roles += [g["name"] for g in user_groups]
                
                await self.principals.upsert(Principal(
                    username=user_data["username"],
                    attributes=user_data.get("attributes", {}),
                    roles=all_roles
                ))
                synced_users += 1
        
        return CommandResponse(
            result=SyncResult(
                synced_roles=synced_roles,
                synced_groups=synced_groups,
                synced_users=synced_users
            ),
            events=[IdentityProviderSynced(
                roles=synced_roles,
                groups=synced_groups,
                users=synced_users
            )]
        )
```

---

## 11. Authorization Port Abstraction

The auth library defines an **abstract authorization interface** that can be implemented by any authorization backend. This follows the Ports & Adapters pattern.

### 11.1 Authorization Port (Abstract Interface)

```python
from typing import Protocol
from dataclasses import dataclass

@dataclass
class AccessDecision:
    """Result of an authorization check."""
    allowed: bool
    reason: str | None = None
    permitted_resources: list[str] | None = None  # For id_list return type

@dataclass
class CheckAccessRequest:
    """Request to check access to resources."""
    resource_type: str
    action: str
    resource_ids: list[str] | None = None  # None = check all accessible
    return_type: str = "decision"  # "decision" or "id_list"

class AuthorizationPort(Protocol):
    """
    Abstract authorization interface.
    
    Implementations:
    - StatefulABACAdapter (contrib/stateful_abac)
    - SimpleRBACAdapter (permission list-based)
    - ExternalServiceAdapter (for third-party auth services)
    """
    
    async def check_access(
        self,
        principal_id: str,
        requests: list[CheckAccessRequest],
        context: dict | None = None,
        role_names: list[str] | None = None,
    ) -> list[AccessDecision]:
        """
        Check if principal has access to resources.
        
        Args:
            principal_id: User identifier (usually from JWT sub claim)
            requests: List of access check requests
            context: Optional context data (e.g., location, time)
            role_names: Optional role names for the principal
        
        Returns:
            List of access decisions corresponding to requests
        """
        ...
    
    async def get_permitted_resources(
        self,
        principal_id: str,
        resource_type: str,
        action: str,
        role_names: list[str] | None = None,
    ) -> list[str]:
        """
        Get all resource IDs the principal can access.
        Useful for filtering queries.
        """
        ...
    
    async def get_authorization_filter(
        self,
        principal_id: str,
        resource_type: str,
        action: str,
        role_names: list[str] | None = None,
        context: dict | None = None,
    ) -> "AuthorizationFilter":
        """
        Get authorization conditions as a SearchQuery for merging.
        
        This enables single-query authorization: instead of fetching all IDs
        and then filtering via ABAC, the authorization filter is returned as
        a SearchQuery that can be merged with the user's search query.
        
        The adapter fetches JSON condition DSL from ABAC and converts it
        to a SearchQuery using the FieldMapping configured at initialization.
        
        Args:
            principal_id: User identifier
            resource_type: Name of the resource type
            action: Action being performed (e.g., "read", "update")
            role_names: Optional role names for the principal
            context: Context data for condition evaluation, structured as:
                     {"principal": {...}, "context": {...}}
                     Used to resolve $principal.* and $context.* references
        
        Returns:
            AuthorizationFilter with authorization SearchQuery and metadata
        """
        ...
    
    async def sync(self) -> None:
        """
        Trigger sync with identity provider (optional).
        Some backends manage their own sync schedule.
        """
        ...


@dataclass
class AuthorizationFilter:
    """
    Result of get_authorization_filter() - contains authorization as SearchQuery.
    
    The SearchQuery can be merged with the user's search query using
    SearchQuery.merge() for single-query authorization.
    """
    search_query: "SearchQuery | None" = None  # Authorization conditions as SearchQuery
    granted_all: bool = False                   # True = no filter needed (blanket access)
    denied_all: bool = False                    # True = return empty results immediately
    has_context_refs: bool = False              # Whether conditions originally had context refs
```

### 11.2 Stateful ABAC Contrib Adapter

The auth library provides a contrib module for the Stateful ABAC Policy Engine.

- `FieldMapping` - Maps ABAC attributes to search_query_dsl field names
- `ABACConditionConverter` - Converts JSON DSL to SearchQuery
- `StatefulABACAuthorizationAdapter` - Full adapter with `get_authorization_filter()` support

```python
# py-cqrs-ddd-auth/contrib/stateful_abac/__init__.py
from .adapter import StatefulABACAuthorizationAdapter

# py-cqrs-ddd-auth/contrib/abac_dsl/converter.py
from .converter import FieldMapping, ABACConditionConverter
```

**Key points:**

1. The adapter requires a `FieldMapping` at initialization to map ABAC's abstract
   attributes (`region_id`, `status`, `geometry`) to your DSL field names.

2. `get_authorization_filter()` returns a `AuthorizationFilter` with a `SearchQuery` object
   (not SQLAlchemy expressions), enabling simple `merge()` operations.

3. The ABAC engine evaluates `source='principal'` and `source='context'` conditions server-side,
   resolving `$context.*` and `$principal.*` references before returning. Only `source='resource'`
   conditions remain in `conditions_dsl` for database-side evaluation.

4. Other methods like `check_access()` and `get_permitted_resources()` work as before
   for non-SQL-filter use cases.

### 11.3 Using the Authorization Adapter

```python
from stateful_abac_sdk import StatefulABACClient
from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAuthorizationAdapter
from cqrs_ddd_auth.contrib.abac_dsl.converter import FieldMapping
from search_query_dsl.core.models import SearchQuery

# 1. Create ABAC client (HTTP or DB mode)
abac_client = StatefulABACClient(
    base_url="http://localhost:8000/api/v1",
    realm="my_realm"
)

# 2. Create field mapping for your application
field_mapping = FieldMapping(
    mappings={
        'region_id': 'region_id',
        'status': 'document_status',
        'department': 'dept',
    },
    external_id_field='external_id',
    external_id_cast=int,  # Cast external_ids to int
)

# 3. Create authorization adapter with field mapping
auth_adapter = StatefulABACAuthorizationAdapter(
    client=abac_client,
    field_mapping=field_mapping,
)

# 4. Use for authorization filter
async with abac_client.connect(token=access_token):
    auth_filter = await auth_adapter.get_authorization_filter(
        principal_id=user_claims.sub,
        resource_type="document",
        action="read",
        auth_context={"ip": request.client.host, "location": "POINT(23.7 37.9)"}
    )
    
    # Handle the three filter types
    if auth_filter.denied_all:
        return []  # No access
    
    if auth_filter.granted_all:
        # No authorization filter needed - user has blanket access
        combined = user_query
    else:
        # Merge authorization conditions with user query
        combined = user_query.merge(auth_filter.search_query)
```

### 11.4 Dependency Injection Setup

```python
# FastAPI example with resource-specific field mappings
from dependency_injector import containers, providers
from cqrs_ddd_auth.contrib.abac_dsl.converter import FieldMapping

class AuthContainer(containers.DeclarativeContainer):
    config = providers.Configuration()
    
    # ABAC SDK client
    abac_client = providers.Singleton(
        StatefulABACClient,
        mode=config.abac_mode,  # "http" or "db"
        base_url=config.abac_url,
        realm=config.realm
    )
    
    # Field mappings per resource type
    document_field_mapping = providers.Singleton(
        FieldMapping,
        mappings={
            'region_id': 'region_id',
            'status': 'doc_status',
        },
        external_id_field='external_id',
    )
    
    element_field_mapping = providers.Singleton(
        FieldMapping,
        mappings={
            'region_id': 'region_id',
            'geometry': 'geom',
            'status': 'element_status',
        },
        external_id_field='external_id',
    )
    
    # Authorization adapters per resource type
    document_authorization = providers.Singleton(
        StatefulABACAuthorizationAdapter,
        client=abac_client,
        field_mapping=document_field_mapping,
    )
    
    element_authorization = providers.Singleton(
        StatefulABACAuthorizationAdapter,
        client=abac_client,
        field_mapping=element_field_mapping,
    )
    
    # Handlers receive the appropriate adapter
    search_documents_handler = providers.Factory(
        SearchDocumentsHandler,
        authorization=document_authorization,
    )
    
    search_elements_handler = providers.Factory(
        SearchElementsHandler,
        authorization=element_authorization,
    )
```

### 11.5 Authorization Filter Injection (Single-Query Authorization)

The `get_authorization_filter()` method enables **single-query authorization** - a major performance optimization that eliminates the need for two-phase fetch-then-filter patterns.

#### The Problem: Two-Phase Authorization

Traditional authorization flow for search queries:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ LEGACY FLOW (Inefficient)                                               │
├─────────────────────────────────────────────────────────────────────────┤
│ 1. User sends search query                                              │
│ 2. Query handler: SELECT * FROM resources WHERE {filters} → ALL IDs    │
│ 3. Pass N IDs to authorization service                         ← N IDs │
│ 4. Authorization: filter IDs via check_access()                ← Query │
│ 5. Return filtered IDs                                                  │
│                                                                         │
│ Problems:                                                               │
│   - Two database roundtrips                                             │
│   - N IDs transferred over network                                      │
│   - Memory explosion with large result sets                             │
│   - Pagination breaks (page 1 might return 0 results after filtering)  │
└─────────────────────────────────────────────────────────────────────────┘
```

#### The Solution: Authorization Filter Injection

```
┌─────────────────────────────────────────────────────────────────────────┐
│ OPTIMIZED FLOW (Single Query with SearchQuery.merge())                  │
├─────────────────────────────────────────────────────────────────────────┤
│ 1. User sends search query                                              │
│ 2. Get authorization filter: get_authorization_filter(type, action, context)     │
│    → Returns AuthorizationFilter with authorization as SearchQuery                │
│ 3. Merge: user_query.merge(auth_query)                                 │
│    → Combined SearchQuery: user filters AND authorization conditions   │
│ 4. Execute via search_query_dsl                        ← One query!    │
│                                                                         │
│ Benefits:                                                               │
│   - Single database query                                               │
│   - Zero ID transfer overhead                                           │
│   - Correct pagination                                                  │
│   - Backend-agnostic (works with any search_query_dsl backend)         │
│   - Simple field name mapping, not SQLAlchemy column objects            │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Usage Example

```python
from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAuthorizationAdapter
from cqrs_ddd_auth.contrib.abac_dsl.converter import FieldMapping
from search_query_dsl import SearchQuery

# One-time setup at application startup
field_mapping = FieldMapping(
    mappings={
        'geometry': 'geom',              # ABAC "geometry" → DSL field "geom"
        'status': 'element_status',      # ABAC "status" → DSL field "element_status"
        'region_id': 'region_id',        # Same name
    },
    external_id_field='external_id',
    external_id_cast=int,                # Cast external_ids to int
)

authorization = StatefulABACAuthorizationAdapter(
    client=abac_client,
    field_mapping=field_mapping,
)


class SearchElementsHandler(QueryHandler):
    def __init__(
        self,
        persistence: ElementSearchPersistence,
        authorization: StatefulABACAuthorizationAdapter,
    ):
        self.persistence = persistence
        self.authorization = authorization
    
    async def handle(self, query: SearchElements) -> list[Element]:
        identity = get_identity()
        
        # 1. Get authorization filter (returns SearchQuery)
        auth_filter = await self.authorization.get_authorization_filter(
            principal_id=identity.sub,
            resource_type="elements",
            action="read",
            context={
                "principal": {"department": identity.department},
                "context": {"location": query.location} if query.location else {}
            }
        )
        # auth_filter.search_query is now:
        # SearchQuery(groups=[
        #     SearchQueryGroup(conditions=[
        #         SearchCondition(field="region_id", operator="=", value=5)
        #     ], group_operator="or")
        # ])
        
        # 2. Handle edge cases
        if auth_filter.denied_all:
            return []  # User has no access whatsoever
        
        # 3. Parse user's search query
        user_query = SearchQuery.from_dict(query.filters)
        
        # 4. Merge with authorization (unless blanket access)
        if not auth_filter.granted_all and auth_filter.search_query is not None:
            combined_query = user_query.merge(auth_filter.search_query)
        else:
            combined_query = user_query
        
        # 5. Execute single query - search_query_dsl handles everything
        return await self.persistence.search(combined_query)
```

#### AuthorizationFilter Return Values

| Scenario | `granted_all` | `denied_all` | `search_query` |
|----------|---------------|--------------|----------------|
| User has blanket type-level access | `True` | `False` | `None` |
| User has no access at all | `False` | `True` | `None` |
| User has conditional access | `False` | `False` | `SearchQuery` with conditions |
| User has resource-level ACLs | `False` | `False` | `SearchQuery` with `external_id IN [...]` |
| Mixed (conditions + resource ACLs) | `False` | `False` | `SearchQuery` with `conditions OR external_id IN [...]` |

> **Note**: The ABAC engine evaluates `source='principal'` and `source='context'` conditions 
> server-side before returning. If all conditions evaluate to true, `filter_type='granted_all'`.
> If any required condition evaluates to false, `filter_type='denied_all'`. Only 
> `source='resource'` conditions remain in `conditions_dsl` for database-side evaluation.

#### Field Mapping (Simple String Mapping)

Instead of SQLAlchemy column objects, use simple string field names:

```python
# Application's field names used in search_query_dsl
# These match the column aliases or field names in your backend

# Register field mapping
field_mapping = FieldMapping(
    mappings={
        'geometry': 'geom',              # ABAC attr → DSL field name
        'status': 'element_status',
        'region_id': 'region_id',
    },
    external_id_field='external_id',
    external_id_cast=int,                # Cast external_ids to int (default is str)
    # Or use a lambda for custom parsing:
    # external_id_cast=lambda x: UUID(x),
    # external_id_cast=lambda x: x.split('-')[0],
)

# ABAC returns DSL: {"op": "=", "source": "resource", "attr": "status", "val": "active"}
# Converter produces: SearchCondition(field="element_status", operator="=", value="active")
# Which the search_query_dsl backend compiles to: elements.element_status = 'active'
```

### 11.6 ABAC Condition DSL Reference

The ABAC engine returns authorization conditions as JSON DSL. The condition DSL supports nested logical operators (`and`, `or`, `not`) with leaf conditions.

**Sources** (where attribute values come from):
| Source | Description |
|--------|-------------|
| `"resource"` | From resource attributes (only source remaining in `conditions_dsl` - evaluated database-side) |
| `"principal"` | From authenticated principal's attributes (evaluated server-side, resolved before returning) |
| `"context"` | From runtime `auth_context` passed in the request (evaluated server-side, resolved before returning) |

> **Note**: The ABAC engine evaluates all `source='principal'` and `source='context'` conditions 
> server-side before returning. Only `source='resource'` conditions remain in `conditions_dsl` 
> for database-side evaluation. This means the `conditions_dsl` you receive is already simplified
> and contains only conditions that require access to the actual resource rows.

**Comparison Operators** (leaf conditions):
| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equal | `{"op": "=", "source": "resource", "attr": "status", "val": "active"}` |
| `!=` | Not equal | `{"op": "!=", "source": "resource", "attr": "deleted", "val": true}` |
| `<`, `>`, `<=`, `>=` | Numeric comparison | `{"op": ">=", "source": "principal", "attr": "clearance", "val": 5}` |
| `in` | Value in list | `{"op": "in", "source": "resource", "attr": "category", "val": ["A", "B"]}` |

**Spatial Operators** (PostGIS):
| Operator | Description | Example |
|----------|-------------|---------|
| `st_dwithin` | Within distance (meters) | `{"op": "st_dwithin", "source": "resource", "attr": "geometry", "val": "$context.location", "args": 5000}` |
| `st_contains` | Geometry contains | `{"op": "st_contains", "source": "resource", "attr": "geometry", "val": "$context.point"}` |
| `st_within` | Geometry within | `{"op": "st_within", "source": "resource", "attr": "geometry", "val": "POLYGON(...)"}` |
| `st_intersects` | Geometries intersect | `{"op": "st_intersects", "source": "resource", "attr": "geometry", "val": "$context.region"}` |

**Logical Operators** (compound conditions):
| Operator | Description |
|----------|-------------|
| `and` | All conditions must be true |
| `or` | At least one condition must be true |
| `not` | Negates a single condition |

**Value References** (dynamic values):
- `$resource.attr_name` - Reference resource attribute
- `$principal.attr_name` - Reference principal attribute  
- `$context.attr_name` - Reference auth_context value

**Nested Condition Example**:
```json
{
    "op": "or",
    "conditions": [
        {"op": "=", "source": "resource", "attr": "classification", "val": "public"},
        {
            "op": "and",
            "conditions": [
                {"op": "=", "source": "resource", "attr": "classification", "val": "confidential"},
                {"op": ">=", "source": "principal", "attr": "clearance", "val": "$resource.level"},
                {"op": "=", "source": "context", "attr": "ip", "val": "10.0.0.100"}
            ]
        }
    ]
}
```

This means: Allow if resource is public OR (resource is confidential AND principal.clearance >= resource.level AND request IP is 10.0.0.100).

**Python SDK ConditionBuilder**:
```python
from stateful_abac_sdk.manifest import ConditionBuilder

# Fluent API for building conditions
condition = ConditionBuilder.or_(
    ConditionBuilder.attr("classification").eq("public"),
    ConditionBuilder.and_(
        ConditionBuilder.attr("classification").eq("confidential"),
        ConditionBuilder.attr("clearance").from_principal().gte("$resource.level"),
        ConditionBuilder.attr("ip").from_context().eq("10.0.0.100")
    )
)

# Negation example - deny access to drafts owned by the principal
denied_condition = ConditionBuilder.not_(
    ConditionBuilder.and_(
        ConditionBuilder.attr("status").eq("draft"),
        ConditionBuilder.attr("owner").eq("$principal.username")
    )
)
```

#### SDK Usage

```python
from stateful_abac_sdk import StatefulABACClient

# HTTP mode
client = StatefulABACClient(base_url="http://localhost:8000/api/v1", realm="my_realm")
async with client.connect(token=access_token):
    result = await client.auth.get_authorization_conditions(
        resource_type_name="element",
        action_name="read",
        auth_context={"ip": "10.0.0.5", "location": "POINT(23.7 37.9)"},  # Optional
        role_names=["admin"]  # Optional: override active roles
    )
    
    # result.filter_type: "granted_all" | "denied_all" | "conditions"
    # result.conditions_dsl: dict | None (only source='resource' conditions remain)
    # result.has_context_refs: bool (whether original had $context.* or $principal.* refs)

# DB mode (direct database access - 10-100x faster)
client = StatefulABACClient(mode="db", realm="my_realm")
async with client.connect():
    result = await client.auth.get_authorization_conditions(
        resource_type_name="element",
        action_name="read",
        auth_context={"department": "Engineering"},
    )
```

> **Note**: The ABAC engine evaluates all `source='principal'` and `source='context'` conditions
> server-side, resolving `$context.*` and `$principal.*` references to actual values. Only 
> `source='resource'` conditions remain in `conditions_dsl`. If all conditions evaluate to true,
> `filter_type='granted_all'`. If any required condition evaluates to false, `filter_type='denied_all'`.

#### Application-Side Converter (Simplified)

The converter is much simpler since context/principal resolution happens server-side. 
It only does field name remapping:

```python
# py-cqrs-ddd-auth/contrib/abac_dsl/converter.py

from dataclasses import dataclass, field
from typing import Any, Callable
from search_query_dsl.core.models import SearchQuery, SearchQueryGroup, SearchCondition


@dataclass
class FieldMapping:
    """
    Maps ABAC attribute names to search_query_dsl field names.
    
    This is application-specific and registered once at startup.
    
    Args:
        mappings: Dict mapping ABAC attr names to DSL field names
        external_id_field: DSL field name for external_id (default: "external_id")
        external_id_cast: Callable to cast external_id values. Can be a type (int, str)
                          or a lambda/function for custom parsing. Default is str.
                          Examples: int, str, lambda x: UUID(x), lambda x: x.split('-')[0]
    """
    mappings: dict[str, str] = field(default_factory=dict)
    external_id_field: str = "external_id"
    external_id_cast: Callable[[Any], Any] = str  # Cast function for external_id values
    
    def get_field(self, abac_attr: str) -> str:
        """Get the DSL field name for an ABAC attribute."""
        return self.mappings.get(abac_attr, abac_attr)
    
    def cast_external_id(self, val: Any) -> Any:
        """Cast an external_id value using the configured cast function."""
        if isinstance(val, list):
            return [self.external_id_cast(v) for v in val]
        return self.external_id_cast(val)


class ABACConditionConverter:
    """
    Converts ABAC JSON condition DSL to SearchQuery.
    
    Since the ABAC engine now evaluates all $context.* and $principal.* 
    references server-side, this converter only needs to:
    1. Remap ABAC attribute names to application field names
    2. Convert the DSL structure to SearchQuery objects
    """
    
    OPERATOR_MAP = {
        '=': '=',
        '==': '=',
        '!=': '!=',
        '<': '<',
        '>': '>',
        '<=': '<=',
        '>=': '>=',
        'in': 'in',
        'like': 'like',
        'ilike': 'ilike',
        'is_null': 'is_null',
        'is_not_null': 'is_not_null',
        # Spatial operators
        'st_intersects': 'intersects',
        'st_dwithin': 'dwithin',
        'st_contains': 'contains',
        'st_within': 'within',
    }
    
    def __init__(self, field_mapping: FieldMapping):
        self.mapping = field_mapping
    
    def convert(self, conditions_dsl: dict) -> SearchQuery:
        """
        Convert ABAC conditions JSON to SearchQuery.
        
        Args:
            conditions_dsl: The JSON condition DSL from ABAC (already resolved)
            
        Returns:
            SearchQuery ready for merging with user query
        """
        if conditions_dsl is None:
            return SearchQuery()
        
        group = self._convert_node(conditions_dsl)
        
        if isinstance(group, SearchQueryGroup):
            return SearchQuery(groups=[group])
        elif isinstance(group, SearchCondition):
            return SearchQuery(groups=[SearchQueryGroup(conditions=[group])])
        else:
            return SearchQuery()
    
    def _convert_node(self, node: dict) -> SearchQueryGroup | SearchCondition:
        """Recursively convert a condition node."""
        op = node.get('op', '').lower()
        
        # Compound operators → SearchQueryGroup
        if op in ('and', 'or'):
            conditions = [self._convert_node(c) for c in node.get('conditions', [])]
            return SearchQueryGroup(conditions=conditions, group_operator=op)
        
        if op == 'not':
            inner = node.get('conditions', [])
            if inner:
                return SearchQueryGroup(
                    conditions=[self._convert_node(inner[0])],
                    group_operator='not'
                )
            return SearchQueryGroup()
        
        # Leaf operators → SearchCondition
        attr = node.get('attr', '')
        val = node.get('val')
        args = node.get('args')
        
        # Remap field name (only resource attributes reach here after server-side evaluation)
        field = self.mapping.get_field(attr)
        
        # Cast external_id values to configured type
        if attr == 'external_id':
            field = self.mapping.external_id_field
            val = self.mapping.cast_external_id(val)
        
        # Map operator
        dsl_op = self.OPERATOR_MAP.get(op, op)
        
        # Handle spatial operators with args
        value_type = None
        if op.startswith('st_'):
            value_type = 'geometry'
            if op == 'st_dwithin' and args is not None:
                val = {'geometry': val, 'distance': args}
        
        return SearchCondition(
            field=field,
            operator=dsl_op,
            value=val,
            value_type=value_type,
        )
```

#### Contrib Adapter Implementation

```python
# py-cqrs-ddd-auth/contrib/stateful_abac/adapter.py

from ..abac_dsl.converter import ABACConditionConverter, FieldMapping
from search_query_dsl.core.models import SearchQuery


class StatefulABACAuthorizationAdapter(AuthorizationPort):
    """
    Stateful ABAC adapter that converts conditions to SearchQuery.
    
    The ABAC engine handles all the complexity:
    - Evaluates source='principal' and source='context' conditions server-side
    - Resolves $context.* and $principal.* references
    - Merges resource-level ACLs into conditions_dsl as IN clauses
    
    This adapter just converts the returned DSL to SearchQuery.
    """
    
    def __init__(
        self, 
        client: StatefulABACClient,
        field_mapping: FieldMapping,
    ):
        self.client = client
        self.field_mapping = field_mapping
        self.converter = ABACConditionConverter(field_mapping)
    
    async def get_authorization_filter(
        self,
        principal_id: str,
        resource_type: str,
        action: str,
        role_names: list[str] | None = None,
        auth_context: dict | None = None,
    ) -> AuthorizationFilter:
        """
        Get authorization filter as SearchQuery.
        
        The ABAC engine evaluates all evaluable conditions server-side.
        Only source='resource' conditions remain for database-side evaluation.
        """
        result = await self.client.auth.get_authorization_conditions(
            resource_type_name=resource_type,
            action_name=action,
            auth_context=auth_context,
            role_names=role_names,
        )
        
        if result.filter_type == "granted_all":
            return AuthorizationFilter(granted_all=True)
        
        if result.filter_type == "denied_all":
            return AuthorizationFilter(denied_all=True)
        
        # Convert conditions DSL to SearchQuery
        # The DSL already contains merged resource-level ACLs as external_id IN clauses
        if result.conditions_dsl:
            search_query = self.converter.convert(result.conditions_dsl)
        else:
            # No conditions - shouldn't happen with filter_type='conditions'
            return AuthorizationFilter(denied_all=True)
        
        return AuthorizationFilter(
            search_query=search_query,
            has_context_refs=result.has_context_refs,
        )
```

#### Usage in Persistence Layer

Here's how it integrates with the cqrs-ddd toolkit persistence:

```python
# In your application's persistence layer

from cqrs_ddd.backends.sqlalchemy import SQLAlchemyQueryPersistence
from search_query_dsl.core.models import SearchQuery

class ProductSearchPersistence(SQLAlchemyQueryPersistence[ProductSearchDto]):
    model_class = ProductModel
    dto_class = ProductSearchDto
    
    def __init__(self, authorization: StatefulABACAuthorizationAdapter):
        self.authorization = authorization
    
    async def search(
        self, 
        user_query: SearchQuery,
        identity: UserIdentity,
        unit_of_work: Any,
    ) -> list[ProductSearchDto]:
        """
        Search with authorization merged into query.
        """
        # Get authorization as SearchQuery
        # auth_context is passed to ABAC for server-side evaluation
        auth_filter = await self.authorization.get_authorization_filter(
            principal_id=identity.sub,
            resource_type="product",
            action="read",
            auth_context={"department": identity.department, "ip": request.client.host}
        )
        
        if auth_filter.denied_all:
            return []
        
        # Merge authorization into user query
        if auth_filter.granted_all:
            combined_query = user_query
        else:
            combined_query = user_query.merge(auth_filter.search_query)
        
        # Execute via search_query_dsl
        from search_query_dsl.api import search
        session = unit_of_work.session
        
        results = await search(
            combined_query.to_dict(), 
            session, 
            model=self.model_class
        )
        
        return [self.to_dto(row) for row in results]
```

#### Comparison: SQLAlchemy Expressions vs SearchQuery.merge()

| Aspect | SQLAlchemy Expressions | SearchQuery.merge() |
|--------|------------------------|---------------------|
| **Complexity** | Need `ConditionCompiler` with operator mapping | Simple field name remapping |
| **Dependencies** | Requires SQLAlchemy, GeoAlchemy2 | Only search_query_dsl models |
| **Backend coupling** | Tied to SQLAlchemy | Works with any DSL backend |
| **Type safety** | SQLAlchemy column validation | Field validation by backend |
| **Spatial operators** | Native GeoAlchemy2 functions | DSL operator names (backend handles) |
| **Testing** | Need to mock SQLAlchemy | Pure dataclass testing |
| **Serialization** | Can't serialize expressions | `SearchQuery.to_dict()` works |

#### Implementation Considerations

| Consideration | Approach |
|---------------|----------|
| **Field mapping** | One-time setup at app startup with `FieldMapping` |
| **Missing fields** | Converter passes through unmapped names; backend validates |
| **Spatial operators** | Map ABAC's `st_*` to DSL's spatial operators |
| **Context resolution** | Handled server-side by ABAC engine before returning |
| **Resource-level ACLs** | Merged into `conditions_dsl` as `external_id IN (...)` |
| **Merging semantics** | Groups are ANDed; use OR group wrapper for complex logic |
| **Condition evaluation** | ABAC evaluates source='principal'/'context' server-side |

### 11.7 Integration with search_query_dsl

The `search_query_dsl` library provides a JSON-based DSL for building database queries. 
With the new `SearchQuery.merge()` method, integration becomes simple and elegant.

#### The Key Insight: SearchQuery.merge()

The `search_query_dsl` library now supports merging queries:

```python
# In search_query_dsl/core/models.py
@dataclass
class SearchQuery:
    groups: List[SearchQueryGroup] = field(default_factory=list)
    limit: Optional[int] = None
    offset: Optional[int] = None
    order_by: Optional[List[str]] = None
    
    def merge(self, other: "SearchQuery") -> "SearchQuery":
        """
        Merge another SearchQuery into this one using AND logic.
        
        Both queries' groups are combined. Since groups are ANDed together,
        this effectively creates: (self conditions) AND (other conditions).
        """
        return SearchQuery(
            groups=self.groups + other.groups,
            limit=self.limit if self.limit is not None else other.limit,
            offset=self.offset if self.offset is not None else other.offset,
            order_by=self.order_by if self.order_by is not None else other.order_by,
        )
```

#### Architecture: SearchQuery as Universal Language

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                SEARCHQUERY-BASED AUTHORIZATION + SEARCH FLOW                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. User Request                                                            │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ POST /api/elements/search                                       │     │
│     │ { "filters": [...], "pagination": {...} }                       │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                              │                                              │
│                              ▼                                              │
│  2. Query Handler                                                           │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ a. Parse user query → SearchQuery                               │     │
│     │    → SearchQuery(groups=[user filters])                         │     │
│     │                                                                 │     │
│     │ b. Get authorization conditions → SearchQuery                   │     │
│     │    → AuthorizationFilter.search_query = SearchQuery(groups=[auth conds]) │     │
│     │                                                                 │     │
│     │ c. Merge: user_query.merge(auth_query)                         │     │
│     │    → Combined SearchQuery: user filters AND auth conditions    │     │
│     │                                                                 │     │
│     │ d. Execute via search_query_dsl backend                        │     │
│     │    → Backend compiles to SQL and executes                      │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                              │                                              │
│                              ▼                                              │
│  3. Response (already filtered by authorization)                            │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │ { "items": [...], "total": 42, "page": 1 }                      │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Complete Usage Example

```python
from dataclasses import dataclass
from search_query_dsl.core.models import SearchQuery
from search_query_dsl.api import search

from cqrs_ddd.core import Query, QueryHandler
from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAuthorizationAdapter
from cqrs_ddd_auth.contrib.abac_dsl.converter import FieldMapping


# One-time setup: Register field mapping
field_mapping = FieldMapping(
    mappings={
        'region_id': 'region_id',        # ABAC attr → DSL field (same)
        'geometry': 'geom',              # ABAC attr → DSL field (different)
        'status': 'element_status',      # ABAC attr → DSL field (different)
    },
    external_id_field='external_id',
)

authorization = StatefulABACAuthorizationAdapter(
    client=abac_client,
    field_mapping=field_mapping,
)


@dataclass
class SearchElements(Query):
    """Search elements with authorization."""
    filters: dict  # User's search query as dict
    

class SearchElementsHandler(QueryHandler):
    """
    Handler that combines search_query_dsl with SearchQuery.merge() for authorization.
    
    This is the simplest and most elegant approach:
    - ABAC evaluates principal/context conditions server-side
    - Remaining conditions are converted to SearchQuery
    - User query is parsed to SearchQuery
    - Both are merged with AND semantics
    - search_query_dsl backend handles all SQL compilation
    """
    
    def __init__(
        self,
        authorization: StatefulABACAuthorizationAdapter,
        session: AsyncSession,
    ):
        self.authorization = authorization
        self.session = session
    
    async def handle(self, query: SearchElements) -> list[ElementDTO]:
        from cqrs_ddd_auth.context import get_identity
        
        identity = get_identity()
        
        # Step 1: Parse user's search query
        user_query = SearchQuery.from_dict(query.filters)
        
        # Step 2: Get authorization filter
        # auth_context is sent to ABAC for server-side evaluation
        auth_filter = await self.authorization.get_authorization_filter(
            principal_id=identity.principal_id,
            resource_type="element",
            action="view",
            auth_context={"department": identity.department, "location": query.location}
        )
        # The returned auth_filter.search_query only contains source='resource' conditions
        # All $principal.* and $context.* references have been resolved server-side
        
        # Step 3: Handle edge cases
        if auth_filter.denied_all:
            return []  # User has no access
        
        # Step 4: Merge queries (unless blanket access)
        if auth_filter.granted_all:
            combined_query = user_query
        else:
            combined_query = user_query.merge(auth_filter.search_query)
        
        # Step 5: Execute via search_query_dsl
        # The backend handles all SQL compilation with proper column mapping
        results = await search(
            combined_query.to_dict(),
            self.session,
            model=Element,
        )
        
        return [ElementDTO.from_model(r) for r in results]
```

#### How It Works: Complete Flow

```
User: GET /api/elements?status=active&page=1

1. Parse user filters to SearchQuery:
   SearchQuery(groups=[
       SearchQueryGroup(conditions=[
           SearchCondition(field="status", operator="=", value="active")
       ])
   ], limit=20, offset=0)

2. ABAC returns conditions DSL:
   {"op": "or", "conditions": [
       {"op": "in", "source": "resource", "attr": "region_id", "val": [5, 7, 12]},
       {"op": "intersects", "source": "resource", "attr": "geometry", "val": "POLYGON(...)"}
   ]}

3. ABACConditionConverter converts to SearchQuery:
   SearchQuery(groups=[
       SearchQueryGroup(
           conditions=[
               SearchCondition(field="region_id", operator="in", value=[5, 7, 12]),
               SearchCondition(field="geom", operator="intersects", value="POLYGON(...)")
           ],
           group_operator="or"
       )
   ])

4. Merge: user_query.merge(auth_query):
   SearchQuery(groups=[
       SearchQueryGroup(conditions=[  # User's filter
           SearchCondition(field="status", operator="=", value="active")
       ]),
       SearchQueryGroup(              # Authorization filter
           conditions=[...],
           group_operator="or"
       )
   ], limit=20, offset=0)

5. search_query_dsl backend compiles to SQL:
   SELECT * FROM elements
   WHERE element_status = 'active'                      -- User filter
     AND (region_id IN (5, 7, 12)                       -- Auth condition 1
          OR ST_Intersects(geom, ST_GeomFromText(...))) -- Auth condition 2
   LIMIT 20 OFFSET 0

6. Single query execution with correct pagination ✓
```

#### Flow with External IDs (Resource-Level ACLs)

When users have resource-level ACLs (permissions on specific resources), the flow 
includes external IDs:

```
User: GET /api/documents?status=published&page=1

1. Parse user filters to SearchQuery:
   SearchQuery(groups=[
       SearchQueryGroup(conditions=[
           SearchCondition(field="status", operator="=", value="published")
       ])
   ], limit=20, offset=0)

2. ABAC returns conditions_dsl (type-level + resource-level merged):
   {
     "op": "or",
     "conditions": [
       {"op": "=", "source": "resource", "attr": "department", "val": "engineering"},
       {"op": "in", "source": "resource", "attr": "external_id", "val": ["doc-123", "doc-456", "doc-789"]}
     ]
   }
   
   The user can access:
   a) Any document where department = "engineering" (type-level condition)
   b) Specific documents: doc-123, doc-456, doc-789 (resource-level grants merged as IN clause)

3. ABACConditionConverter creates authorization SearchQuery:
   SearchQuery(groups=[
       SearchQueryGroup(
           conditions=[
               SearchCondition(field="dept", operator="=", value="engineering"),
               SearchCondition(field="external_id", operator="in", 
                              value=["doc-123", "doc-456", "doc-789"])
           ],
           group_operator="or"  # Type-level condition OR resource-level IDs
       )
   ])

4. Merge: user_query.merge(auth_query):
   SearchQuery(groups=[
       SearchQueryGroup(conditions=[  # User's filter
           SearchCondition(field="status", operator="=", value="published")
       ]),
       SearchQueryGroup(              # Authorization filter (from conditions_dsl)
           conditions=[
               SearchCondition(field="dept", operator="=", value="engineering"),
               SearchCondition(field="external_id", operator="in", 
                              value=["doc-123", "doc-456", "doc-789"])
           ],
           group_operator="or"
       )
   ], limit=20, offset=0)

5. search_query_dsl backend compiles to SQL:
   SELECT * FROM documents
   WHERE status = 'published'                           -- User filter
     AND (
           department = 'engineering'                   -- Type-level condition
           OR external_id IN ('doc-123', 'doc-456', 'doc-789')  -- Resource ACLs
         )
   LIMIT 20 OFFSET 0

6. User sees:
   - All published engineering documents (via type-level policy)
   - Plus doc-123, doc-456, doc-789 if published (via resource-level grants)
```

#### External IDs Only (No Type-Level Conditions)

When a user only has resource-level ACLs with no type-level conditions:

```
User: GET /api/confidential-reports?year=2025

1. ABAC returns conditions_dsl (resource-level only, merged as IN clause):
   {"op": "in", "source": "resource", "attr": "external_id", "val": ["report-001", "report-002"]}
   
2. AuthorizationFilter:
   AuthorizationFilter(
       granted_all=False,
       denied_all=False,
       search_query=SearchQuery(groups=[
           SearchQueryGroup(conditions=[
               SearchCondition(field="external_id", operator="in", 
                              value=["report-001", "report-002"])
           ])
       ]),
       has_context_refs=False
   )

3. Merged query compiles to:
   SELECT * FROM confidential_reports
   WHERE year = 2025                                    -- User filter
     AND external_id IN ('report-001', 'report-002')   -- Only these specific reports
   LIMIT 20 OFFSET 0

4. User can only ever see report-001 and report-002, regardless of filters ✓
```

#### Integration with cqrs-ddd Persistence

The pattern integrates naturally with the toolkit's persistence layer:

```python
# In your persistence layer

class ProductSearchPersistence(SQLAlchemyQueryPersistence[ProductSearchDto]):
    model_class = ProductModel
    dto_class = ProductSearchDto
    
    def __init__(self, authorization: StatefulABACAuthorizationAdapter):
        self.authorization = authorization
    
    async def fetch(
        self, 
        queries: List[dict], 
        unit_of_work: Any,
    ) -> List[ProductSearchDto]:
        """
        Override fetch to integrate authorization via SearchQuery.merge().
        """
        if not queries:
            return []
        
        from cqrs_ddd_auth.context import get_identity
        identity = get_identity()
        
        # Parse user query
        user_query = SearchQuery.from_dict(queries[0])
        
        # Get authorization as SearchQuery
        auth_filter = await self.authorization.get_authorization_filter(
            principal_id=identity.sub,
            resource_type="product",
            action="read",
        )
        
        if auth_filter.denied_all:
            return []
        
        # Merge authorization into user query
        if auth_filter.granted_all:
            combined_query = user_query
        else:
            combined_query = user_query.merge(auth_filter.search_query)
        
        # Execute via search_query_dsl
        from search_query_dsl.api import search
        session = unit_of_work.session
        
        results = await search(
            combined_query.to_dict(), 
            session, 
            model=self.model_class
        )
        
        return [self.to_dto(row) for row in results]
```

#### Advantages of SearchQuery.merge() Approach

| Aspect | SQLAlchemy Expressions | SearchQuery.merge() |
|--------|------------------------|---------------------|
| **Complexity** | Need ConditionCompiler, GeoAlchemy2 | Simple field name remapping |
| **Dependencies** | SQLAlchemy, GeoAlchemy2 | Only search_query_dsl models |
| **Backend coupling** | Tied to SQLAlchemy | Works with any DSL backend |
| **Serialization** | Can't serialize expressions | `SearchQuery.to_dict()` works |
| **Testing** | Need to mock SQLAlchemy | Pure dataclass testing |
| **Debugging** | SQLAlchemy expression trees | Simple dict/dataclass inspection |

#### Security Notes

1. **DSL Validation**: ABAC validates conditions when policies are created - only well-formed conditions are stored.

2. **Field Mapping**: The converter only produces fields explicitly registered in FieldMapping - no arbitrary field access.

3. **Backend Validation**: search_query_dsl backend validates fields against the model - unknown fields are rejected.

4. **Context Resolution**: Context values are resolved at convert time - no dynamic injection.

## 12. Package Structure

```
py-cqrs-ddd-auth/
├── src/
│   └── cqrs_ddd_auth/
│       │
│       │   # ═══════ DOMAIN LAYER ═══════
│       ├── domain/
│       │   ├── __init__.py
│       │   ├── aggregates.py         # AuthSession, OTPChallenge
│       │   ├── value_objects.py      # Credentials, OTPCode, UserClaims, AuthRole
│       │   ├── events.py             # AuthenticationSucceeded, UserCreated, etc.
│       │   └── errors.py             # AuthenticationError, AuthorizationError
│       │
│       │   # ═══════ APPLICATION LAYER ═══════
│       ├── application/
│       │   ├── __init__.py
│       │   ├── commands/
│       │   │   ├── authenticate.py       # AuthenticateWithCredentials
│       │   │   ├── validate_otp.py       # ValidateOTP
│       │   │   ├── refresh_tokens.py     # RefreshTokens (transparent refresh)
│       │   │   ├── logout.py             # Logout
│       │   │   ├── create_user.py        # CreateUser
│       │   │   ├── update_user.py        # UpdateUser
│       │   │   ├── manage_roles.py       # AssignRoles, RemoveRoles
│       │   │   └── manage_groups.py      # AssignGroups, RemoveFromGroups
│       │   ├── queries/
│       │   │   ├── get_user_info.py      # GetUserInfo (with permissions)
│       │   │   ├── get_otp_methods.py    # GetAvailableOTPMethods
│       │   │   ├── get_user.py           # GetUser, GetUserByUsername
│       │   │   ├── list_users.py         # ListUsers with filters
│       │   │   └── get_user_roles.py     # GetUserRoles, GetUserGroups
│       │   └── sagas/
│       │       └── stepup_auth.py        # StepUpAuthenticationSaga
│       │
│       │   # ═══════ INFRASTRUCTURE LAYER ═══════
│       ├── infrastructure/
│       │   ├── __init__.py
│       │   ├── ports.py                  # IdentityProviderPort, AuthorizationPort, etc.
│       │   └── adapters/
│       │       ├── keycloak/
│       │       │   ├── __init__.py
│       │       │   ├── auth.py           # KeycloakIdentityProvider (token validation)
│       │       │   └── admin.py          # KeycloakAdminAdapter (user management)
│       │       └── otp/
│       │           ├── __init__.py
│       │           ├── email.py          # EmailOTPService
│       │           ├── sms.py            # SMSOTPService
│       │           └── totp.py           # TOTPService
│       │
│       │   # ═══════ MIDDLEWARE ═══════
│       ├── middleware/
│       │   ├── __init__.py
│       │   ├── authorization.py          # AuthorizationMiddleware
│       │   └── permitted_actions.py      # PermittedActionsMiddleware
│       │
│       │   # ═══════ CONTEXT & IDENTITY ═══════
│       ├── context.py                    # RequestContext, get_identity(), get_access_token()
│       ├── identity.py                   # Identity Protocol, AnonymousIdentity, SystemIdentity
│       │
│       │   # ═══════ TOKEN REFRESH ═══════
│       ├── refresh/
│       │   ├── __init__.py
│       │   └── adapter.py                # TokenRefreshAdapter (framework-agnostic)
│       │
│       │   # ═══════ CONTRIB: FRAMEWORK ADAPTERS ═══════
│       └── contrib/
│           │
│           │   # --- Stateful ABAC Policy Engine ---
│           ├── stateful_abac/
│           │   ├── __init__.py
│           │   └── adapter.py            # StatefulABACAuthorizationAdapter
│           │
│           │   # --- FastAPI Integration ---
│           ├── fastapi/
│           │   ├── __init__.py
│           │   ├── dependencies.py       # get_identity, require_auth dependencies
│           │   ├── router.py             # Auth routes (login, logout, users, etc.)
│           │   └── middleware.py         # Optional request middleware
│           │
│           │   # --- Django Integration ---
│           └── django/
│               ├── __init__.py
│               ├── middleware.py         # AuthenticationMiddleware, TokenRefreshMiddleware
│               ├── views.py              # Auth endpoints
│               └── startup.py            # AppConfig integration
│
├── tests/
├── pyproject.toml
└── README.md
```

---

## 13. Key Differentiators

| Aspect | Legacy Approach | Toolkit-Native Approach |
|--------|-----------------|-------------------------|
| **Identity** | Hardcoded JWT/Cookie logic | `Identity` Protocol filled by adapters |
| **2FA** | Procedural view logic | OTP as Domain Events + Commands |
| **Multi-step Auth** | Stateless retries | `AuthSession` Aggregate with status tracking |
| **Step-up Auth** | Ad-hoc checks | Saga pattern with compensation |
| **Token Refresh** | Middleware-only | `RefreshTokens` Command + adapter |
| **Groups/Roles** | Separate concepts | Unified `AuthRole` with `GroupPathStrategy` |
| **User Management** | Direct Keycloak calls | CQRS Commands via `IdentityProviderAdminPort` |
| **Authorization** | SDK coupled to app | `AuthorizationPort` + contrib adapters |
| **Framework coupling** | Django-only | Protocol-first, thin adapters |
| **Testing** | Integration tests only | Unit test domain, mock ports |
| **Tracing** | Manual logging | Automatic via `@middleware.log()` |
| **Events** | None | Full audit trail via Domain Events |

---

## 14. Integration with ABAC Engine

The **Stateful ABAC Policy Engine** provides:
- **JIT SQL compilation** of JSON policies
- **3-level authorization** (public flag → type ACL → resource ACL)
- **Spatial authorization** via PostGIS
- **Context-aware rules** (`$context.location`, `$principal.dept`)

This library integrates via the **`AuthorizationPort`** abstraction (Section 11):

```python
# Install the contrib adapter
from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAuthorizationAdapter
from cqrs_ddd_auth.contrib.abac_dsl.converter import FieldMapping
from search_query_dsl.core.models import SearchQuery

# Create field mapping for your application
field_mapping = FieldMapping(
    mappings={'region_id': 'region_id', 'status': 'document_status'},
    external_id_field='external_id',
)

# Create adapter with SDK client and field mapping
adapter = StatefulABACAuthorizationAdapter(
    client=StatefulABACClient(base_url="http://localhost:8000/api/v1", realm="my_realm"),
    field_mapping=field_mapping,
)

# Use via the abstract port interface
auth_filter = await adapter.get_authorization_filter(
    principal_id=user.sub,
    resource_type="document",
    action="read",
)

# Merge authorization with user query
user_query = SearchQuery.from_dict(request_filters)
if not auth_filter.granted_all and auth_filter.search_query:
    combined = user_query.merge(auth_filter.search_query)
else:
    combined = user_query
```

The SDK supports two modes:
- **HTTP mode**: REST API calls (production, standard deployment)
- **DB mode**: Direct SQL execution (10-100x faster for co-located services)

---

## 15. References

| Concept | Source |
|---------|--------|
| Authentication Strategy | [authentication_strategy.md](file:///home/mgourlis/Development/py-cqrs-ddd-toolkit/docs/authentication_strategy.md) |
| ABAC Engine | [fws-auth-app/README.md](file:///home/mgourlis/Development/fws-auth-app/README.md) |
| Keycloak Adapter | [keycloak_adapter.py](file:///home/mgourlis/Development/stateful-abac-policy-engine/common/adapters/keycloak_adapter.py) |
| Sync Service | [sync_service.py](file:///home/mgourlis/Development/stateful-abac-policy-engine/common/services/sync_service.py) |
| Token Refresh | [middlewares.py](file:///home/mgourlis/Development/fws_light_django/fws_light/fws_auth/middlewares.py) |
| Toolkit Core | [py-cqrs-ddd-toolkit/README.md](file:///home/mgourlis/Development/py-cqrs-ddd-toolkit/README.md) |
| Production Example | [fws_light_django](file:///home/mgourlis/Development/fws_light_django) |

---

## 16. Implementation Status

Tracks what has been implemented in the `stateful-abac-policy-engine` project.

### 16.1 Completed (Tested)

| Component | Location | Description |
|-----------|----------|-------------|
| **PostgreSQL Function** | `alembic/versions/58055ca375cf_*.py` | `get_authorization_conditions()` function with proper schema handling |
| **Request/Response Schemas** | `common/schemas/auth.py` | `GetAuthorizationConditionsRequest`, `AuthorizationConditionsResponse` |
| **Auth Service Method** | `common/application/auth_service.py` | `get_authorization_conditions()` method |
| **REST API Endpoint** | `app/api/v1/auth.py` | `POST /get-authorization-conditions` |
| **SDK Models** | `python-sdk/.../models.py` | `AuthorizationConditionsResponse` |
| **SDK Interface** | `python-sdk/.../interfaces/__init__.py` | `IAuthManager.get_authorization_conditions()` |
| **SDK HTTP Manager** | `python-sdk/.../managers/auth.py` | HTTP mode implementation |
| **SDK DB Manager** | `python-sdk/.../db_managers/auth.py` | Direct database mode implementation |
| **Tests** | `tests/test_get_authorization_conditions.py` | 11 comprehensive tests covering all scenarios |

### 16.2 Tested Scenarios

- ✅ Blanket grant (type-level ACL with no conditions) → `granted_all`
- ✅ No ACLs for user → `denied_all`
- ✅ Single conditional ACL → `conditions_dsl` with single condition
- ✅ Multiple conditional ACLs via different roles → `conditions_dsl` with OR-combined conditions
- ✅ Resource-level ACLs → merged into `conditions_dsl` as IN clause
- ✅ Mixed type-level and resource-level ACLs → unified `conditions_dsl` with OR structure
- ✅ Context references in conditions → `has_context_refs = true`
- ✅ HTTP API endpoint integration
- ✅ SDK HTTP mode
- ✅ SDK DB mode

### 16.3 Not Yet Implemented

| Component | Notes |
|-----------|-------|
| **py-cqrs-ddd-auth library** | The auth library with `ABACConditionConverter` and `StatefulABACAuthorizationAdapter` |
| **FieldMapping** | Application-side field name remapping for SearchQuery conversion |
| **SearchQuery.merge()** | Already exists in `search_query_dsl`, but integration not yet done |
| **Framework Middleware** | FastAPI/Django authorization middleware using the new endpoint |

### 16.4 Key Implementation Details

1. **Schema differences from proposal**:
   - Table is `acl` (singular), not `acls`
   - No `effect` column - all ACLs are grants by default
   - External IDs stored in separate `external_ids` table, joined via `resource_id`
   - Resource-level grants are merged into `conditions_dsl` as IN clauses (not separate field)
   - Must check both SQL `NULL` and JSON `null` for empty conditions

2. **Unique constraint limitation**:
   - Cannot have multiple ACLs with same `(realm, resource_type, action, principal/role, resource_id)` tuple
   - Use different roles to achieve multiple conditional grants that are OR-combined

3. **Condition DSL structure**:
   - **Sources**: `resource` (default), `principal`, `context`
   - **Comparison operators**: `=`, `!=`, `<`, `>`, `<=`, `>=`, `in`
   - **Logical operators**: `and`, `or`, `not` (with nested `conditions` array; `not` takes a single `condition`)
   - **Spatial operators**: `st_dwithin`, `st_contains`, `st_within`, `st_intersects`, `st_covers`
   - **Value references**: `$resource.*`, `$principal.*`, `$context.*`
   - See `python-sdk/src/stateful_abac_sdk/manifest/builder.py` for fluent `ConditionBuilder` API

4. **SDK usage pattern**:
   ```python
   async with client.connect(token=access_token):
       result = await client.auth.get_authorization_conditions(
           resource_type_name="element",
           action_name="read",
           role_names=["admin"]  # Optional: override active roles
       )
   ```

