"""
FastAPI integration for py-cqrs-ddd-auth.

Provides dependencies, middleware, and utilities for authentication
and token handling in FastAPI applications.

Example usage:
    from fastapi import FastAPI, Depends
    from cqrs_ddd_auth.contrib.fastapi import (
        get_identity,
        get_current_user,
        require_authenticated,
        require_groups,
    )
    
    app = FastAPI()
    
    @app.get("/protected")
    async def protected_endpoint(identity: Identity = Depends(get_current_user)):
        return {"user": identity.username}
"""

from dataclasses import dataclass
from typing import Optional, Callable, List, Any
from functools import wraps
import logging

from fastapi import Request, Response, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from dependency_injector.wiring import inject, Provide
    HAS_DI = True
except ImportError:
    HAS_DI = False
    # Define dummy decorators/classes if DI not installed
    def inject(f): return f
    class Provide: 
        def __getitem__(self, item): return None
    Provide = Provide()

from cqrs_ddd_auth.adapters.tokens import (
    TokenSource,
    TokenExtractionResult,
    TokenRefreshResult,
    TokenRefreshAdapter,
)
from cqrs_ddd_auth.identity import (
    Identity,
    AuthenticatedIdentity,
    AnonymousIdentity,
    get_identity as _get_identity,
    set_identity,
    set_access_token,
)
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort

logger = logging.getLogger(__name__)

# OAuth2 scheme for OpenAPI documentation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ═══════════════════════════════════════════════════════════════
# TOKEN EXTRACTION
# ═══════════════════════════════════════════════════════════════

def extract_tokens(
    request: Request,
    cookie_name: str = "access_token",
    refresh_cookie_name: str = "refresh_token",
) -> TokenExtractionResult:
    """
    Extract tokens from FastAPI request, auto-detecting source.
    
    Priority: Header > Cookie
    """
    # 1. Check Authorization header first (API/mobile clients)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return TokenExtractionResult(
            access_token=auth_header[7:],
            refresh_token=request.headers.get("X-Refresh-Token"),
            source=TokenSource.HEADER,
        )
    
    # 2. Fall back to cookies (web clients)
    access = request.cookies.get(cookie_name)
    if access:
        return TokenExtractionResult(
            access_token=access,
            refresh_token=request.cookies.get(refresh_cookie_name),
            source=TokenSource.COOKIE,
        )
    
    return TokenExtractionResult()


def attach_tokens(
    response: Response,
    result: TokenRefreshResult,
    source: TokenSource,
    cookie_secure: bool = True,
    cookie_samesite: str = "lax",
    cookie_max_age: int = 86400,
) -> None:
    """
    Attach tokens to response via the same channel they arrived.
    """
    if not result.was_refreshed:
        return
    
    if source == TokenSource.HEADER:
        # API/mobile: Return in response headers
        response.headers["X-New-Access-Token"] = result.new_access_token
        if result.new_refresh_token:
            response.headers["X-New-Refresh-Token"] = result.new_refresh_token
    else:
        # Web: Set httpOnly cookies
        response.set_cookie(
            "access_token",
            result.new_access_token,
            httponly=True,
            secure=cookie_secure,
            samesite=cookie_samesite,
            max_age=cookie_max_age,
        )
        if result.new_refresh_token:
            response.set_cookie(
                "refresh_token",
                result.new_refresh_token,
                httponly=True,
                secure=cookie_secure,
                samesite=cookie_samesite,
                max_age=cookie_max_age,
            )


# ═══════════════════════════════════════════════════════════════
# DEPENDENCIES
# ═══════════════════════════════════════════════════════════════

async def get_optional_token(request: Request) -> Optional[str]:
    """
    Get access token from request (header or cookie).
    
    Returns None if no token found.
    """
    # Check for refreshed token first
    refreshed = getattr(request.state, "refreshed_access_token", None)
    if refreshed:
        return refreshed
    
    tokens = extract_tokens(request)
    return tokens.access_token


def create_get_identity_dependency(
    idp: "IdentityProviderPort",
) -> Callable:
    """
    Factory to create get_identity dependency with IdP injected.
    
    Usage:
        from dependency_injector.wiring import inject, Provide
        
        get_identity = create_get_identity_dependency(container.idp())
        
        @app.get("/me")
        async def me(identity: Identity = Depends(get_identity)):
            return {"user": identity.username}
    """
    async def get_identity_dep(
        request: Request,
        token: Optional[str] = Depends(get_optional_token),
    ) -> Identity:
        if not token:
            return AnonymousIdentity()
        
        try:
            claims = await idp.decode_token(token)
            return AuthenticatedIdentity(
                user_id=claims.sub,
                username=claims.username,
                groups=list(claims.groups) if claims.groups else [],
                permissions=[],
                tenant_id=claims.attributes.get("tenant_id"),
            )
        except Exception as e:
            logger.warning(f"Token decode failed: {e}")
            return AnonymousIdentity()
    
    return get_identity_dep


def get_identity() -> Identity:
    """
    Get current identity from context.
    
    Use this after AuthenticationMiddleware has run.
    """
    return _get_identity()


@inject
async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(get_optional_token),
    idp: Optional["IdentityProviderPort"] = Depends(Provide[AuthContainer.identity_provider] if HAS_DI else lambda: None),
) -> Identity:
    """
    Dependency that returns the current user identity.
    
    Requires IdP to be injected via request.state or middleware.
    
    Usage:
        @app.get("/me")
        async def me(user: Identity = Depends(get_current_user)):
            return {"username": user.username}

    If Dependency Injector is available and wired, it resolves the IdentityProviderPort.
    Otherwise, it expects the IdP to be provided via middleware or manual injection.
    """
    # 1. If middleware already set identity, use it
    identity = _get_identity()
    if identity.is_authenticated:
        return identity
    
    # 2. If no token, return anonymous
    if not token:
        return AnonymousIdentity()
        
    # 3. If we have a token but no IDP was injected, we can't decode
    if not idp:
        logger.warning("get_current_user: No IdentityProviderPort available for token decoding")
        return AnonymousIdentity()
        
    try:
        claims = await idp.decode_token(token)
        return AuthenticatedIdentity(
            user_id=claims.sub,
            username=claims.username,
            groups=list(claims.groups) if claims.groups else [],
            permissions=[],
            tenant_id=claims.attributes.get("tenant_id"),
        )
    except Exception as e:
        logger.warning(f"Token decode failed in dependency: {e}")
        return AnonymousIdentity()


def require_authenticated(identity: Identity = Depends(get_current_user)) -> Identity:
    """
    Dependency that requires authentication.
    
    Raises HTTPException 401 if user is not authenticated.
    
    Usage:
        @app.get("/protected")
        async def protected(user: Identity = Depends(require_authenticated)):
            return {"user": user.username}
    """
    if not identity.is_authenticated:
        raise HTTPException(
            status_code=401,
            detail={"error": "UNAUTHORIZED", "message": "Authentication required"},
        )
    return identity


def require_groups(*required_groups: str) -> Callable:
    """
    Factory for dependency that requires specific group membership.
    
    Usage:
        @app.get("/admin")
        async def admin(
            user: Identity = Depends(require_groups("/admin", "/superuser"))
        ):
            return {"admin": user.username}
    """
    async def dependency(
        identity: Identity = Depends(require_authenticated),
    ) -> Identity:
        user_groups = set(identity.groups)
        if not any(g in user_groups for g in required_groups):
            raise HTTPException(
                status_code=403,
                detail={"error": "FORBIDDEN", "message": "Insufficient permissions"},
            )
        return identity
    
    return dependency


# ═══════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════

class TokenRefreshMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for transparent token refresh.
    
    Auto-detects token source and responds via the same channel.
    
    Usage:
        from cqrs_ddd_auth.contrib.fastapi import TokenRefreshMiddleware
        
        app.add_middleware(
            TokenRefreshMiddleware,
            idp=container.idp(),
            public_paths=["/health", "/api/auth/login"],
        )
    """
    
    @inject
    def __init__(
        self,
        app,
        idp: Optional["IdentityProviderPort"] = Provide[AuthContainer.identity_provider],
        public_paths: Optional[List[str]] = None,
        threshold_seconds: int = 60,
        cookie_secure: bool = True,
        cookie_samesite: str = "lax",
        cookie_max_age: int = 86400,
    ):
        super().__init__(app)
        if idp is None:
            raise ValueError("IdentityProviderPort is required for TokenRefreshMiddleware")
            
        self.adapter = TokenRefreshAdapter(idp, threshold_seconds)
        self.public_paths = public_paths or ["/health", "/api/auth/login"]
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_max_age = cookie_max_age
    
    def _is_public(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.public_paths)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        if self._is_public(request.url.path):
            return await call_next(request)
        
        tokens = extract_tokens(request)
        
        if not tokens.is_present:
            return await call_next(request)
        
        result = await self.adapter.process_request(
            tokens.access_token,
            tokens.refresh_token,
        )
        
        if result.needs_auth:
            raise HTTPException(
                status_code=401,
                detail={"error": "UNAUTHORIZED", "message": "Authentication required"},
            )
        
        if result.was_refreshed:
            # Store refreshed token for downstream dependencies
            request.state.refreshed_access_token = result.new_access_token
            
            response = await call_next(request)
            
            attach_tokens(
                response,
                result,
                tokens.source,
                self.cookie_secure,
                self.cookie_samesite,
                self.cookie_max_age,
            )
            return response
        
        return await call_next(request)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for authentication context.
    
    Sets identity in context for downstream handlers.
    
    Usage:
        app.add_middleware(
            AuthenticationMiddleware,
            idp=container.idp(),
            public_paths=["/health"],
        )
    """
    
    @inject
    def __init__(
        self,
        app,
        idp: Optional["IdentityProviderPort"] = Provide[AuthContainer.identity_provider],
        public_paths: Optional[List[str]] = None,
    ):
        super().__init__(app)
        if idp is None:
            raise ValueError("IdentityProviderPort is required for AuthenticationMiddleware")
            
        self.idp = idp
        self.public_paths = public_paths or ["/health"]
    
    def _is_public(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.public_paths)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        if self._is_public(request.url.path):
            set_identity(AnonymousIdentity())
            return await call_next(request)
        
        # Check for refreshed token
        access_token = getattr(request.state, "refreshed_access_token", None)
        
        if not access_token:
            tokens = extract_tokens(request)
            access_token = tokens.access_token
        
        if not access_token:
            set_identity(AnonymousIdentity())
            return await call_next(request)
        
        try:
            claims = await self.idp.decode_token(access_token)
            
            identity = AuthenticatedIdentity(
                user_id=claims.sub,
                username=claims.username,
                groups=list(claims.groups) if claims.groups else [],
                permissions=[],
                tenant_id=claims.attributes.get("tenant_id"),
            )
            
            set_identity(identity)
            set_access_token(access_token)
            
        except Exception as e:
            logger.warning(f"Token decode failed: {e}")
            set_identity(AnonymousIdentity())
        
        return await call_next(request)


# Type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort
