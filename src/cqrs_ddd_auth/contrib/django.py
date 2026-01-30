"""
Django integration for py-cqrs-ddd-auth.

Provides middleware for authentication, token refresh,
and identity context propagation.

Example usage in settings.py:
    MIDDLEWARE = [
        ...
        'cqrs_ddd_auth.contrib.django.TokenRefreshMiddleware',
        'cqrs_ddd_auth.contrib.django.AuthenticationMiddleware',
        ...
    ]
"""

from dataclasses import dataclass
from typing import Optional, Callable, Awaitable, List
import logging

from django.http import JsonResponse, HttpRequest, HttpResponse
from django.conf import settings

from cqrs_ddd_auth.adapters.tokens import (
    TokenSource,
    TokenExtractionResult,
    TokenRefreshResult,
    TokenRefreshAdapter,
)
from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.identity import (
    AuthenticatedIdentity,
    AnonymousIdentity,
    set_identity,
    set_access_token,
)
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.factory import create_default_idp

try:
    from dependency_injector.wiring import inject, Provide
    HAS_DI = True
except ImportError:
    HAS_DI = False
    # Define dummy decorators/classes if DI not installed
    def inject(f): return f
    class Provide: 
        def __getitem__(self, item): 
            # Return a dummy callable so it can be used in dependencies
            return lambda: None
    Provide = Provide()

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# TOKEN EXTRACTION
# ═══════════════════════════════════════════════════════════════

def extract_tokens(
    request: HttpRequest,
    cookie_name: str = "access_token",
    refresh_cookie_name: str = "refresh_token",
    header_name: str = "Authorization",
    refresh_header_name: str = "X-Refresh-Token",
) -> TokenExtractionResult:
    """
    Extract tokens from request, auto-detecting source.
    
    Priority: Header > Cookie
    
    Args:
        request: Django HttpRequest
        cookie_name: Name of access token cookie
        refresh_cookie_name: Name of refresh token cookie
        header_name: Authorization header name
        refresh_header_name: Refresh token header name
    
    Returns:
        TokenExtractionResult with tokens and their source
    """
    # 1. Check Authorization header first (API/mobile clients)
    auth_header = request.headers.get(header_name, "")
    if auth_header.startswith("Bearer "):
        return TokenExtractionResult(
            access_token=auth_header[7:],
            refresh_token=request.headers.get(refresh_header_name),
            source=TokenSource.HEADER,
        )
    
    # 2. Fall back to cookies (web clients)
    access = request.COOKIES.get(cookie_name)
    if access:
        return TokenExtractionResult(
            access_token=access,
            refresh_token=request.COOKIES.get(refresh_cookie_name),
            source=TokenSource.COOKIE,
        )
    
    return TokenExtractionResult()


def attach_tokens(
    response: HttpResponse,
    result: TokenRefreshResult,
    source: TokenSource,
    cookie_secure: bool = True,
    cookie_samesite: str = "Lax",
    cookie_max_age: int = 86400,
) -> None:
    """
    Attach tokens to response via the same channel they arrived.
    
    Args:
        response: Django HttpResponse
        result: Token refresh result with new tokens
        source: Where tokens came from (determines delivery method)
        cookie_secure: Set Secure flag on cookies
        cookie_samesite: SameSite attribute for cookies
        cookie_max_age: Cookie max age in seconds
    """
    if not result.was_refreshed:
        return
    
    if source == TokenSource.HEADER:
        # API/mobile: Return in response headers
        response["X-New-Access-Token"] = result.new_access_token
        if result.new_refresh_token:
            response["X-New-Refresh-Token"] = result.new_refresh_token
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
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════

class TokenRefreshMiddleware:
    """
    Django ASGI middleware for transparent token refresh.
    
    Auto-detects token source (header vs cookie) and responds accordingly.
    No custom headers required from clients.
    
    Usage:
        # In settings.py
        MIDDLEWARE = [
            ...
            'cqrs_ddd_auth.contrib.django.TokenRefreshMiddleware',
            ...
        ]
        
        # Configure via settings
        AUTH_TOKEN_REFRESH_THRESHOLD = 60  # seconds
        AUTH_COOKIE_SECURE = True
        AUTH_COOKIE_SAMESITE = 'Lax'
        AUTH_COOKIE_MAX_AGE = 86400
    """
    
    async_capable = True
    sync_capable = False
    
    @inject
    def __init__(
        self,
        get_response,
        idp: Optional[IdentityProviderPort] = Provide[AuthContainer.identity_provider],
    ):
        self.get_response = get_response
        
        # Resolve IDP if it's the dummy callable (Standalone mode)
        if not HAS_DI and callable(idp):
            idp = idp()
            
        if idp is None:
            idp = create_default_idp()
                
        if idp is None:
            # We don't raise here yet to allow public paths to work, 
            # but process_request will fail if tokens present.
            self._idp = None
            self._adapter = None
        else:
            self._idp = idp
            threshold = getattr(settings, "AUTH_TOKEN_REFRESH_THRESHOLD", 60)
            self._adapter = TokenRefreshAdapter(self._idp, threshold)
            
        self._public_paths: List[str] = getattr(settings, "AUTH_PUBLIC_PATHS", [
            "/health",
            "/api/auth/login",
            "/api/auth/refresh",
        ])
    
    def _is_public(self, path: str) -> bool:
        """Check if path is public (no auth required)."""
        return any(path.startswith(p) for p in self._public_paths)
    
    async def __call__(self, request: HttpRequest) -> HttpResponse:
        if self._is_public(request.path):
            return await self.get_response(request)
        
        # Auto-detect: extract tokens and remember where they came from
        tokens = extract_tokens(request)
        
        if not tokens.is_present:
            # No tokens found, let auth middleware handle 401
            return await self.get_response(request)
        
        if self._adapter is None:
            raise ValueError("IdentityProviderPort is required for TokenRefreshMiddleware (tokens detected)")
            
        # Delegate to adapter
        result = await self._adapter.process_request(
            tokens.access_token,
            tokens.refresh_token,
        )
        
        if result.needs_auth:
            return JsonResponse(
                {"error": "UNAUTHORIZED", "message": "Authentication required"},
                status=401,
            )
        
        if result.was_refreshed:
            # Inject refreshed token for downstream middleware
            request._refreshed_access_token = result.new_access_token
            
            # Process request with fresh token
            response = await self.get_response(request)
            
            # Return tokens via the same channel they arrived
            attach_tokens(
                response,
                result,
                tokens.source,
                cookie_secure=getattr(settings, "AUTH_COOKIE_SECURE", True),
                cookie_samesite=getattr(settings, "AUTH_COOKIE_SAMESITE", "Lax"),
                cookie_max_age=getattr(settings, "AUTH_COOKIE_MAX_AGE", 86400),
            )
            return response
        
        return await self.get_response(request)


class AuthenticationMiddleware:
    """
    Django ASGI middleware for authentication context.
    
    Extracts tokens, decodes JWT, and sets identity context.
    Works with both header and cookie tokens.
    
    Usage:
        # In settings.py
        MIDDLEWARE = [
            ...
            'cqrs_ddd_auth.contrib.django.TokenRefreshMiddleware',  # Optional
            'cqrs_ddd_auth.contrib.django.AuthenticationMiddleware',
            ...
        ]
    """
    
    async_capable = True
    sync_capable = False
    
    @inject
    def __init__(
        self,
        get_response,
        idp: Optional[IdentityProviderPort] = Provide[AuthContainer.identity_provider],
    ):
        self.get_response = get_response
        
        # Resolve IDP if it's the dummy callable (Standalone mode)
        if not HAS_DI and callable(idp):
            idp = idp()
            
        if idp is None:
            idp = create_default_idp()
                
        self._idp = idp
        self._public_paths: List[str] = getattr(settings, "AUTH_PUBLIC_PATHS", [
            "/health",
            "/api/auth/login",
        ])
    
    def _is_public(self, path: str) -> bool:
        """Check if path is public."""
        return any(path.startswith(p) for p in self._public_paths)
    
    async def __call__(self, request: HttpRequest) -> HttpResponse:
        if self._is_public(request.path):
            set_identity(AnonymousIdentity())
            return await self.get_response(request)
        
        # Check for refreshed token first
        access_token = getattr(request, "_refreshed_access_token", None)
        
        if not access_token:
            tokens = extract_tokens(request)
            access_token = tokens.access_token
        
        if not access_token:
            set_identity(AnonymousIdentity())
            return await self.get_response(request)
            
        if self._idp is None:
            logger.warning("AuthenticationMiddleware: No IdentityProviderPort available for token decoding")
            set_identity(AnonymousIdentity())
            return await self.get_response(request)
        
        try:
            claims = await self._idp.decode_token(access_token)
            
            identity = AuthenticatedIdentity(
                user_id=claims.sub,
                username=claims.username,
                groups=list(claims.groups) if claims.groups else [],
                permissions=[],  # Fetched separately from ABAC
                tenant_id=claims.attributes.get("tenant_id"),
            )
            
            set_identity(identity)
            set_access_token(access_token)
            
        except Exception as e:
            logger.warning(f"Token decode failed: {e}")
            set_identity(AnonymousIdentity())
        
        return await self.get_response(request)


# ═══════════════════════════════════════════════════════════════
# DECORATORS
# ═══════════════════════════════════════════════════════════════

def require_authenticated(view_func: Callable) -> Callable:
    """
    Decorator to require authentication for a view.
    
    Usage:
        @require_authenticated
        async def my_view(request):
            identity = get_identity()
            ...
    """
    from functools import wraps
    from cqrs_ddd_auth.identity import get_identity
    
    @wraps(view_func)
    async def wrapper(request, *args, **kwargs):
        identity = get_identity()
        if not identity.is_authenticated:
            return JsonResponse(
                {"error": "UNAUTHORIZED", "message": "Authentication required"},
                status=401,
            )
        return await view_func(request, *args, **kwargs)
    
    return wrapper


def require_groups(*required_groups: str) -> Callable:
    """
    Decorator to require specific group membership.
    
    Usage:
        @require_groups("/web_user", "/admin")
        async def my_view(request):
            ...
    """
    from functools import wraps
    from cqrs_ddd_auth.identity import get_identity
    
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        async def wrapper(request, *args, **kwargs):
            identity = get_identity()
            if not identity.is_authenticated:
                return JsonResponse(
                    {"error": "UNAUTHORIZED", "message": "Authentication required"},
                    status=401,
                )
            
            user_groups = set(identity.groups)
            if not any(g in user_groups for g in required_groups):
                return JsonResponse(
                    {"error": "FORBIDDEN", "message": "Insufficient permissions"},
                    status=403,
                )
            
            return await view_func(request, *args, **kwargs)
        
        return wrapper
    
    return decorator
