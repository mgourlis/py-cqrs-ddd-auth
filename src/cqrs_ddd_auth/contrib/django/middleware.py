from typing import Optional
import logging
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.conf import settings
from dependency_injector.wiring import inject, Provide

from cqrs_ddd_auth.infrastructure.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.factory import create_default_idp
from cqrs_ddd_auth.refresh import TokenRefreshAdapter, TokenRefreshResult
from cqrs_ddd_auth.infrastructure.adapters.tokens import (
    TokenSource,
    TokenExtractionResult,
)
from cqrs_ddd_auth.identity import (
    set_identity,
    set_access_token,
    AnonymousIdentity,
    AuthenticatedIdentity,
)

logger = logging.getLogger(__name__)


def extract_tokens(
    request: HttpRequest,
    cookie_name: str = "access_token",
    refresh_cookie_name: str = "refresh_token",
    header_name: str = "Authorization",
    refresh_header_name: str = "X-Refresh-Token",
) -> TokenExtractionResult:
    """Extract tokens from request, auto-detecting source."""
    auth_header = request.headers.get(header_name, "")
    if auth_header.startswith("Bearer "):
        return TokenExtractionResult(
            access_token=auth_header[7:],
            refresh_token=request.headers.get(refresh_header_name),
            source=TokenSource.HEADER,
        )
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
    """Attach tokens to response via the same channel they arrived."""
    if not result.was_refreshed:
        return
    if source == TokenSource.HEADER:
        response["X-New-Access-Token"] = result.new_access_token
        if result.new_refresh_token:
            response["X-New-Refresh-Token"] = result.new_refresh_token
    else:
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


class TokenRefreshMiddleware:
    async_capable = True
    sync_capable = False

    @inject
    def __init__(
        self,
        get_response,
        idp: Optional[IdentityProviderPort] = Provide[AuthContainer.identity_provider],
    ):
        self.get_response = get_response
        if idp is None:
            idp = create_default_idp()
        self._idp = idp
        if idp:
            threshold = getattr(settings, "AUTH_TOKEN_REFRESH_THRESHOLD", 60)
            self._adapter = TokenRefreshAdapter(self._idp, threshold)
        else:
            self._adapter = None
        self._public_paths = getattr(
            settings,
            "AUTH_PUBLIC_PATHS",
            ["/health", "/api/auth/login", "/api/auth/refresh"],
        )

    def _is_public(self, path: str) -> bool:
        return any(path.startswith(p) for p in self._public_paths)

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        if self._is_public(request.path):
            return await self.get_response(request)
        tokens = extract_tokens(request)
        if not tokens.is_present:
            return await self.get_response(request)
        if self._adapter is None:
            raise ValueError(
                "IdentityProviderPort is required for TokenRefreshMiddleware"
            )
        result = await self._adapter.process_request(
            tokens.access_token, tokens.refresh_token
        )
        if result.needs_auth:
            return JsonResponse(
                {"error": "UNAUTHORIZED", "message": "Authentication required"},
                status=401,
            )
        if result.was_refreshed:
            request._refreshed_access_token = result.new_access_token
            response = await self.get_response(request)
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
    async_capable = True
    sync_capable = False

    @inject
    def __init__(
        self,
        get_response,
        idp: Optional[IdentityProviderPort] = Provide[AuthContainer.identity_provider],
    ):
        self.get_response = get_response
        if idp is None:
            idp = create_default_idp()
        self._idp = idp
        self._public_paths = getattr(
            settings, "AUTH_PUBLIC_PATHS", ["/health", "/api/auth/login"]
        )

    def _is_public(self, path: str) -> bool:
        return any(path.startswith(p) for p in self._public_paths)

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        if self._is_public(request.path):
            set_identity(AnonymousIdentity())
            return await self.get_response(request)
        access_token = getattr(request, "_refreshed_access_token", None)
        if not access_token:
            tokens = extract_tokens(request)
            access_token = tokens.access_token
        if not access_token:
            set_identity(AnonymousIdentity())
            return await self.get_response(request)
        if self._idp is None:
            logger.warning("No IdentityProviderPort available")
            set_identity(AnonymousIdentity())
            return await self.get_response(request)
        try:
            claims = await self._idp.decode_token(access_token)
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
        return await self.get_response(request)
