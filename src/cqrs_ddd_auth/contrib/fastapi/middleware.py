from typing import Optional, List
import logging
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from dependency_injector.wiring import inject, Provide

from cqrs_ddd_auth.infrastructure.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.factory import create_default_idp
from cqrs_ddd_auth.refresh import TokenRefreshAdapter, TokenRefreshResult
from cqrs_ddd_auth.infrastructure.adapters.tokens import TokenSource
from cqrs_ddd_auth.identity import (
    set_identity,
    set_access_token,
    AnonymousIdentity,
    AuthenticatedIdentity,
)
from .dependencies import extract_tokens

logger = logging.getLogger(__name__)


def attach_tokens(
    response: Response,
    result: TokenRefreshResult,
    source: TokenSource,
    cookie_secure: bool = True,
    cookie_samesite: str = "lax",
    cookie_max_age: int = 86400,
) -> None:
    """Attach tokens to response via the same channel they arrived."""
    if not result.was_refreshed:
        return

    if source == TokenSource.HEADER:
        response.headers["X-New-Access-Token"] = result.new_access_token
        if result.new_refresh_token:
            response.headers["X-New-Refresh-Token"] = result.new_refresh_token
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


class TokenRefreshMiddleware(BaseHTTPMiddleware):
    @inject
    def __init__(
        self,
        app,
        idp: Optional[IdentityProviderPort] = Provide[AuthContainer.identity_provider],
        public_paths: Optional[List[str]] = None,
        threshold_seconds: int = 60,
        cookie_secure: bool = True,
        cookie_samesite: str = "lax",
        cookie_max_age: int = 86400,
    ):
        super().__init__(app)
        if idp is None:
            idp = create_default_idp()
        if idp is None:
            raise ValueError(
                "IdentityProviderPort is required for TokenRefreshMiddleware"
            )

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
            tokens.access_token, tokens.refresh_token
        )
        if result.needs_auth:
            raise HTTPException(status_code=401, detail="Authentication required")
        if result.was_refreshed:
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
    @inject
    def __init__(
        self,
        app,
        idp: Optional[IdentityProviderPort] = Provide[AuthContainer.identity_provider],
        public_paths: Optional[List[str]] = None,
    ):
        super().__init__(app)
        if idp is None:
            idp = create_default_idp()
        if idp is None:
            raise ValueError(
                "IdentityProviderPort is required for AuthenticationMiddleware"
            )
        self.idp = idp
        self.public_paths = public_paths or ["/health"]

    def _is_public(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.public_paths)

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._is_public(request.url.path):
            set_identity(AnonymousIdentity())
            return await call_next(request)

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
