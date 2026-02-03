from typing import Optional, Callable
import logging
from fastapi import Request, Depends, HTTPException
from dependency_injector.wiring import inject, Provide

from cqrs_ddd_auth.identity import (
    Identity,
    AuthenticatedIdentity,
    AnonymousIdentity,
    get_identity as _get_identity,
)
from cqrs_ddd_auth.infrastructure.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.factory import create_default_idp
from cqrs_ddd_auth.infrastructure.adapters.tokens import (
    TokenSource,
    TokenExtractionResult,
)

logger = logging.getLogger(__name__)


def extract_tokens(
    request: Request,
    cookie_name: str = "access_token",
    refresh_cookie_name: str = "refresh_token",
) -> TokenExtractionResult:
    """
    Extract tokens from FastAPI request, auto-detecting source.
    """
    # 1. Check Authorization header first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return TokenExtractionResult(
            access_token=auth_header[7:],
            refresh_token=request.headers.get("X-Refresh-Token"),
            source=TokenSource.HEADER,
        )

    # 2. Fall back to cookies
    access = request.cookies.get(cookie_name)
    if access:
        return TokenExtractionResult(
            access_token=access,
            refresh_token=request.cookies.get(refresh_cookie_name),
            source=TokenSource.COOKIE,
        )

    return TokenExtractionResult()


async def get_optional_token(request: Request) -> Optional[str]:
    """Get access token from request (header or cookie)."""
    refreshed = getattr(request.state, "refreshed_access_token", None)
    if refreshed:
        return refreshed

    tokens = extract_tokens(request)
    return tokens.access_token


@inject
async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(get_optional_token),
    idp: Optional[IdentityProviderPort] = Depends(
        Provide[AuthContainer.identity_provider]
    ),
) -> Identity:
    """Dependency that returns the current user identity."""
    if idp is None:
        idp = getattr(request.state, "identity_provider", None)
        if idp is None:
            idp = create_default_idp()

    identity = _get_identity()
    if identity.is_authenticated:
        return identity

    if not token:
        return AnonymousIdentity()

    if not idp:
        logger.warning("get_current_user: No IdentityProviderPort available")
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
    """Dependency that requires authentication."""
    if not identity.is_authenticated:
        raise HTTPException(
            status_code=401,
            detail={"error": "UNAUTHORIZED", "message": "Authentication required"},
        )
    return identity


def require_groups(*required_groups: str) -> Callable:
    """Factory for dependency that requires specific group membership."""

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


def get_identity() -> Identity:
    """Get current identity from context."""
    return _get_identity()


def create_get_identity_dependency(
    idp: "IdentityProviderPort",
) -> Callable:
    """
    Factory to create get_identity dependency with IdP injected.
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
