from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from dependency_injector.wiring import inject, Provide

from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.application.commands import (
    AuthenticateWithCredentials,
    RefreshTokens,
    Logout,
    SetupTOTP,
)
from cqrs_ddd_auth.application.queries import (
    GetUserInfo,
    ListUsers,
)
from .dependencies import (
    require_authenticated,
    require_groups,
)
from cqrs_ddd_auth.identity import Identity
from cqrs_ddd.contrib.fastapi import CQRSRouter


class LoginRequest(BaseModel):
    username: str
    password: str
    track_session: bool = False
    otp_method: Optional[str] = None
    otp_code: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


# -----------------------------------------------------------------------------
# Module-level handlers (required for dependency-injector wiring)
# -----------------------------------------------------------------------------


@inject
async def login(
    request: Request,
    data: LoginRequest,
    mediator: Any = Depends(Provide[AuthContainer.mediator]),
):
    cmd = AuthenticateWithCredentials(
        username=data.username,
        password=data.password,
        track_session=data.track_session,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        otp_method=data.otp_method,
        otp_code=data.otp_code,
    )
    result = await mediator.send(cmd)

    if result.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error_message
        )

    return result


@inject
async def totp_setup(
    identity: Identity = Depends(require_authenticated),
    mediator: Any = Depends(Provide[AuthContainer.mediator]),
):
    cmd = SetupTOTP(user_id=identity.user_id)
    result = await mediator.send(cmd)
    return result


@inject
async def me(
    identity: Identity = Depends(require_authenticated),
    mediator: Any = Depends(Provide[AuthContainer.mediator]),
):
    query = GetUserInfo(user_id=identity.user_id)
    result = await mediator.query(query)
    return result


@inject
async def list_users(
    search: Optional[str] = None,
    role: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
    mediator: Any = Depends(Provide[AuthContainer.mediator]),
):
    query = ListUsers(
        search=search,
        role=role,
        offset=offset,
        limit=limit,
    )
    result = await mediator.query(query)
    return result


# -----------------------------------------------------------------------------
# Router Factory
# -----------------------------------------------------------------------------


def create_auth_router() -> APIRouter:
    """
    Factory to create a FastAPI router with authentication endpoints.
    """
    # Use CQRSRouter to benefit from automatic dependency resolution for mediator
    cqrs = CQRSRouter(
        mediator_provider=Provide[AuthContainer.mediator], prefix="/auth", tags=["auth"]
    )

    # Register handlers
    cqrs.router.add_api_route(
        "/login", login, methods=["POST"], status_code=status.HTTP_200_OK
    )

    # Standard command endpoints (CQRSRouter handles these)
    cqrs.command("/refresh", RefreshTokens)
    cqrs.command("/logout", Logout)

    cqrs.router.add_api_route(
        "/totp/setup",
        totp_setup,
        methods=["POST"],
        dependencies=[Depends(require_authenticated)],
    )

    cqrs.router.add_api_route("/me", me, methods=["GET"])

    cqrs.router.add_api_route(
        "/users",
        list_users,
        methods=["GET"],
        dependencies=[Depends(require_groups("/admin"))],
    )

    return cqrs.router
