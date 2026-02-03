from typing import Any, List
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.urls import path
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
from .decorators import require_authenticated, require_groups
from cqrs_ddd_auth.identity import get_identity
from cqrs_ddd.contrib.django import CQRSView


from cqrs_ddd_auth.domain.errors import (
    AuthenticationError,
    AuthorizationError,
    UserNotFoundError,
    InvalidOTPError,
    OTPRateLimitError,
    UserManagementError,
    OTPError,
    AuthDomainError,
)

from dataclasses import is_dataclass, asdict


class AuthView(CQRSView):
    """
    Base view for Auth endpoints, resolving container automatically.
    """

    @inject
    def __init__(self, container: AuthContainer = Provide[AuthContainer], **kwargs):
        super().__init__(**kwargs)
        self.container = container

    def success(self, data: Any, status: int = 200) -> JsonResponse:
        if is_dataclass(data):
            data = asdict(data)
        return super().success(data, status)

    async def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        try:
            return await super().dispatch(request, *args, **kwargs)
        except AuthenticationError as e:
            return JsonResponse(
                {"error": e.code, "message": str(e), "details": e.details}, status=401
            )
        except AuthorizationError as e:
            return JsonResponse(
                {"error": e.code, "message": str(e), "details": e.details}, status=403
            )
        except UserNotFoundError as e:
            return JsonResponse(
                {"error": e.code, "message": str(e), "details": e.details}, status=404
            )
        except (
            InvalidOTPError,
            OTPRateLimitError,
            UserManagementError,
            OTPError,
            AuthDomainError,
        ) as e:
            code = getattr(e, "code", "AUTH_ERROR")
            details = getattr(e, "details", {})
            return JsonResponse(
                {"error": code, "message": str(e), "details": details}, status=400
            )


class LoginView(AuthView):
    async def post(self, request: HttpRequest) -> JsonResponse:
        data = self.parse_body(request)

        cmd = AuthenticateWithCredentials(
            username=data.get("username"),
            password=data.get("password"),
            track_session=data.get("track_session", False),
            ip_address=request.META.get("REMOTE_ADDR", ""),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            otp_method=data.get("otp_method"),
            otp_code=data.get("otp_code"),
        )

        result = await self.dispatch_command(cmd)

        if result.status == "failed":
            return self.error(result.error_message, status=401)

        return self.success(result)


class RefreshView(AuthView):
    async def post(self, request: HttpRequest) -> JsonResponse:
        data = self.parse_body(request)
        cmd = RefreshTokens(refresh_token=data.get("refresh_token"))
        result = await self.dispatch_command(cmd)
        return self.success(result)


class LogoutView(AuthView):
    async def post(self, request: HttpRequest) -> JsonResponse:
        data = self.parse_body(request)
        cmd = Logout(refresh_token=data.get("refresh_token"))
        result = await self.dispatch_command(cmd)
        return self.success(result)


class MeView(AuthView):
    @require_authenticated
    async def get(self, request: HttpRequest) -> JsonResponse:
        identity = get_identity()
        query = GetUserInfo(user_id=identity.user_id)
        result = await self.dispatch_query(query)
        return self.success(result)


class TOTPSetupView(AuthView):
    @require_authenticated
    async def post(self, request: HttpRequest) -> JsonResponse:
        identity = get_identity()
        cmd = SetupTOTP(user_id=identity.user_id)
        result = await self.dispatch_command(cmd)
        return self.success(result)


class ListUsersView(AuthView):
    @require_groups("/admin")
    async def get(self, request: HttpRequest) -> JsonResponse:
        query = ListUsers(
            search=request.GET.get("search"),
            role=request.GET.get("role"),
            offset=int(request.GET.get("offset", 0)),
            limit=int(request.GET.get("limit", 100)),
        )
        result = await self.dispatch_query(query)
        return self.success(result)


def get_auth_urls() -> List[Any]:
    """
    Factory to get URL patterns for auth endpoints.
    """
    return [
        path("login/", LoginView.as_view(), name="auth_login"),
        path("refresh/", RefreshView.as_view(), name="auth_refresh"),
        path("logout/", LogoutView.as_view(), name="auth_logout"),
        path("me/", MeView.as_view(), name="auth_me"),
        path("totp/setup/", TOTPSetupView.as_view(), name="auth_totp_setup"),
        path("users/", ListUsersView.as_view(), name="auth_users"),
    ]
