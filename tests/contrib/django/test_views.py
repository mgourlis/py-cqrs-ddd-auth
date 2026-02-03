from unittest.mock import Mock, patch, AsyncMock
from django.test import RequestFactory
from django.http import HttpResponse
from cqrs_ddd_auth.contrib.django.decorators import require_authenticated
from cqrs_ddd_auth.contrib.django.views import LoginView, LogoutView
from cqrs_ddd_auth.application.results import AuthResult, TokenPair, LogoutResult
import pytest
import json


@pytest.fixture
def request_factory():
    return RequestFactory()


@pytest.mark.asyncio
class TestDjangoDecorators:
    async def test_login_required_authenticated(self, request_factory):
        @require_authenticated
        async def view(request):
            return HttpResponse("OK")

        request = request_factory.get("/")
        # The decorator checks identity using get_identity(), so we need to mock that
        with patch(
            "cqrs_ddd_auth.contrib.django.decorators.get_identity"
        ) as mock_get_identity:
            mock_identity = Mock()
            mock_identity.is_authenticated = True
            mock_get_identity.return_value = mock_identity

            response = await view(request)
            assert response.status_code == 200
            assert response.content == b"OK"

    async def test_login_required_unauthenticated(self, request_factory):
        @require_authenticated
        async def view(request):
            return HttpResponse("OK")

        request = request_factory.get("/")

        with patch(
            "cqrs_ddd_auth.contrib.django.decorators.get_identity"
        ) as mock_get_identity:
            mock_identity = Mock()
            mock_identity.is_authenticated = False
            mock_get_identity.return_value = mock_identity

            response = await view(request)
            assert response.status_code == 401


@pytest.mark.asyncio
class TestDjangoViews:
    async def test_login_view_success(self, request_factory):
        # We need to mock the container passed to AuthView OR the provided dependency
        mock_container = Mock()
        mock_mediator = AsyncMock()
        mock_container.mediator = mock_mediator
        # Mock successful auth result
        mock_result = Mock()
        mock_result.is_failure = False  # Result object check
        mock_result.status = "success"
        mock_result.error_message = None

        # Result content depends on what dispatch returns.
        # Command handler returns a Result object.
        mock_result = AuthResult.success(
            tokens=TokenPair(access_token="at", refresh_token="rt"),
            user_id="u1",
            username="u",
        )

        # When creating the view, pass the container explicitly
        view = LoginView(container=mock_container)

        # Mock dispatch_command directly to bypass CQRSView complexity/issues
        view.dispatch_command = AsyncMock(return_value=mock_result)

        data = {"username": "u", "password": "p"}
        request = request_factory.post(
            "/login", data=json.dumps(data), content_type="application/json"
        )

        response = await view.post(request)

        # Inspect response
        assert response.status_code == 200
        view.dispatch_command.assert_awaited()

    async def test_logout_view(self, request_factory):
        mock_container = Mock()
        mock_mediator = AsyncMock()
        mock_container.mediator = mock_mediator

        mock_result = LogoutResult(success=True)

        view = LogoutView(container=mock_container)
        view.dispatch_command = AsyncMock(return_value=mock_result)
        data = {"refresh_token": "rt"}
        request = request_factory.post(
            "/logout", data=json.dumps(data), content_type="application/json"
        )

        response = await view.post(request)
        assert response.status_code == 200
