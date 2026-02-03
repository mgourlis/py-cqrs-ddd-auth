from unittest.mock import Mock, AsyncMock
from django.test import RequestFactory
from django.http import HttpResponse
import pytest
from cqrs_ddd_auth.contrib.django.middleware import AuthenticationMiddleware
from cqrs_ddd_auth.identity import get_identity


@pytest.fixture
def request_factory():
    return RequestFactory()


@pytest.fixture
def mock_get_response():
    return AsyncMock(return_value=HttpResponse("OK"))


@pytest.mark.django_db
@pytest.mark.asyncio
class TestAuthenticationMiddleware:
    async def test_process_request_public_path(
        self, request_factory, mock_get_response
    ):
        request = request_factory.get("/api/auth/login")
        middleware = AuthenticationMiddleware(get_response=mock_get_response)

        await middleware(request)

        identity = get_identity()
        assert not identity.is_authenticated

    async def test_process_request_no_token(self, request_factory, mock_get_response):
        request = request_factory.get("/")
        middleware = AuthenticationMiddleware(get_response=mock_get_response)

        await middleware(request)

        identity = get_identity()
        assert not identity.is_authenticated

    async def test_process_request_invalid_token(
        self, request_factory, mock_get_response
    ):
        request = request_factory.get("/", HTTP_AUTHORIZATION="Bearer invalid_token")

        mock_idp = Mock()
        mock_idp.decode_token = AsyncMock(side_effect=ValueError("Invalid token"))

        middleware = AuthenticationMiddleware(
            get_response=mock_get_response, idp=mock_idp
        )
        await middleware(request)

        identity = get_identity()
        assert not identity.is_authenticated

    async def test_process_request_valid_token(
        self, request_factory, mock_get_response
    ):
        request = request_factory.get("/", HTTP_AUTHORIZATION="Bearer valid_token")

        mock_idp = Mock()
        mock_claims = Mock(sub="user123", username="testuser", groups=[])
        # attributes is a dict
        mock_claims.attributes = {}
        mock_idp.decode_token = AsyncMock(return_value=mock_claims)

        middleware = AuthenticationMiddleware(
            get_response=mock_get_response, idp=mock_idp
        )
        await middleware(request)

        identity = get_identity()
        assert identity.is_authenticated
        assert identity.user_id == "user123"


@pytest.mark.django_db
@pytest.mark.asyncio
class TestTokenRefreshMiddleware:
    async def test_extract_tokens_header(self, request_factory):
        from cqrs_ddd_auth.contrib.django.middleware import extract_tokens
        from cqrs_ddd_auth.infrastructure.adapters.tokens import TokenSource

        request = request_factory.get("/", HTTP_AUTHORIZATION="Bearer at")
        tokens = extract_tokens(request)
        assert tokens.access_token == "at"
        assert tokens.source == TokenSource.HEADER

    async def test_extract_tokens_cookie(self, request_factory):
        from cqrs_ddd_auth.contrib.django.middleware import extract_tokens
        from cqrs_ddd_auth.infrastructure.adapters.tokens import TokenSource

        request = request_factory.get("/")
        request.COOKIES["access_token"] = "at"
        request.COOKIES["refresh_token"] = "rt"
        tokens = extract_tokens(request)
        assert tokens.access_token == "at"
        assert tokens.refresh_token == "rt"
        assert tokens.source == TokenSource.COOKIE

    async def test_public_path_skipped(self, request_factory, mock_get_response):
        from cqrs_ddd_auth.contrib.django.middleware import TokenRefreshMiddleware

        request = request_factory.get("/health")
        middleware = TokenRefreshMiddleware(get_response=mock_get_response, idp=Mock())
        await middleware(request)
        mock_get_response.assert_called()

    async def test_no_tokens_skipped(self, request_factory, mock_get_response):
        from cqrs_ddd_auth.contrib.django.middleware import TokenRefreshMiddleware

        request = request_factory.get("/protected")
        middleware = TokenRefreshMiddleware(get_response=mock_get_response, idp=Mock())
        await middleware(request)
        mock_get_response.assert_called()

    async def test_missing_idp_error(self, request_factory, mock_get_response):
        from cqrs_ddd_auth.contrib.django.middleware import TokenRefreshMiddleware

        request = request_factory.get("/protected", HTTP_AUTHORIZATION="Bearer at")
        middleware = TokenRefreshMiddleware(get_response=mock_get_response, idp=Mock())
        middleware._adapter = None

        with pytest.raises(ValueError):
            await middleware(request)

    async def test_refresh_flow_refreshed(self, request_factory, mock_get_response):
        from cqrs_ddd_auth.contrib.django.middleware import TokenRefreshMiddleware

        request = request_factory.get("/protected", HTTP_AUTHORIZATION="Bearer old_at")

        mock_idp = Mock()
        middleware = TokenRefreshMiddleware(
            get_response=mock_get_response, idp=mock_idp
        )

        # Mock adapter response
        from cqrs_ddd_auth.refresh import TokenRefreshResult

        result = TokenRefreshResult(
            new_access_token="new_at", new_refresh_token="new_rt"
        )
        middleware._adapter.process_request = AsyncMock(return_value=result)

        response = await middleware(request)

        assert request._refreshed_access_token == "new_at"
        assert response["X-New-Access-Token"] == "new_at"
        assert response["X-New-Refresh-Token"] == "new_rt"
        mock_get_response.assert_called()

    async def test_refresh_flow_cookies(self, request_factory, mock_get_response):
        from cqrs_ddd_auth.contrib.django.middleware import TokenRefreshMiddleware

        request = request_factory.get("/")
        request.COOKIES["access_token"] = "old_at"
        request.COOKIES["refresh_token"] = "old_rt"

        mock_idp = Mock()
        middleware = TokenRefreshMiddleware(
            get_response=mock_get_response, idp=mock_idp
        )

        from cqrs_ddd_auth.refresh import TokenRefreshResult

        result = TokenRefreshResult(
            new_access_token="new_at", new_refresh_token="new_rt"
        )
        middleware._adapter.process_request = AsyncMock(return_value=result)

        response = await middleware(request)

        # Check response cookies
        assert response.cookies["access_token"].value == "new_at"
        assert response.cookies["refresh_token"].value == "new_rt"

    async def test_refresh_flow_unauthorized(self, request_factory, mock_get_response):
        from cqrs_ddd_auth.contrib.django.middleware import TokenRefreshMiddleware

        request = request_factory.get("/protected", HTTP_AUTHORIZATION="Bearer bad_at")

        mock_idp = Mock()
        middleware = TokenRefreshMiddleware(
            get_response=mock_get_response, idp=mock_idp
        )

        from cqrs_ddd_auth.refresh import TokenRefreshResult

        result = TokenRefreshResult(needs_auth=True)
        middleware._adapter.process_request = AsyncMock(return_value=result)

        response = await middleware(request)

        assert response.status_code == 401
