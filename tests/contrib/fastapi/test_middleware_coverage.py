from unittest.mock import Mock, AsyncMock
from fastapi import Request, Response
from cqrs_ddd_auth.contrib.fastapi.middleware import AuthenticationMiddleware
from cqrs_ddd_auth.contrib.fastapi.exception_handlers import (
    authentication_error_handler,
    domain_error_handler,
)
from cqrs_ddd_auth.domain.errors import AuthenticationError
from cqrs_ddd_auth.domain.value_objects import UserClaims
import pytest
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.identity import get_identity


@pytest.fixture
def mock_app():
    return Mock()


@pytest.fixture
def container():
    c = AuthContainer()
    c.wire(modules=["cqrs_ddd_auth.contrib.fastapi.middleware"])
    return c


@pytest.mark.asyncio
class TestFastAPIMiddleware:
    async def test_auth_middleware_success(self, container):
        # We need to construct middleware with mocked IDP or allow injection
        mock_idp = AsyncMock()
        mock_idp.decode_token.return_value = UserClaims(
            sub="u1", username="user", email="e", groups=[]
        )

        middleware = AuthenticationMiddleware(app=Mock(), idp=mock_idp)
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer valid_token"}
        request.scope = {"type": "http"}
        request.cookies = {}
        # Ensure getattr works for _refreshed_access_token
        request._refreshed_access_token = None
        # Ensure middleware doesn't treat it as public path
        # Middleware checks request.path or request.url.path
        request.path = "/protected"
        request.url.path = "/protected"

        call_next = AsyncMock(return_value=Response("OK"))

        response = await middleware.dispatch(request, call_next)

        # Verify decode_token was called
        mock_idp.decode_token.assert_awaited()

        identity = get_identity()
        assert identity.is_authenticated
        assert identity.user_id == "u1"
        assert response.body == b"OK"

    async def test_auth_middleware_no_token(self, container):
        middleware = AuthenticationMiddleware(app=Mock(), idp=AsyncMock())
        request = Mock(spec=Request)
        request.headers = {}
        request.cookies = {}
        request.state.refreshed_access_token = None
        request.scope = {"type": "http"}
        request.url.path = "/protected"

        call_next = AsyncMock(return_value=Response("OK"))

        response = await middleware.dispatch(request, call_next)

        identity = get_identity()
        assert not identity.is_authenticated
        assert response.body == b"OK"


@pytest.mark.asyncio
class TestFastAPIExceptionHandlers:
    async def test_authentication_error_handler(self):
        request = Mock(spec=Request)
        exc = AuthenticationError("Auth failed", code="AUTH_FAILED")

        response = await authentication_error_handler(request, exc)
        assert response.status_code == 401
        content = str(response.body)
        assert "AUTH_FAILED" in content

    async def test_domain_error_handler(self):
        request = Mock(spec=Request)
        exc = ValueError("Something bad")

        # This handler expects specific types or falls back
        # If we pass a generic Exception, it might return 500 based on implementation
        # Looking at implementation:
        # async def domain_error_handler(request: Request, exc: Exception):
        #    if isinstance(exc, (UserManagementError, OTPError))...
        #    return JSONResponse(status_code=500...)

        response = await domain_error_handler(request, exc)
        assert response.status_code == 500
