from unittest.mock import AsyncMock, Mock
from fastapi import HTTPException, Request, status
import pytest
from cqrs_ddd_auth.contrib.fastapi.dependencies import get_current_user, require_groups
from cqrs_ddd_auth.domain.value_objects import UserClaims
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.identity import AnonymousIdentity


@pytest.fixture
def mock_request():
    return Mock(spec=Request)


@pytest.fixture
def container():
    c = AuthContainer()
    c.wire(modules=["cqrs_ddd_auth.contrib.fastapi.dependencies"])
    return c


@pytest.mark.asyncio
async def test_get_current_user_valid_token(mock_request, container):
    mock_request.headers = {"Authorization": "Bearer valid_token"}

    mock_idp = AsyncMock()
    mock_idp.decode_token.return_value = UserClaims(
        sub="u1", username="user", email="e", groups=[]
    )

    with container.identity_provider.override(mock_idp):
        user = await get_current_user(mock_request)
        assert user.user_id == "u1"


@pytest.mark.asyncio
async def test_get_current_user_missing_header(mock_request, container):
    mock_request.headers = {}
    mock_request.cookies = {}
    mock_request.state.refreshed_access_token = None

    # Defaults to AnonymousIdentity if no token
    user = await get_current_user(mock_request)
    assert isinstance(user, AnonymousIdentity)


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(mock_request, container):
    mock_request.headers = {"Authorization": "Bearer invalid"}

    mock_idp = AsyncMock()
    mock_idp.decode_token.side_effect = ValueError("Invalid")

    with container.identity_provider.override(mock_idp):
        user = await get_current_user(mock_request)
        assert isinstance(user, AnonymousIdentity)


@pytest.mark.asyncio
async def test_require_groups_success(mock_request):
    # user_claims = UserClaims(sub="u1", username="user", email="e", groups=["admin"])
    identity = Mock()
    identity.groups = ["admin"]
    identity.is_authenticated = True

    # create dependency
    dep_factory = require_groups("admin")

    # In FastAPI, we would simulate the dependency call.
    # require_groups returns a callable that takes 'identity'.

    result = await dep_factory(identity=identity)
    assert result == identity


@pytest.mark.asyncio
async def test_require_groups_forbidden(mock_request):
    identity = Mock()
    identity.groups = ["user"]
    identity.is_authenticated = True

    dep_factory = require_groups("admin")

    with pytest.raises(HTTPException) as exc:
        await dep_factory(identity=identity)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN
