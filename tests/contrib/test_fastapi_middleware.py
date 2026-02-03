"""
Tests for FastAPI Middleware using TestClient.
"""

from unittest.mock import AsyncMock, Mock, patch
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cqrs_ddd_auth.contrib.fastapi.middleware import (
    TokenRefreshMiddleware,
    AuthenticationMiddleware,
)
from cqrs_ddd_auth.infrastructure.adapters.keycloak import TokenResponse
from cqrs_ddd_auth.identity import AnonymousIdentity, get_identity
from cqrs_ddd_auth.domain.value_objects import UserClaims
from cqrs_ddd_auth.infrastructure.adapters.tokens import (
    TokenExtractionResult,
    TokenSource,
)

# -----------------------------------------------------------------------------
# TokenRefreshMiddleware
# -----------------------------------------------------------------------------


def test_refresh_middleware_integration():
    app = FastAPI()

    idp = Mock()
    idp.decode_token = AsyncMock(return_value=Mock(exp=9999999999))

    app.add_middleware(TokenRefreshMiddleware, idp=idp)

    @app.get("/")
    def root():
        return {"status": "ok"}

    client = TestClient(app)
    # Provide valid token to trigger logic
    response = client.get("/", headers={"Authorization": "Bearer valid_at"})

    assert response.status_code == 200
    idp.decode_token.assert_awaited()


def test_refresh_middleware_refreshed():
    app = FastAPI()

    idp = Mock()
    idp.decode_token = AsyncMock(side_effect=Exception("Expired"))
    idp.refresh = AsyncMock(return_value=TokenResponse("new_at", "new_rt", 300, 600))

    app.add_middleware(TokenRefreshMiddleware, idp=idp)

    @app.get("/")
    def root():
        return {"status": "ok"}

    # Mock extract_tokens to return both access and refresh tokens
    with patch(
        "cqrs_ddd_auth.contrib.fastapi.middleware.extract_tokens"
    ) as mock_extract:
        mock_extract.return_value = TokenExtractionResult(
            access_token="expired_at",
            refresh_token="valid_rt",
            source=TokenSource.HEADER,
        )

        client = TestClient(app)
        response = client.get("/", headers={"Authorization": "Bearer expired_at"})

    assert response.status_code == 200
    idp.refresh.assert_awaited()
    assert response.headers["X-New-Access-Token"] == "new_at"


# -----------------------------------------------------------------------------
# AuthenticationMiddleware
# -----------------------------------------------------------------------------


def test_auth_middleware_authenticated():
    app = FastAPI()

    idp = Mock()
    idp.decode_token = AsyncMock(
        return_value=UserClaims(
            sub="u1",
            username="alice",
            email="a@a.com",
            groups=("g1",),
            attributes={"tenant_id": "t1"},
        )
    )

    app.add_middleware(AuthenticationMiddleware, idp=idp)

    @app.get("/me")
    def me(request: Request):
        # Correctly use get_identity() from context var
        identity = get_identity()
        return {"user_id": identity.user_id}

    client = TestClient(app)

    # Needs to see a token to attempt auth
    with patch(
        "cqrs_ddd_auth.contrib.fastapi.middleware.extract_tokens"
    ) as mock_extract:
        mock_extract.return_value = TokenExtractionResult(
            access_token="at", refresh_token=None, source=TokenSource.HEADER
        )
        response = client.get("/me", headers={"Authorization": "Bearer at"})

    assert response.status_code == 200
    assert response.json() == {"user_id": "u1"}


def test_auth_middleware_anonymous():
    app = FastAPI()
    idp = Mock()
    app.add_middleware(AuthenticationMiddleware, idp=idp)

    @app.get("/me")
    def me():
        identity = get_identity()
        return {"is_anon": isinstance(identity, AnonymousIdentity)}

    client = TestClient(app)
    response = client.get("/me")

    assert response.status_code == 200
    assert response.json()["is_anon"] is True
