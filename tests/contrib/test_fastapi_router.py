"""
Tests for FastAPI Router.
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from dependency_injector import providers

from cqrs_ddd_auth.contrib.fastapi.router import create_auth_router
from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
from cqrs_ddd_auth.application.results import AuthResult, TokenPair
from cqrs_ddd_auth.identity import AuthenticatedIdentity


@pytest.fixture
def mock_mediator():
    return AsyncMock()


@pytest.fixture
def app(mock_mediator):
    # Setup container overrides
    container = AuthContainer()
    container.mediator.override(providers.Object(mock_mediator))
    container.wire(modules=["cqrs_ddd_auth.contrib.fastapi.router"])

    app = FastAPI()
    router = create_auth_router()
    app.include_router(router)

    yield app

    container.unwire()


def test_login_success(app, mock_mediator):
    client = TestClient(app)

    # Mock mediator response
    mock_mediator.send.return_value = AuthResult(
        status="success",
        user_id="u1",
        username="user",
        tokens=TokenPair(access_token="at", refresh_token="rt"),
    )

    response = client.post("/auth/login", json={"username": "user", "password": "pwd"})

    assert response.status_code == 200
    assert response.json()["tokens"]["access_token"] == "at"
    mock_mediator.send.assert_called_once()


def test_login_failure(app, mock_mediator):
    client = TestClient(app)

    mock_mediator.send.return_value = AuthResult(
        status="failed", error_message="Invalid credentials"
    )

    response = client.post("/auth/login", json={"username": "user", "password": "pwd"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_me_endpoint(app, mock_mediator):
    client = TestClient(app)

    # Mock identity by overriding module-level dependency
    from cqrs_ddd_auth.contrib.fastapi.router import require_authenticated

    app.dependency_overrides[require_authenticated] = lambda: AuthenticatedIdentity(
        "u1", "user"
    )

    mock_mediator.query.return_value = {"id": "u1", "username": "user"}

    response = client.get("/auth/me")
    # assert response.status_code == 200 # Skip status check for now, logic is tricky with overridden deps
    # Dependency override for 'me' endpoint function?
    # Since we moved 'me' to module level, using app.dependency_overrides should work
    # IF the router was included correctly.

    assert response.status_code == 200
    assert response.json()["id"] == "u1"
    mock_mediator.query.assert_called_once()
