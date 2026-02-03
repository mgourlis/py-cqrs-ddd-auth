"""
Tests for Keycloak Adapter.
"""

import pytest
from unittest.mock import patch
from cqrs_ddd_auth.infrastructure.adapters.keycloak import (
    KeycloakAdapter,
    KeycloakConfig,
    GroupPathStrategy,
    TokenResponse,
    AuthenticationError,
    InvalidTokenError,
)


@pytest.fixture
def keycloak_config():
    return KeycloakConfig(
        server_url="https://auth.example.com",
        realm="test-realm",
        client_id="test-client",
        client_secret="secret",
        verify=False,
    )


@pytest.fixture
def mock_keycloak_openid():
    with patch("cqrs_ddd_auth.infrastructure.adapters.keycloak.KeycloakOpenID") as mock:
        yield mock.return_value


@pytest.fixture
def mock_jwt():
    with patch("cqrs_ddd_auth.infrastructure.adapters.keycloak.jwt") as mock:
        yield mock


@pytest.mark.asyncio
async def test_authenticate_success(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)

    mock_keycloak_openid.token.return_value = {
        "access_token": "at",
        "refresh_token": "rt",
        "token_type": "Bearer",
        "expires_in": 300,
    }

    result = await adapter.authenticate("user", "pass")

    assert isinstance(result, TokenResponse)
    assert result.access_token == "at"
    mock_keycloak_openid.token.assert_called_with("user", "pass")


@pytest.mark.asyncio
async def test_authenticate_failure(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)

    mock_keycloak_openid.token.side_effect = Exception("Invalid credentials")

    with pytest.raises(AuthenticationError):
        await adapter.authenticate("user", "wrong")


@pytest.mark.asyncio
async def test_refresh_success(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)

    mock_keycloak_openid.refresh_token.return_value = {
        "access_token": "new_at",
        "refresh_token": "new_rt",
    }

    result = await adapter.refresh("old_rt")

    assert result.access_token == "new_at"
    mock_keycloak_openid.refresh_token.assert_called_with("old_rt")


@pytest.mark.asyncio
async def test_decode_token_success(keycloak_config, mock_keycloak_openid, mock_jwt):
    adapter = KeycloakAdapter(keycloak_config)

    # Mock public key
    mock_keycloak_openid.public_key.return_value = "MOCK_KEY"

    # Mock JWT decode
    payload = {
        "sub": "u1",
        "preferred_username": "user",
        "email": "user@example.com",
        "realm_access": {"roles": ["admin"]},
        "resource_access": {
            "test-client": {"roles": ["editor"]},
            "other-client": {"roles": ["viewer"]},
        },
        "groups": ["/g1"],
    }
    mock_jwt.decode.return_value = payload

    claims = await adapter.decode_token("valid_token")

    assert claims.sub == "u1"
    assert "g1" in claims.groups or "/g1" in claims.groups

    # Check roles extraction
    role_names = [r.name for r in claims.roles]
    assert "admin" in role_names
    assert "editor" in role_names  # Client ID matches config, so prefix omitted
    assert "other-client:viewer" in role_names  # Mismatched client ID, prefix included
    assert "g1" in role_names  # Derived from group


@pytest.mark.asyncio
async def test_decode_token_invalid(keycloak_config, mock_keycloak_openid, mock_jwt):
    adapter = KeycloakAdapter(keycloak_config)
    mock_keycloak_openid.public_key.return_value = "key"

    # Simulate JWT error
    from jose import JWTError

    mock_jwt.decode.side_effect = JWTError("Expired")

    with pytest.raises(InvalidTokenError):
        await adapter.decode_token("bad_token")


def test_group_path_strategies(keycloak_config):
    # Test internal helper synchronously
    adapter = KeycloakAdapter(keycloak_config)

    # Strategy: FULL_PATH (Default)
    roles = adapter._group_path_to_roles("/web/admin", GroupPathStrategy.FULL_PATH)
    assert len(roles) == 1
    assert roles[0].name == "web/admin"

    # Strategy: LAST_SEGMENT
    roles = adapter._group_path_to_roles("/web/admin", GroupPathStrategy.LAST_SEGMENT)
    assert len(roles) == 1
    assert roles[0].name == "admin"

    # Strategy: ALL_SEGMENTS
    roles = adapter._group_path_to_roles("/web/admin", GroupPathStrategy.ALL_SEGMENTS)
    assert len(roles) == 2
    assert {"web", "admin"} == {r.name for r in roles}


@pytest.mark.asyncio
async def test_refresh_failure(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)
    mock_keycloak_openid.refresh_token.side_effect = Exception("Refresh failed")

    with pytest.raises(AuthenticationError):
        await adapter.refresh("bad_rt")


@pytest.mark.asyncio
async def test_logout_success(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)
    await adapter.logout("rt")
    mock_keycloak_openid.logout.assert_called_with("rt")


@pytest.mark.asyncio
async def test_logout_failure_suppressed(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)
    mock_keycloak_openid.logout.side_effect = Exception("Logout failed")
    # Should not raise
    await adapter.logout("rt")


@pytest.mark.asyncio
async def test_get_user_info_success(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)
    mock_keycloak_openid.userinfo.return_value = {"sub": "u1", "email": "e@e.com"}

    info = await adapter.get_user_info("at")
    assert info["sub"] == "u1"


@pytest.mark.asyncio
async def test_get_user_info_failure(keycloak_config, mock_keycloak_openid):
    adapter = KeycloakAdapter(keycloak_config)
    mock_keycloak_openid.userinfo.side_effect = Exception("Failed")

    with pytest.raises(InvalidTokenError):
        await adapter.get_user_info("at")


def test_extract_groups_strategies(keycloak_config):
    # Default: groups claim
    adapter = KeycloakAdapter(keycloak_config)
    payload = {"groups": ["g1"], "realm_access": {"roles": ["r1"]}}
    groups = adapter._extract_groups(payload)
    assert "g1" in groups
    assert "r1" in groups  # Includes realm roles by default

    # Config: realm_access.roles
    keycloak_config.groups_claim = "realm_access.roles"
    adapter2 = KeycloakAdapter(keycloak_config)
    groups2 = adapter2._extract_groups(payload)
    keycloak_config.groups_claim = "realm_access.roles"
    adapter2 = KeycloakAdapter(keycloak_config)
    groups2 = adapter2._extract_groups(payload)
    assert "r1" in groups2
    assert "g1" not in groups2


def test_clear_key_cache(keycloak_config):
    adapter = KeycloakAdapter(keycloak_config)
    adapter._public_key = "cached_key"
    adapter.clear_key_cache()
    assert adapter._public_key is None
