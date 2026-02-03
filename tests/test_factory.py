"""
Tests for Factory functions.
"""

import os
from unittest.mock import Mock, patch

from cqrs_ddd_auth.factory import create_default_idp, create_default_session_repo
from cqrs_ddd_auth.infrastructure.adapters.keycloak import KeycloakAdapter
from cqrs_ddd_auth.infrastructure.adapters.session import InMemorySessionAdapter


def test_create_default_session_repo():
    repo = create_default_session_repo()
    assert isinstance(repo, InMemorySessionAdapter)


def test_create_default_idp_env_vars():
    with patch.dict(
        os.environ,
        {
            "AUTH_KEYCLOAK_SERVER_URL": "http://keycloak",
            "AUTH_KEYCLOAK_REALM": "realm",
            "AUTH_KEYCLOAK_CLIENT_ID": "client",
            "AUTH_KEYCLOAK_CLIENT_SECRET": "secret",
        },
    ):
        idp = create_default_idp()
        assert isinstance(idp, KeycloakAdapter)
        assert idp.config.server_url == "http://keycloak"


def test_create_default_idp_none():
    # Ensure env vars are clear
    with patch.dict(os.environ, {}, clear=True):
        idp = create_default_idp()
        assert idp is None


def test_create_default_idp_django():
    # Mock django settings
    mock_settings = Mock()
    mock_settings.AUTH_KEYCLOAK = {
        "SERVER_URL": "http://django-keycloak",
        "REALM": "django-realm",
        "CLIENT_ID": "django-client",
    }

    with patch.dict(os.environ, {}, clear=True):
        with patch.dict("sys.modules", {"django.conf": Mock(settings=mock_settings)}):
            idp = create_default_idp()
            assert isinstance(idp, KeycloakAdapter)
            assert idp.config.server_url == "http://django-keycloak"
