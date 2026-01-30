"""
Factory functions for automatic service creation.

Implements the 'if not provide create' pattern for framework integrations.
"""

import os
import logging
from typing import Optional, Any

from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.adapters.keycloak import KeycloakAdapter, KeycloakConfig
from cqrs_ddd_auth.adapters.repositories import InMemorySessionRepository

logger = logging.getLogger(__name__)

def create_default_idp() -> IdentityProviderPort:
    """
    Create a default IdentityProviderPort from environment variables or settings.
    
    Tries to detect the framework and use appropriate configuration source.
    """
    # 1. Try Django settings first
    try:
        from django.conf import settings
        if hasattr(settings, "AUTH_KEYCLOAK"):
            k_config = settings.AUTH_KEYCLOAK
            config = KeycloakConfig(
                server_url=k_config.get("SERVER_URL"),
                realm=k_config.get("REALM"),
                client_id=k_config.get("CLIENT_ID"),
                client_secret=k_config.get("CLIENT_SECRET"),
                verify=k_config.get("VERIFY", True),
            )
            return KeycloakAdapter(config)
    except (ImportError, Exception):
        pass
        
    # 2. Fall back to environment variables
    server_url = os.environ.get("AUTH_KEYCLOAK_SERVER_URL")
    if server_url:
        config = KeycloakConfig(
            server_url=server_url,
            realm=os.environ.get("AUTH_KEYCLOAK_REALM", "master"),
            client_id=os.environ.get("AUTH_KEYCLOAK_CLIENT_ID", "admin-cli"),
            client_secret=os.environ.get("AUTH_KEYCLOAK_CLIENT_SECRET"),
            verify=os.environ.get("AUTH_KEYCLOAK_VERIFY", "true").lower() == "true",
        )
        return KeycloakAdapter(config)
        
    # 3. Try legacy 'inject' library
    try:
        import inject as legacy_inject
        from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort
        idp = legacy_inject.instance(IdentityProviderPort)
        if idp:
            return idp
    except (ImportError, Exception):
        pass

    # 4. Last resort: Return None
    return None

def create_default_session_repo() -> Any:
    """Create a default in-memory session repository."""
    return InMemorySessionRepository()
