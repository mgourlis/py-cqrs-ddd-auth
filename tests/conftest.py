"""
Pytest configuration for py-cqrs-ddd-auth tests.
"""

import pytest


@pytest.fixture
def anonymous_identity():
    """Fixture providing an anonymous identity."""
    from cqrs_ddd_auth.identity import AnonymousIdentity
    return AnonymousIdentity()


@pytest.fixture
def system_identity():
    """Fixture providing a system identity."""
    from cqrs_ddd_auth.identity import SystemIdentity
    return SystemIdentity()


@pytest.fixture
def authenticated_identity():
    """Fixture providing an authenticated test user identity."""
    from cqrs_ddd_auth.identity import AuthenticatedIdentity
    return AuthenticatedIdentity(
        user_id="test-user-123",
        username="testuser",
        groups=["users", "developers"],
        permissions=["read", "write"],
        tenant_id="tenant-1"
    )
