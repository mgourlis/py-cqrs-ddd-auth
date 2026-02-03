"""
Pytest configuration for py-cqrs-ddd-auth tests.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from cqrs_ddd_auth.infrastructure.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.infrastructure.ports.otp import OTPServicePort, TOTPSecretRepository
from cqrs_ddd_auth.infrastructure.ports.session import AuthSessionPort


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
        tenant_id="tenant-1",
    )


# -----------------------------------------------------------------------------
# MOCKS
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_idp():
    mock = MagicMock(spec=IdentityProviderPort)
    mock.authenticate = AsyncMock()
    mock.decode_token = AsyncMock()
    mock.refresh = AsyncMock()
    mock.logout = AsyncMock()
    return mock


@pytest.fixture
def mock_otp_service():
    mock = MagicMock(spec=OTPServicePort)
    mock.is_required_for_user = AsyncMock(return_value=False)
    mock.get_available_methods = AsyncMock(return_value=[])
    mock.validate = AsyncMock(return_value=True)
    mock.send_challenge = AsyncMock(return_value="Code sent")
    return mock


@pytest.fixture
def mock_session_repo():
    mock = MagicMock(spec=AuthSessionPort)
    mock.save = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.revoke = AsyncMock()
    mock.revoke_all_for_user = AsyncMock(return_value=1)
    return mock


@pytest.fixture
def mock_totp_repo():
    mock = MagicMock(spec=TOTPSecretRepository)
    mock.get_by_user_id = AsyncMock(return_value=None)
    mock.save = AsyncMock()
    mock.delete = AsyncMock()
    return mock
