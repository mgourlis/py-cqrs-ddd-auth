"""
Tests for RBAC Adapters.
"""

import pytest
from unittest.mock import AsyncMock
from cqrs_ddd_auth.infrastructure.adapters.rbac import (
    SimpleRBACAdapter,
    OwnershipAwareRBACAdapter,
    OwnershipStrategy,
)

# -----------------------------------------------------------------------------
# SimpleRBACAdapter
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_simple_rbac_check_access():
    config = {"admin": ["*"], "editor": ["read", "write"], "viewer": ["read"]}
    adapter = SimpleRBACAdapter(config)

    # Admin (via role_names)
    allowed = await adapter.check_access(None, "delete", "doc", None, None, ["admin"])
    assert allowed == ["*"]

    # Editor (allowed action)
    allowed = await adapter.check_access(None, "write", "doc", None, None, ["editor"])
    assert allowed == ["*"]

    # Viewer (denied action)
    allowed = await adapter.check_access(None, "write", "doc", None, None, ["viewer"])
    assert allowed == []


@pytest.mark.asyncio
async def test_simple_rbac_auth_filter():
    adapter = SimpleRBACAdapter({"viewer": ["read"]})

    # Granted
    f = await adapter.get_authorization_filter(None, "doc", "read", None, ["viewer"])
    assert f.granted_all is True
    assert f.denied_all is False

    # Denied
    f = await adapter.get_authorization_filter(None, "doc", "write", None, ["viewer"])
    assert f.granted_all is False
    assert f.denied_all is True


# -----------------------------------------------------------------------------
# OwnershipAwareRBACAdapter
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ownership_aware_fallback():
    # Setup Ownership Strategy mock
    ownership_mock = AsyncMock(spec=OwnershipStrategy)
    ownership_mock.is_owner.return_value = False

    config = {"user": ["read"]}  # Regular role only has read
    adapter = OwnershipAwareRBACAdapter(
        config,
        ownership_mock,
        ownership_actions={"edit"},  # Only 'edit' triggers ownership check
    )

    # 1. Role match: 'read' is in role -> Access Granted via Base
    allowed = await adapter.check_access(None, "read", "doc", None, None, ["user"])
    assert allowed == ["*"]

    # 2. No Role match, Action is ownership candidate: 'edit' -> Check Ownership
    ownership_mock.is_owner.return_value = True  # Is owner

    context = {"sub": "u1"}
    allowed = await adapter.check_access(
        None, "edit", "doc", ["doc1"], context, ["user"]
    )

    assert allowed == ["doc1"]
    ownership_mock.is_owner.assert_called_with("u1", "doc", "doc1")

    # 3. No role match, ownership candidate, NOT owner -> Denied
    ownership_mock.is_owner.return_value = False
    allowed = await adapter.check_access(
        None, "edit", "doc", ["doc2"], context, ["user"]
    )
    assert allowed == []
