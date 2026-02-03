"""
Tests for RBAC Adapter.
"""

import pytest
from cqrs_ddd_auth.infrastructure.adapters.rbac import SimpleRBACAdapter


@pytest.fixture
def policy_config():
    return {
        "admin": ["read", "write", "delete"],
        "editor": ["read", "write"],
        "viewer": ["read"],
        "superuser": ["*"],
    }


@pytest.mark.asyncio
async def test_check_access_allowed(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    # Editor -> Write -> Allowed
    res = await adapter.check_access(
        access_token=None,
        action="write",
        resource_type="resource",
        role_names=["editor"],
    )
    assert res == ["*"]  # Returns wildcard if no IDs provided and allowed


@pytest.mark.asyncio
async def test_check_access_denied(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    # Viewer -> Delete -> Denied
    res = await adapter.check_access(
        access_token=None,
        action="delete",
        resource_type="resource",
        role_names=["viewer"],
    )
    assert res == []


@pytest.mark.asyncio
async def test_check_access_wildcard(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    # Superuser -> Anything -> Allowed
    res = await adapter.check_access(
        access_token=None,
        action="nuke",
        resource_type="world",
        role_names=["superuser"],
    )
    assert res == ["*"]


@pytest.mark.asyncio
async def test_check_access_ids(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    ids = ["id1", "id2"]
    res = await adapter.check_access(
        access_token=None,
        action="read",
        resource_type="res",
        resource_ids=ids,
        role_names=["viewer"],
    )
    assert res == ids


@pytest.mark.asyncio
async def test_get_permitted_actions(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    # Viewer: read
    actions = await adapter.get_permitted_actions(
        access_token=None, resource_type="res", role_names=["viewer"]
    )
    assert "read" in actions["res"]
    assert "write" not in actions["res"]

    # Editor: read, write
    actions = await adapter.get_permitted_actions(
        access_token=None, resource_type="res", role_names=["editor"]
    )
    assert "write" in actions["res"]


@pytest.mark.asyncio
async def test_get_authorization_conditions(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    # Allowed
    res = await adapter.get_authorization_conditions(
        access_token=None, resource_type="res", action="read", role_names=["viewer"]
    )
    assert res.filter_type == "granted_all"

    # Denied
    res = await adapter.get_authorization_conditions(
        access_token=None, resource_type="res", action="write", role_names=["viewer"]
    )
    assert res.filter_type == "denied_all"


@pytest.mark.asyncio
async def test_check_access_batch(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    resources = [
        {
            "resource_type_name": "res",
            "action_name": "read",
            "external_resource_ids": ["1", "2"],
        },
        {
            "resource_type_name": "res",
            "action_name": "write",
            "external_resource_ids": ["3"],
        },
    ]

    # Viewer -> Read Allowed, Write Denied
    result = await adapter.check_access_batch(
        access_token=None, resources=resources, role_names=["viewer"]
    )

    # Check Read
    assert result.is_allowed("res", "1", {"read"})
    assert result.is_allowed("res", "2", {"read"})
    # Check Write
    assert not result.is_allowed("res", "3", {"write"})

    # Editor -> All Allowed
    result_ed = await adapter.check_access_batch(
        access_token=None, resources=resources, role_names=["editor"]
    )
    assert result_ed.is_allowed("res", "3", {"write"})


@pytest.mark.asyncio
async def test_get_permitted_actions_batch(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    resources = [{"resource_type_name": "res", "external_resource_ids": ["1"]}]

    result = await adapter.get_permitted_actions_batch(
        access_token=None, resources=resources, role_names=["editor"]
    )

    assert "res" in result
    assert "1" in result["res"]
    assert "write" in result["res"]["1"]


@pytest.mark.asyncio
async def test_list_metadata(policy_config):
    adapter = SimpleRBACAdapter(policy_config)

    types = await adapter.list_resource_types()
    assert types == ["*"]

    actions = await adapter.list_actions("any")
    assert "read" in actions
    assert "delete" in actions
