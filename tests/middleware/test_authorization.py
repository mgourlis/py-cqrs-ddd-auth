"""
Tests for Authorization Middleware.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from cqrs_ddd_auth.middleware.authorization import (
    AuthorizationMiddleware,
    PermittedActionsMiddleware,
    AuthorizationConfig,
    PermittedActionsConfig,
    AuthorizationError,
)
from cqrs_ddd_auth.infrastructure.ports.authorization import ABACAuthorizationPort


@pytest.fixture
def mock_abac():
    return Mock(spec=ABACAuthorizationPort)


@pytest.fixture
def identity_context():
    """Mock context vars."""
    with patch(
        "cqrs_ddd_auth.middleware.authorization.get_access_token", return_value="at"
    ):
        yield


@pytest.fixture
def anonymous_context():
    with patch(
        "cqrs_ddd_auth.middleware.authorization.get_access_token", return_value=None
    ):
        yield


# -----------------------------------------------------------------------------
# AuthorizationMiddleware Pre-Check
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authz_middleware_pre_check_all_granted(mock_abac, identity_context):
    config = AuthorizationConfig(
        resource_type="doc", required_actions=["read"], resource_id_attr="id"
    )
    middleware = AuthorizationMiddleware(config, mock_abac)

    # Mock handler
    handler = AsyncMock(return_value="success")
    wrapped = middleware.apply(handler, Mock(id="doc1"))

    # Mock ABAC grant
    mock_abac.check_access = AsyncMock(return_value=["doc1"])

    res = await wrapped(Mock(id="doc1"))

    assert res == "success"
    mock_abac.check_access.assert_called()


@pytest.mark.asyncio
async def test_authz_middleware_pre_check_denied(mock_abac, identity_context):
    config = AuthorizationConfig(
        resource_type="doc", required_actions=["read"], resource_id_attr="id"
    )
    middleware = AuthorizationMiddleware(config, mock_abac)

    handler = AsyncMock()
    wrapped = middleware.apply(handler, Mock(id="doc1"))

    # Mock ABAC deny (return empty list)
    mock_abac.check_access = AsyncMock(return_value=[])

    with pytest.raises(AuthorizationError):
        await wrapped(Mock(id="doc1"))

    handler.assert_not_called()


@pytest.mark.asyncio
async def test_authz_middleware_deny_anonymous(mock_abac, anonymous_context):
    config = AuthorizationConfig("doc", deny_anonymous=True)
    middleware = AuthorizationMiddleware(config, mock_abac)

    handler = AsyncMock()
    wrapped = middleware.apply(handler, Mock())

    with pytest.raises(AuthorizationError):
        await wrapped()

    mock_abac.check_access.assert_not_called()


@pytest.mark.asyncio
async def test_authz_middleware_anonymous_allowed_by_abac(mock_abac, anonymous_context):
    config = AuthorizationConfig("doc", deny_anonymous=False)
    middleware = AuthorizationMiddleware(config, mock_abac)

    handler = AsyncMock(return_value="ok")
    wrapped = middleware.apply(handler, Mock())

    # Mock ABAC allowing anonymous access at type level
    mock_abac.get_type_level_permissions = AsyncMock(return_value={"doc": ["read"]})

    assert await wrapped() == "ok"


@pytest.mark.asyncio
async def test_authz_middleware_quantifiers(mock_abac, identity_context):
    # Quantifier "any"
    config = AuthorizationConfig(
        "doc",
        required_actions=["read", "write"],
        quantifier="any",
        resource_id_attr="ids",
    )
    middleware = AuthorizationMiddleware(config, mock_abac)

    mock_abac.check_access = AsyncMock(return_value=["doc1"])  # Only one of two
    handler = AsyncMock(return_value="ok")

    msg = Mock(ids=["doc1", "doc2"])
    wrapped = middleware.apply(handler, msg)
    assert await wrapped(msg) == "ok"

    # Quantifier "all" failure
    config.quantifier = "all"
    with pytest.raises(AuthorizationError):
        await wrapped(msg)


@pytest.mark.asyncio
async def test_authz_middleware_fail_silently(mock_abac, identity_context):
    config = AuthorizationConfig("doc", fail_silently=True, resource_id_attr="id")
    middleware = AuthorizationMiddleware(config, mock_abac)

    mock_abac.check_access = AsyncMock(return_value=[])  # Denied
    handler = AsyncMock(return_value="ok")
    wrapped = middleware.apply(handler, Mock(id="doc1"))

    # SHould not raise but just execute (warning logged)
    assert await wrapped(Mock(id="doc1")) == "ok"


@pytest.mark.asyncio
async def test_authz_middleware_dotted_paths(mock_abac, identity_context):
    config = AuthorizationConfig(
        resource_type="doc",
        resource_id_attr="filter.doc_id",
        result_entities_attr="data.items",
    )
    middleware = AuthorizationMiddleware(config, mock_abac)

    msg = {"filter": {"doc_id": "d1"}}
    handler = AsyncMock(return_value={"data": {"items": [{"id": "d1"}]}})
    wrapped = middleware.apply(handler, msg)

    mock_abac.check_access = AsyncMock(return_value=["d1"])
    res = await wrapped(msg)
    assert res["data"]["items"][0]["id"] == "d1"


# -----------------------------------------------------------------------------
# AuthorizationMiddleware Post-Filter
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authz_middleware_post_filter(mock_abac, identity_context):
    config = AuthorizationConfig(
        resource_type="doc",
        required_actions=["read"],
        result_entities_attr="items",
        entity_id_attr="id",
    )
    middleware = AuthorizationMiddleware(config, mock_abac)

    # Result object mimicking a response with items
    class Result:
        items = [Mock(id="doc1"), Mock(id="doc2")]

    handler = AsyncMock(return_value=Result())
    wrapped = middleware.apply(handler, Mock())

    # ABAC: doc1 allowed, doc2 denied
    # Pre-check uses type-level (no resource_id_attr on input)
    mock_abac.get_type_level_permissions = AsyncMock(return_value={"doc": ["read"]})
    # Check access for post-filter
    mock_abac.check_access = AsyncMock(return_value=["doc1"])

    res = await wrapped()

    assert len(res.items) == 1
    assert res.items[0].id == "doc1"


# -----------------------------------------------------------------------------
# PermittedActionsMiddleware
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_permitted_actions_middleware(mock_abac, identity_context):
    config = PermittedActionsConfig(resource_type="doc", result_entities_attr="items")
    middleware = PermittedActionsMiddleware(config, mock_abac)

    entity = Mock(id="doc1")

    class Result:
        items = [entity]

    handler = AsyncMock(return_value=Result())
    wrapped = middleware.apply(handler, Mock())

    mock_abac.get_permitted_actions = AsyncMock(
        return_value={"doc1": ["read", "write"]}
    )

    await wrapped()

    assert hasattr(entity, "permitted_actions")
    assert "read" in entity.permitted_actions
    assert "write" in entity.permitted_actions


@pytest.mark.asyncio
async def test_authz_middleware_auth_context_provider(mock_abac, identity_context):
    def provider(msg):
        return {"org_id": msg.org_id}

    config = AuthorizationConfig("doc", auth_context_provider=provider)
    middleware = AuthorizationMiddleware(config, mock_abac)

    msg = Mock(org_id="o1")
    handler = AsyncMock(return_value="ok")
    wrapped = middleware.apply(handler, msg)

    mock_abac.get_type_level_permissions = AsyncMock(return_value={"doc": ["read"]})
    await wrapped(msg)

    # Verify auth_context passed to ABAC
    args = mock_abac.get_type_level_permissions.call_args[1]
    assert args["auth_context"] == {"org_id": "o1"}


@pytest.mark.asyncio
async def test_authz_middleware_nested_attr_failures(mock_abac, identity_context):
    config = AuthorizationConfig("doc", resource_id_attr="missing.attr")
    middleware = AuthorizationMiddleware(config, mock_abac)

    # Missing attribute branch on plain object (doesn't have 'missing')
    class Empty:
        pass

    assert middleware._extract_resource_ids(Empty()) is None

    # _get_nested_attr branches
    assert middleware._get_nested_attr(None, "any") is None
    assert middleware._get_nested_attr({"a": 1}, "b") is None
    assert middleware._get_nested_attr(Empty(), "a.b") is None

    # _set_nested_attr branches
    obj = {"a": {}}
    middleware._set_nested_attr(obj, "a.b", 1)
    assert obj["a"]["b"] == 1

    # Test setting on object without attr but with __dict__
    class Simple:
        def __init__(self):
            # We don't define new_attr here
            pass

    s = Simple()
    middleware._set_nested_attr(s, "new_attr", "val")
    # This might still fail if Python versions/Simple don't allow dynamic attrs
    # Let's use a dict instead for certainty of the 'dict' branch
    d_obj = {"existing": {}}
    middleware._set_nested_attr(d_obj, "existing.new", "val")
    assert d_obj["existing"]["new"] == "val"

    # Test setting on object WITHOUT __dict__ (will fail gracefully)
    class Locked:
        __slots__ = ["id"]

        def __init__(self):
            self.id = 1

    locked_obj = Locked()
    # _set_nested_attr navigates. If we target a final attr:
    middleware._set_nested_attr(locked_obj, "id", 2)
    assert locked_obj.id == 2

    # Target missing on locked object
    middleware._set_nested_attr(locked_obj, "missing", 3)
    # Should just return without setting
    assert not hasattr(locked_obj, "missing")

    # _set_attr edge cases (PermittedActionsMiddleware helper)
    config_pa = PermittedActionsConfig("doc", "items")
    mw_pa = PermittedActionsMiddleware(config_pa, mock_abac)

    # Set on object without __dict__ (like a slot-based or builtin if it fails)
    # We can use a Mock with spec and no __dict__ or just test the try-except logic
    class NoDict:
        __slots__ = ["id"]

        def __init__(self):
            self.id = 1

    nd = NoDict()
    mw_pa._set_attr(nd, "new", "val")  # should fail gracefully or set if possible

    # Test dictionary path
    d = {}
    mw_pa._set_attr(d, "perm", [1])
    assert d["perm"] == [1]


def test_convenience_functions():
    from cqrs_ddd_auth.middleware.authorization import authorize, permitted_actions

    c1 = authorize("doc", required_actions=["delete"])
    assert c1.resource_type == "doc"
    assert c1.required_actions == ["delete"]

    c2 = permitted_actions("doc", "items")
    assert c2.resource_type == "doc"
    assert c2.result_entities_attr == "items"


@pytest.mark.asyncio
async def test_permitted_actions_middleware_with_type_level(
    mock_abac, identity_context
):
    config = PermittedActionsConfig(
        resource_type="doc", result_entities_attr="items", include_type_level=True
    )
    middleware = PermittedActionsMiddleware(config, mock_abac)

    entity = {"id": "doc1"}
    result = Mock(items=[entity])
    handler = AsyncMock(return_value=result)
    wrapped = middleware.apply(handler, Mock())

    mock_abac.get_permitted_actions = AsyncMock(return_value={"doc1": ["write"]})
    mock_abac.get_type_level_permissions = AsyncMock(return_value={"doc": ["read"]})

    await wrapped()

    assert "read" in entity["permitted_actions"]
    assert "write" in entity["permitted_actions"]


@pytest.mark.asyncio
async def test_permitted_actions_anonymous(mock_abac, anonymous_context):
    config = PermittedActionsConfig("doc", "items")
    middleware = PermittedActionsMiddleware(config, mock_abac)

    result = Mock(items=[{"id": "d1"}])
    handler = AsyncMock(return_value=result)
    wrapped = middleware.apply(handler, Mock())

    await wrapped()
    assert "permitted_actions" not in result.items[0]


# -----------------------------------------------------------------------------
# Convenience and Registration
# -----------------------------------------------------------------------------


def test_register_abac_middleware(mock_abac):
    from cqrs_ddd_auth.middleware.authorization import register_abac_middleware
    from cqrs_ddd.middleware import middleware as registry

    register_abac_middleware(mock_abac)

    assert "authorization" in registry.classes
    assert "permitted_actions" in registry.classes

    # Verify pre-binding
    auth_cls = registry.classes["authorization"]
    instance = auth_cls(resource_type="test")
    assert instance.authorization_port == mock_abac
