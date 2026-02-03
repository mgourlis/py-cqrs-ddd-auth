"""
Tests for Stateful ABAC Adapter.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch

from cqrs_ddd_auth.contrib.stateful_abac.adapter import (
    StatefulABACAdapter,
    ABACClientConfig,
)
from cqrs_ddd_auth.infrastructure.ports.authorization import CheckAccessBatchResult


# Mock the SDK interfaces
class MockAuthManager:
    check_access = AsyncMock()
    get_permitted_actions = AsyncMock()
    get_authorization_conditions = AsyncMock()


class MockResourceManager:
    list = AsyncMock()


class MockActionManager:
    list = AsyncMock()


class MockClient:
    def __init__(self):
        self.auth = MockAuthManager()
        self.resource_types = MockResourceManager()
        self.actions = MockActionManager()
        self.realms = AsyncMock()
        self.set_token = Mock()
        self.close = AsyncMock()


@pytest.fixture
def mock_client():
    return MockClient()


@pytest.fixture
def mock_sdk_factory(mock_client):
    with patch("stateful_abac_sdk.StatefulABACClientFactory") as factory:
        factory.create.return_value = mock_client
        factory.from_env.return_value = mock_client
        yield factory


@pytest.mark.asyncio
async def test_init_http(mock_sdk_factory):
    config = ABACClientConfig(mode="http", base_url="http://test")
    adapter = StatefulABACAdapter(config)
    await adapter._ensure_client()
    mock_sdk_factory.create.assert_called_with(
        mode="http", realm="default", base_url="http://test", timeout=30.0
    )


@pytest.mark.asyncio
async def test_init_db(mock_sdk_factory):
    config = ABACClientConfig(mode="db", realm="test-realm")
    adapter = StatefulABACAdapter(config)
    await adapter._ensure_client()
    mock_sdk_factory.create.assert_called_with(mode="db", realm="test-realm")


@pytest.mark.asyncio
async def test_init_from_env(mock_sdk_factory):
    config = ABACClientConfig(from_env=True)
    adapter = StatefulABACAdapter(config)
    await adapter._ensure_client()
    mock_sdk_factory.from_env.assert_called()


@pytest.mark.asyncio
async def test_init_failures(mock_sdk_factory):
    # No base_url for http
    with pytest.raises(ValueError, match="base_url is required"):
        await StatefulABACAdapter(ABACClientConfig(mode="http"))._ensure_client()
    # Invalid mode
    with pytest.raises(ValueError, match="Invalid mode"):
        await StatefulABACAdapter(ABACClientConfig(mode="invalid"))._ensure_client()


@pytest.mark.asyncio
async def test_context_manager(mock_sdk_factory, mock_client):
    config = ABACClientConfig(mode="http", base_url="http://test")
    async with StatefulABACAdapter(config) as adapter:
        assert adapter._client == mock_client
    assert mock_client.close.called


@pytest.mark.asyncio
async def test_check_access(mock_sdk_factory, mock_client):
    config = ABACClientConfig(mode="http", base_url="http://test")
    adapter = StatefulABACAdapter(config)

    # Mock response
    mock_result = Mock()
    mock_result.answer = [1, 2]

    mock_response = Mock()
    mock_response.results = [mock_result]

    mock_client.auth.check_access.return_value = mock_response

    result = await adapter.check_access(
        access_token="token",
        action="read",
        resource_type="doc",
        resource_ids=["1", "2", "3"],
    )

    assert result == ["1", "2"]
    mock_client.set_token.assert_called_with("token")


@pytest.mark.asyncio
async def test_check_access_blanket(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    mock_result = Mock()
    mock_result.answer = True  # Blanket
    mock_client.auth.check_access.return_value = Mock(results=[mock_result])

    res = await adapter.check_access("t", "read", "doc", ["1", "2"])
    assert res == ["1", "2"]


@pytest.mark.asyncio
async def test_check_access_batch(mock_sdk_factory, mock_client):
    config = ABACClientConfig(mode="http", base_url="http://test")
    adapter = StatefulABACAdapter(config)

    res1 = Mock()
    res1.action_name = "read"
    res1.resource_type_name = "doc"
    res1.answer = [1]

    res2 = Mock()
    res2.action_name = "write"
    res2.answer = True

    mock_response = Mock()
    mock_response.results = [res1, res2]

    mock_client.auth.check_access.return_value = mock_response

    result = await adapter.check_access_batch(
        access_token="token",
        resources=[{"resource_type_name": "doc", "action_name": "read"}],
    )

    assert isinstance(result, CheckAccessBatchResult)
    assert result.access_map[("doc", "1")] == {"read"}
    assert "write" in result.global_permissions


@pytest.mark.asyncio
async def test_get_permitted_actions(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    item = Mock(external_resource_id="1", actions=["read"])
    mock_client.auth.get_permitted_actions.return_value = Mock(results=[item])

    res = await adapter.get_permitted_actions("t", "doc", ["1"])
    assert res["1"] == ["read"]


@pytest.mark.asyncio
async def test_get_permitted_actions_type_level(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    item = Mock(external_resource_id=None, actions=["read"])
    mock_client.auth.get_permitted_actions.return_value = Mock(results=[item])

    res = await adapter.get_permitted_actions("t", "doc", None)
    assert res["doc"] == ["read"]


@pytest.mark.asyncio
async def test_get_type_level_permissions(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    item = Mock(resource_type_name="doc", actions=["read"])
    mock_client.auth.get_permitted_actions.return_value = Mock(results=[item])

    res = await adapter.get_type_level_permissions("t", ["doc"])
    assert res["doc"] == ["read"]


@pytest.mark.asyncio
async def test_list_resource_types(mock_sdk_factory, mock_client):
    config = ABACClientConfig(
        mode="http", base_url="http://test", cache_resource_types=True
    )
    adapter = StatefulABACAdapter(config)

    r1 = Mock()
    r1.name = "doc"
    mock_client.resource_types.list.return_value = [r1]

    res = await adapter.list_resource_types()
    assert res == ["doc"]

    # Cache hit
    hit = await adapter.list_resource_types()
    assert hit == ["doc"]
    assert mock_client.resource_types.list.call_count == 1


@pytest.mark.asyncio
async def test_list_actions(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    a1 = Mock()
    a1.name = "read"
    mock_client.actions.list.return_value = [a1]

    res = await adapter.list_actions("doc")
    assert res == ["read"]

    # Cache hit
    await adapter.list_actions("doc")
    assert mock_client.actions.list.call_count == 1


@pytest.mark.asyncio
async def test_permitted_actions_batch(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    item = Mock(resource_type_name="doc", external_resource_id="1", actions=["read"])
    mock_client.auth.get_permitted_actions.return_value = Mock(results=[item])

    res = await adapter.get_permitted_actions_batch(
        access_token="t", resources=[{"resource_type_name": "doc", "id": "1"}]
    )
    assert res["doc"]["1"] == ["read"]


@pytest.mark.asyncio
async def test_get_authorization_conditions(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    mock_client.auth.get_authorization_conditions.return_value = Mock(
        filter_type="dsl", conditions_dsl={"and": []}, has_context_refs=False
    )

    res = await adapter.get_authorization_conditions("t", "doc", "read")
    assert res.filter_type == "dsl"


@pytest.mark.asyncio
async def test_get_authorization_filter_success(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    mock_client.auth.get_authorization_conditions.return_value = Mock(
        filter_type="dsl", conditions_dsl={"and": []}, has_context_refs=False
    )

    with patch(
        "cqrs_ddd_auth.contrib.search_query_dsl.ABACConditionConverter"
    ) as converter_cls:
        converter = converter_cls.return_value
        converter.convert_result.return_value = "FILTER_OBJ"
        res = await adapter.get_authorization_filter("t", "doc", "read")
        assert res == "FILTER_OBJ"


@pytest.mark.asyncio
async def test_get_authorization_filter_import_error(mock_sdk_factory):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    with patch.dict("sys.modules", {"cqrs_ddd_auth.contrib.search_query_dsl": None}):
        with pytest.raises(ImportError, match="search_query_dsl is required"):
            await adapter.get_authorization_filter("t", "doc", "read")


@pytest.mark.asyncio
async def test_sync_from_idp(mock_sdk_factory, mock_client):
    adapter = StatefulABACAdapter(ABACClientConfig(mode="http", base_url="h"))
    mock_client.realms.sync.return_value = {"status": "ok"}
    res = await adapter.sync_from_idp()
    assert res["status"] == "ok"


def test_clear_cache():
    adapter = StatefulABACAdapter(ABACClientConfig())
    adapter._resource_types_cache = ["a"]
    adapter._actions_cache = {"b": ["c"]}
    adapter.clear_cache()
    assert adapter._resource_types_cache is None
    assert adapter._actions_cache == {}
