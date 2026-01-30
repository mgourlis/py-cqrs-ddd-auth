"""
ABAC Authorization Adapter.

Implements ABACAuthorizationPort using the stateful-abac-sdk.
Supports both HTTP and DB modes for different deployment scenarios.
"""

from dataclasses import dataclass, field
from typing import Optional, Any
from functools import lru_cache

from cqrs_ddd_auth.ports.authorization import (
    ABACAuthorizationPort,
    AuthorizationConditionsResult,
    CheckAccessBatchResult,
)


@dataclass
class ABACClientConfig:
    """
    Configuration for ABAC client.
    
    Supports two modes:
    - HTTP mode: Uses REST API (standard deployment)
    - DB mode: Uses direct SQL (10-100x faster for co-located services)
    """
    mode: str = "http"  # "http" or "db"
    
    # HTTP mode settings
    base_url: Optional[str] = None  # e.g., "http://localhost:8000/api/v1"
    
    # DB mode settings
    database_url: Optional[str] = None  # e.g., "postgresql+asyncpg://..."
    
    # Common settings
    realm: str = "default"
    
    # Performance tuning (HTTP mode)
    chunk_size: int = 100  # Batch size for check_access
    max_concurrent: int = 5  # Max concurrent requests
    
    # Caching
    cache_resource_types: bool = True
    cache_actions: bool = True
    cache_ttl_seconds: int = 300  # 5 minutes


class StatefulABACAdapter:
    """
    ABAC Authorization adapter using stateful-abac-sdk.
    
    Implements ABACAuthorizationPort for integration with
    the Stateful ABAC Policy Engine.
    
    Example usage:
        # HTTP mode (standard)
        config = ABACClientConfig(
            mode="http",
            base_url="http://abac-engine:8000/api/v1",
            realm="my-realm",
        )
        adapter = StatefulABACAdapter(config)
        
        # DB mode (high performance)
        config = ABACClientConfig(
            mode="db",
            database_url="postgresql+asyncpg://...",
            realm="my-realm",
        )
        adapter = StatefulABACAdapter(config)
        
        # Check access
        async with adapter:
            adapter.set_token(access_token)
            allowed_ids = await adapter.check_access(
                access_token=token,
                action="read",
                resource_type="document",
                resource_ids=["doc-1", "doc-2"],
            )
    """
    
    def __init__(self, config: ABACClientConfig):
        self.config = config
        self._client = None
        self._resource_types_cache: Optional[list[str]] = None
        self._actions_cache: dict[str, list[str]] = {}
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def _ensure_client(self):
        """Ensure client is initialized."""
        if self._client is None:
            try:
                from stateful_abac_sdk import StatefulABACClient
            except ImportError:
                raise ImportError(
                    "stateful-abac-sdk is required for ABAC integration. "
                    "Install it with: pip install stateful-abac-sdk"
                )
            
            if self.config.mode == "http":
                if not self.config.base_url:
                    raise ValueError("base_url is required for HTTP mode")
                self._client = StatefulABACClient(
                    base_url=self.config.base_url,
                    mode="http",
                )
            elif self.config.mode == "db":
                if not self.config.database_url:
                    raise ValueError("database_url is required for DB mode")
                self._client = StatefulABACClient(
                    mode="db",
                    database_url=self.config.database_url,
                )
            else:
                raise ValueError(f"Invalid mode: {self.config.mode}. Use 'http' or 'db'")
    
    def set_token(self, token: str):
        """
        Set the access token for authorization checks.
        
        The token is used to extract roles for authorization.
        """
        if self._client:
            self._client.set_token(token)
    
    async def close(self):
        """Close the client connection."""
        if self._client:
            await self._client.close()
            self._client = None
    
    # ═══════════════════════════════════════════════════════════════
    # ABACAuthorizationPort Implementation
    # ═══════════════════════════════════════════════════════════════
    
    async def check_access(
        self,
        access_token: str,
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None,
        auth_context: Optional[dict[str, Any]] = None,
    ) -> list[str]:
        """
        Check which resources the user can access.
        
        Args:
            access_token: JWT access token
            action: Action to check (read, write, delete, etc.)
            resource_type: Type of resource
            resource_ids: Optional list of specific resource IDs
            auth_context: Optional runtime context (e.g., {"username": ..., "groups": [...]})
        
        Returns:
            List of authorized resource IDs (empty if denied)
        """
        await self._ensure_client()
        self.set_token(access_token)
        
        try:
            from stateful_abac_sdk import CheckAccessItem
        except ImportError:
            from stateful_abac_sdk.models import CheckAccessItem
        
        # Build check access request
        check_item = CheckAccessItem(
            resource_type_name=resource_type,
            action_name=action,
            return_type="id_list",
            external_resource_ids=resource_ids,
        )
        
        response = await self._client.auth.check_access(
            resources=[check_item],
            auth_context=auth_context,
            chunk_size=self.config.chunk_size,
            max_concurrent=self.config.max_concurrent,
        )
        
        # Extract authorized IDs from response
        if response.results:
            result = response.results[0]
            if isinstance(result.answer, list):
                return [str(id) for id in result.answer]
            elif result.answer is True:
                # Blanket access - return all requested IDs
                return resource_ids or []
        
        return []
    
    async def check_access_batch(
        self,
        access_token: str,
        resources: list[dict[str, Any]],
        auth_context: Optional[dict[str, Any]] = None,
    ) -> "CheckAccessBatchResult":
        """
        Batch check access for multiple resources/actions in a single call.
        
        This is the pattern used by CQRS authorization middleware for efficient
        bulk authorization checks.
        
        Args:
            access_token: JWT access token
            resources: List of dicts with keys:
                - resource_type_name: str
                - action_name: str
                - external_resource_ids: list[str] | None
                - return_type: "id_list" | "decision" (default: "id_list")
            auth_context: Optional runtime context (e.g., {"username": ..., "groups": [...]})
        
        Returns:
            CheckAccessBatchResult with access_map and global_permissions
        """
        await self._ensure_client()
        self.set_token(access_token)
        
        try:
            from stateful_abac_sdk import CheckAccessItem
        except ImportError:
            from stateful_abac_sdk.models import CheckAccessItem
        
        # Build check items from resource dicts
        check_items = [
            CheckAccessItem(
                resource_type_name=r["resource_type_name"],
                action_name=r["action_name"],
                external_resource_ids=r.get("external_resource_ids"),
                return_type=r.get("return_type", "id_list"),
            )
            for r in resources
        ]
        
        response = await self._client.auth.check_access(
            resources=check_items,
            auth_context=auth_context,
            chunk_size=self.config.chunk_size,
            max_concurrent=self.config.max_concurrent,
        )
        
        # Build access map: (type, id) -> set(actions)
        # and global_permissions: set of globally granted actions
        access_map: dict[tuple[str | None, str], set[str]] = {}
        global_permissions: set[str] = set()
        
        if response and response.results:
            for result in response.results:
                action = result.action_name
                r_type = getattr(result, "resource_type_name", None)
                
                if isinstance(result.answer, list):
                    # List of authorized IDs
                    for eid in result.answer:
                        key: tuple[str | None, str] = (r_type, str(eid))
                        if key not in access_map:
                            access_map[key] = set()
                        access_map[key].add(action)
                elif result.answer is True:
                    # Blanket (global) access for this action
                    global_permissions.add(action)
        
        return CheckAccessBatchResult(
            access_map=access_map,
            global_permissions=global_permissions,
        )

    async def get_permitted_actions(
        self,
        access_token: str,
        resource_type: str,
        resource_ids: list[str],
        auth_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, list[str]]:
        """
        Get permitted actions per resource.
        
        Args:
            access_token: JWT access token
            resource_type: Type of resource
            resource_ids: List of resource IDs
            auth_context: Optional runtime context (e.g., {"username": ..., "groups": [...]})
        
        Returns:
            Dict mapping resource_id -> list of permitted actions
        """
        await self._ensure_client()
        self.set_token(access_token)
        
        try:
            from stateful_abac_sdk import GetPermittedActionsItem
        except ImportError:
            from stateful_abac_sdk.models import GetPermittedActionsItem
        
        # Build request
        check_item = GetPermittedActionsItem(
            resource_type_name=resource_type,
            external_resource_ids=resource_ids,
        )
        
        response = await self._client.auth.get_permitted_actions(
            resources=[check_item],
            auth_context=auth_context,
        )
        
        # Map results to dict
        result: dict[str, list[str]] = {}
        for item in response.results:
            if item.external_resource_id:
                result[item.external_resource_id] = item.actions
        
        return result
    
    async def get_permitted_actions_batch(
        self,
        access_token: str,
        resources: list[dict[str, Any]],
        auth_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, dict[str, list[str]]]:
        """
        Batch get permitted actions for multiple resource types.
        
        This is the pattern used by CQRS PermittedActionsMiddleware for efficient
        bulk permission lookups.
        
        Args:
            access_token: JWT access token
            resources: List of dicts with keys:
                - resource_type_name: str
                - external_resource_ids: list[str] | None
            auth_context: Optional runtime context
        
        Returns:
            Nested dict: resource_type -> resource_id -> list of actions
        """
        await self._ensure_client()
        self.set_token(access_token)
        
        try:
            from stateful_abac_sdk import GetPermittedActionsItem
        except ImportError:
            from stateful_abac_sdk.models import GetPermittedActionsItem
        
        # Build request items
        items = [
            GetPermittedActionsItem(
                resource_type_name=r["resource_type_name"],
                external_resource_ids=r.get("external_resource_ids"),
            )
            for r in resources
        ]
        
        response = await self._client.auth.get_permitted_actions(
            resources=items,
            auth_context=auth_context,
        )
        
        # Map results: type -> id -> actions
        result: dict[str, dict[str, list[str]]] = {}
        if response and response.results:
            for item in response.results:
                r_type = item.resource_type_name
                if r_type not in result:
                    result[r_type] = {}
                if item.external_resource_id:
                    result[r_type][item.external_resource_id] = item.actions
        
        return result
    
    async def list_resource_types(self) -> list[str]:
        """List all available resource types."""
        await self._ensure_client()
        
        # Use cache if enabled
        if self.config.cache_resource_types and self._resource_types_cache is not None:
            return self._resource_types_cache
        
        resource_types = await self._client.resource_types.list()
        names = [rt.name for rt in resource_types]
        
        if self.config.cache_resource_types:
            self._resource_types_cache = names
        
        return names
    
    async def list_actions(self, resource_type: str) -> list[str]:
        """List all actions for a resource type."""
        await self._ensure_client()
        
        # Use cache if enabled
        if self.config.cache_actions and resource_type in self._actions_cache:
            return self._actions_cache[resource_type]
        
        # Actions are realm-level in stateful-abac, not per resource type
        actions = await self._client.actions.list()
        names = [a.name for a in actions]
        
        if self.config.cache_actions:
            self._actions_cache[resource_type] = names
        
        return names
    
    async def get_type_level_permissions(
        self,
        access_token: str,
        resource_types: list[str],
        auth_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, list[str]]:
        """
        Get type-level permissions (what actions can user perform on each type).
        
        This is used for UI rendering - showing which menu items,
        buttons, etc. the user has access to.
        
        Also used by middleware for "global access" optimization checks.
        
        Args:
            access_token: JWT access token
            resource_types: List of resource types to check
            auth_context: Optional runtime context (e.g., {"username": ..., "groups": [...]})
        
        Returns:
            Dict mapping resource_type -> list of permitted actions
        """
        await self._ensure_client()
        self.set_token(access_token)
        
        try:
            from stateful_abac_sdk import GetPermittedActionsItem
        except ImportError:
            from stateful_abac_sdk.models import GetPermittedActionsItem
        
        # Build requests for type-level checks (no resource IDs)
        items = [
            GetPermittedActionsItem(
                resource_type_name=rt,
                external_resource_ids=None,  # Type-level check
            )
            for rt in resource_types
        ]
        
        response = await self._client.auth.get_permitted_actions(
            resources=items,
            auth_context=auth_context,
        )
        
        # Map results to dict
        result: dict[str, list[str]] = {}
        for item in response.results:
            result[item.resource_type_name] = item.actions
        
        return result
    
    async def get_authorization_conditions(
        self,
        access_token: str,
        resource_type: str,
        action: str,
        auth_context: Optional[dict[str, Any]] = None,
    ) -> AuthorizationConditionsResult:
        """
        Get authorization conditions as a filter for single-query authorization.
        
        This enables merging authorization with user queries for optimal
        database performance (single query instead of post-filtering).
        
        Args:
            access_token: JWT access token
            resource_type: Type of resource being queried
            action: Action being performed (e.g., "read")
            auth_context: Optional runtime context for condition evaluation
        
        Returns:
            AuthorizationConditionsResult with filter_type and conditions_dsl
        """
        await self._ensure_client()
        self.set_token(access_token)
        
        response = await self._client.auth.get_authorization_conditions(
            resource_type_name=resource_type,
            action_name=action,
            auth_context=auth_context,
        )
        
        return AuthorizationConditionsResult(
            filter_type=response.filter_type,
            conditions_dsl=response.conditions_dsl,
        )
    
    # ═══════════════════════════════════════════════════════════════
    # Additional Methods
    # ═══════════════════════════════════════════════════════════════
    
    async def sync_from_idp(self) -> dict[str, Any]:
        """
        Trigger sync from the identity provider (Keycloak).
        
        This updates principals and roles from the IdP.
        """
        await self._ensure_client()
        return await self._client.realms.sync()
    
    def clear_cache(self):
        """Clear cached resource types and actions."""
        self._resource_types_cache = None
        self._actions_cache.clear()
