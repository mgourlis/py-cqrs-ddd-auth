"""
Authorization Port.

Defines the interface for ABAC (Attribute-Based Access Control) authorization.
"""

from typing import Protocol, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from search_query_dsl import FieldMapping
from dataclasses import dataclass


class ABACAuthorizationPort(Protocol):
    """
    Port for ABAC authorization checks.

    Integrates with the Stateful ABAC Policy Engine or
    similar authorization services.
    """

    async def check_access(
        self,
        access_token: Optional[str],
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> list[str]:
        """
        Check which resources the user can access.

        Args:
            access_token: JWT access token (None for anonymous users)
            action: Action to check (read, write, delete, etc.)
            resource_type: Type of resource
            resource_ids: Optional list of specific resource IDs
            auth_context: Optional runtime context (e.g., {"username": ..., "groups": [...]})
            role_names: Optional explicit role names (overrides token roles)

        Returns:
            List of authorized resource IDs (empty if denied)
        """
        ...

    async def check_access_batch(
        self,
        access_token: Optional[str],
        resources: list[dict[str, Any]],
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
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
            auth_context: Optional runtime context

        Returns:
            CheckAccessBatchResult with access_map and global_permissions
        """
        ...

    async def get_permitted_actions(
        self,
        access_token: Optional[str],
        resource_type: str,
        resource_ids: Optional[list[str]] = None,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> dict[str, list[str]]:
        """
        Get permitted actions per resource or at type-level.

        Args:
            access_token: JWT access token
            resource_type: Type of resource
            resource_ids: List of resource IDs (None for type-level check)
            auth_context: Optional runtime context

        Returns:
            Dict mapping resource_id -> list of permitted actions
            For type-level: returns {resource_type: [actions]}
        """
        ...

    async def get_permitted_actions_batch(
        self,
        access_token: Optional[str],
        resources: list[dict[str, Any]],
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> dict[str, dict[str, list[str]]]:
        """
        Batch get permitted actions for multiple resource types.

        Args:
            access_token: JWT access token
            resources: List of dicts with keys:
                - resource_type_name: str
                - external_resource_ids: list[str] | None
            auth_context: Optional runtime context
            role_names: Optional explicit role names (overrides token roles)

        Returns:
            Nested dict: resource_type -> resource_id -> list of actions
        """
        ...

    async def list_resource_types(self) -> list[str]:
        """List all available resource types."""
        ...

    async def list_actions(self, resource_type: str) -> list[str]:
        """List all actions for a resource type."""
        ...

    async def get_type_level_permissions(
        self,
        access_token: Optional[str],
        resource_types: list[str],
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> dict[str, list[str]]:
        """
        Get type-level permissions (what actions can user perform on each type).

        This is used for:
        - UI rendering (menu items, buttons visibility)
        - Global access optimization in middleware

        Args:
            access_token: JWT access token
            resource_types: List of resource types to check
            auth_context: Optional runtime context
            role_names: Optional explicit role names (overrides token roles)

        Returns:
            Dict mapping resource_type -> list of permitted actions
            Example: {"document": ["read", "create"], "user": ["read"]}
        """
        ...

    async def get_authorization_conditions(
        self,
        access_token: Optional[str],
        resource_type: str,
        action: str,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> "AuthorizationConditionsResult":
        """
        Get authorization conditions as a filter for single-query authorization.

        This enables merging authorization with user queries for optimal
        database performance (single query instead of post-filtering).

        Context references ($context.* and $principal.*) are resolved server-side,
        so the conditions_dsl is ready for direct conversion to SearchQuery.

        Args:
            access_token: JWT access token
            resource_type: Type of resource being queried
            action: Action being performed (e.g., "read")
            auth_context: Optional runtime context for $context.* resolution
            role_names: Optional explicit role names (overrides token roles)

        Returns:
            AuthorizationConditionsResult with filter_type and conditions_dsl
        """
        ...

    async def get_authorization_filter(
        self,
        access_token: Optional[str],
        resource_type: str,
        action: str,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
        field_mapping: Optional["FieldMapping"] = None,
    ) -> "AuthorizationFilter":
        """
        Get authorization filter as a SearchQuery-ready object.

        This is a convenience method that combines get_authorization_conditions()
        with ABACConditionConverter to return an AuthorizationFilter directly.

        Requires the search_query_dsl package to be installed.

        Args:
            access_token: JWT access token (None for anonymous users)
            resource_type: Type of resource being queried
            action: Action being performed (e.g., "read")
            auth_context: Optional runtime context for $context.* resolution
            role_names: Optional explicit role names (overrides token roles)
            field_mapping: Optional field mapping for DSL conversion

        Returns:
            AuthorizationFilter with granted_all, denied_all, or search_query

        Example:
            auth_filter = await adapter.get_authorization_filter(
                access_token=token,
                resource_type="document",
                action="read",
                field_mapping=FieldMapping(
                    external_id_field="id",
                    external_id_cast=int,
                ),
            )

            if not auth_filter:
                return []  # Denied
            if auth_filter.granted_all:
                query = user_query
            else:
                query = user_query.merge(auth_filter.search_query)
        """
        ...

    async def sync_from_idp(self) -> dict[str, Any]:
        """
        Trigger sync from the identity provider (Keycloak).

        This updates principals and roles from the IdP.
        """
        ...


class AuthorizationConditionsResult:
    """
    Result from get_authorization_conditions.

    Contains the filter type and optional conditions DSL
    for single-query authorization.

    The conditions_dsl can be converted to SearchQuery and merged with
    user queries for single-query authorization using SearchQuery.merge().

    Key features:
    - $context.* and $principal.* references are resolved server-side
    - Evaluable conditions (source='principal'/'context') are pre-evaluated
    - Resource-level ACLs are merged into conditions_dsl
    - If all conditions evaluate to true/false, returns granted_all/denied_all
    """

    def __init__(
        self,
        filter_type: str,  # "granted_all", "denied_all", or "conditions"
        conditions_dsl: Optional[dict] = None,
        has_context_refs: bool = False,
    ):
        self.filter_type = filter_type
        self.conditions_dsl = conditions_dsl
        self.has_context_refs = has_context_refs

    @property
    def granted_all(self) -> bool:
        """True if user has blanket access (no filtering needed)."""
        return self.filter_type == "granted_all"

    @property
    def denied_all(self) -> bool:
        """True if user has no access at all."""
        return self.filter_type == "denied_all"

    @property
    def has_conditions(self) -> bool:
        """True if authorization requires condition-based filtering."""
        return self.filter_type == "conditions"


class CheckAccessBatchResult:
    """
    Result from batch check_access operation.

    Used by authorization middleware to efficiently check
    multiple resources/actions in a single call.
    """

    def __init__(
        self,
        access_map: dict[tuple[str | None, str], set[str]] | None = None,
        global_permissions: set[str] | None = None,
    ):
        # Map of (resource_type, resource_id) -> set of granted actions
        self.access_map = access_map or {}
        # Set of globally granted actions (blanket access)
        self.global_permissions = global_permissions or set()

    def is_allowed(
        self,
        resource_type: str,
        resource_id: str,
        required_actions: set[str],
        quantifier: str = "all",
    ) -> bool:
        """
        Check if access is allowed for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: ID of resource
            required_actions: Set of required action names
            quantifier: "all" (default) or "any"

        Returns:
            True if access is granted based on quantifier
        """
        # Get resource-specific permissions
        perms = self.access_map.get((resource_type, resource_id), set())
        # Merge with global permissions
        granted = perms | self.global_permissions

        if not required_actions:
            return True
        if quantifier == "any":
            return not required_actions.isdisjoint(granted)
        return required_actions.issubset(granted)  # "all"


@dataclass
class AuthorizationFilter:
    """
    Search-compatible authorization filter.

    This object is used to integrate authorization with database queries.
    It can be directly used by the query layer to restrict results
    to what the user is allowed to see.
    """

    granted_all: bool = False
    denied_all: bool = False
    search_query: Optional[Any] = None  # DSL or ORM query object

    @classmethod
    def grant_all(cls) -> "AuthorizationFilter":
        return cls(granted_all=True)

    @classmethod
    def deny_all(cls) -> "AuthorizationFilter":
        return cls(denied_all=True)

    @classmethod
    def from_query(cls, query: Any) -> "AuthorizationFilter":
        return cls(search_query=query)
