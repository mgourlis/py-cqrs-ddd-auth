"""
ABAC Condition Converter.

Converts ABAC JSON condition DSL to search_query_dsl SearchQuery objects.

The ABAC engine handles all the complexity:
- Evaluates source='principal' and source='context' conditions server-side
- Resolves $context.* and $principal.* references to actual values
- Merges resource-level ACLs into conditions_dsl as IN clauses
- Returns filter_type='granted_all' or 'denied_all' when appropriate

This converter only needs to:
1. Remap ABAC attribute names to application field names
2. Convert the DSL structure to SearchQuery objects
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from cqrs_ddd_auth.infrastructure.ports.authorization import (
        AuthorizationConditionsResult,
    )
    from cqrs_ddd_auth.contrib.search_query_dsl.filter import AuthorizationFilter


from search_query_dsl import SearchQuery, SearchQueryGroup, SearchCondition


logger = logging.getLogger("cqrs_ddd_auth.abac_converter")


@dataclass
class FieldMapping:
    """
    Maps ABAC attribute names to search_query_dsl field names.

    This is application-specific and registered once at startup.
    Different resource types may need different field mappings.

    Attributes:
        mappings: Dict mapping ABAC attr names to DSL field names
            Example: {"owner_id": "created_by_id", "dept": "department_code"}
        external_id_field: DSL field name for ABAC's external_id
            Default: "external_id" (maps to your entity's ID field)
        external_id_cast: Callable to cast external_id values
            Can be a type (int, str, UUID) or a custom function.
            Default is str.
            Examples:
                - int: Cast to integer
                - str: Keep as string
                - lambda x: UUID(x): Parse as UUID
                - lambda x: x.split('-')[0]: Custom parsing

    Example:
        # Simple mapping
        mapping = FieldMapping(
            mappings={
                "owner_id": "created_by_id",
                "department": "department_code",
            },
            external_id_field="id",  # Your entity uses 'id', not 'external_id'
            external_id_cast=int,    # IDs are integers in your schema
        )

        # UUID-based IDs
        from uuid import UUID
        mapping = FieldMapping(
            external_id_field="uuid",
            external_id_cast=lambda x: UUID(x),
        )
    """

    mappings: dict[str, str] = field(default_factory=dict)
    external_id_field: str = "external_id"
    external_id_cast: Callable[[Any], Any] = str

    def get_field(self, abac_attr: str) -> str:
        """
        Get the DSL field name for an ABAC attribute.

        If no mapping exists, returns the original attribute name.
        """
        return self.mappings.get(abac_attr, abac_attr)

    def cast_external_id(self, val: Any) -> Any:
        """
        Cast an external_id value using the configured cast function.

        Handles both single values and lists.
        """
        if isinstance(val, list):
            return [self.external_id_cast(v) for v in val]
        return self.external_id_cast(val)


class ABACConditionConverter:
    """
    Converts ABAC JSON condition DSL to SearchQuery.

    Since the ABAC engine evaluates all $context.* and $principal.*
    references server-side, this converter only needs to:
    1. Remap ABAC attribute names to application field names
    2. Convert the DSL structure to SearchQuery objects

    Supported DSL operators:
    - Comparison: =, !=, <, >, <=, >=
    - Collection: in, not_in
    - String: like, ilike
    - Null: is_null, is_not_null
    - Spatial: st_intersects, st_dwithin, st_contains, st_within
    - Logical: and, or, not

    Example DSL structure (from ABAC):
        {
            "op": "and",
            "conditions": [
                {"op": "=", "attr": "status", "val": "active"},
                {"op": "in", "attr": "external_id", "val": ["1", "2", "3"]}
            ]
        }

    Converted to SearchQuery:
        SearchQuery(groups=[
            SearchQueryGroup(
                group_operator="and",
                conditions=[
                    SearchCondition(field="status", operator="=", value="active"),
                    SearchCondition(field="id", operator="in", value=[1, 2, 3]),
                ]
            )
        ])
    """

    # Operator mapping from ABAC DSL to search_query_dsl
    OPERATOR_MAP = {
        # Comparison
        "=": "=",
        "==": "=",
        "!=": "!=",
        "<>": "!=",
        "<": "<",
        ">": ">",
        "<=": "<=",
        ">=": ">=",
        # Collection
        "in": "in",
        "not_in": "not_in",
        # String
        "like": "like",
        "ilike": "ilike",
        # Null checks
        "is_null": "is_null",
        "is_not_null": "is_not_null",
        # Spatial operators (map to search_query_dsl spatial ops)
        "st_intersects": "intersects",
        "st_dwithin": "dwithin",
        "st_contains": "contains",
        "st_within": "within",
        "st_overlaps": "overlaps",
    }

    def __init__(self, field_mapping: Optional[FieldMapping] = None):
        """
        Initialize the converter.

        Args:
            field_mapping: Optional field mapping configuration.
                If None, uses default mapping (no remapping).
        """
        self.mapping = field_mapping or FieldMapping()

    def convert(self, conditions_dsl: Optional[dict]) -> "SearchQuery":
        """
        Convert ABAC conditions JSON to SearchQuery.

        Args:
            conditions_dsl: The JSON condition DSL from ABAC (already resolved).
                Context references ($context.*, $principal.*) have been
                resolved server-side. Only resource-level conditions remain.

        Returns:
            SearchQuery ready for merging with user query.
            Returns empty SearchQuery if conditions_dsl is None.

        Example:
            dsl = {"op": "and", "conditions": [...]}
            query = converter.convert(dsl)
            combined = user_query.merge(query)
        """
        if conditions_dsl is None:
            return SearchQuery()

        result = self._convert_node(conditions_dsl)

        if isinstance(result, SearchQueryGroup):
            return SearchQuery(groups=[result])
        elif isinstance(result, SearchCondition):
            # Single condition - wrap in a group
            return SearchQuery(groups=[SearchQueryGroup(conditions=[result])])
        else:
            return SearchQuery()

    def _convert_node(
        self, node: dict
    ) -> Union["SearchQueryGroup", "SearchCondition", None]:
        """
        Recursively convert a condition node.

        Handles both compound nodes (and/or/not) and leaf nodes (comparisons).
        """

        if not isinstance(node, dict):
            logger.warning(f"Expected dict node, got {type(node)}")
            return None

        op = node.get("op", "").lower()

        # Compound operators → SearchQueryGroup
        if op in ("and", "or"):
            conditions = node.get("conditions", [])
            converted = []
            for c in conditions:
                result = self._convert_node(c)
                if result is not None:
                    converted.append(result)
            return SearchQueryGroup(conditions=converted, group_operator=op)

        if op == "not":
            inner = node.get("conditions", [])
            if inner:
                result = self._convert_node(inner[0])
                if result is not None:
                    return SearchQueryGroup(conditions=[result], group_operator="not")
            return SearchQueryGroup()

        # Leaf operators → SearchCondition
        return self._convert_leaf(node, op)

    def _convert_leaf(self, node: dict, op: str) -> Optional["SearchCondition"]:
        """
        Convert a leaf condition node to SearchCondition.

        Handles field mapping, operator mapping, and value casting.
        """
        try:
            from search_query_dsl import SearchCondition
        except ImportError:
            raise ImportError("search_query_dsl is required")

        attr = node.get("attr", "")
        val = node.get("val")
        args = node.get("args")  # For spatial operators (e.g., distance)

        if not attr and not op:
            logger.warning(f"Invalid leaf node (no attr or op): {node}")
            return None

        # Remap field name
        # Note: Only resource attributes reach here after server-side evaluation
        field = self.mapping.get_field(attr)

        # Special handling for external_id
        if attr == "external_id":
            field = self.mapping.external_id_field
            if val is not None:
                val = self.mapping.cast_external_id(val)

        # Map operator
        dsl_op = self.OPERATOR_MAP.get(op, op)

        # Handle value and value_type
        value_type = None

        # Spatial operators need special handling
        if op.startswith("st_"):
            value_type = "geometry"

            # st_dwithin needs distance argument
            if op == "st_dwithin" and args is not None:
                # Pack geometry and distance together
                val = {"geometry": val, "distance": args}

        # Handle is_null/is_not_null (no value needed)
        if op in ("is_null", "is_not_null"):
            val = None

        return SearchCondition(
            field=field,
            operator=dsl_op,
            value=val,
            value_type=value_type,
        )

    def convert_result(
        self, result: "AuthorizationConditionsResult"
    ) -> "AuthorizationFilter":
        """
        Convenience method to convert AuthorizationConditionsResult to AuthorizationFilter.

        Args:
            result: Result from ABACAuthorizationPort.get_authorization_conditions()

        Returns:
            AuthorizationFilter with appropriate state

        Example:
            result = await abac_adapter.get_authorization_conditions(...)
            auth_filter = converter.convert_result(result)

            if not auth_filter:
                return []  # Denied
            if auth_filter.granted_all:
                query = user_query
            else:
                query = user_query.merge(auth_filter.search_query)
        """
        from cqrs_ddd_auth.contrib.search_query_dsl.filter import AuthorizationFilter

        if result.granted_all:
            return AuthorizationFilter(granted_all=True)

        if result.denied_all:
            return AuthorizationFilter(denied_all=True)

        # Convert conditions DSL to SearchQuery
        if result.conditions_dsl:
            search_query = self.convert(result.conditions_dsl)
        else:
            # No conditions with filter_type='conditions' - shouldn't happen
            # Treat as denied for safety
            logger.warning(
                "filter_type='conditions' but no conditions_dsl - treating as denied"
            )
            return AuthorizationFilter(denied_all=True)

        return AuthorizationFilter(
            search_query=search_query,
            has_context_refs=result.has_context_refs,
        )
