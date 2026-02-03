"""
ABAC Filter Integration with search_query_dsl.

Provides conversion from ABAC JSON condition DSL to SearchQuery objects,
enabling single-query authorization where authorization filters are merged
with user queries for optimal database performance.

Key components:
- FieldMapping: Maps ABAC attribute names to application field names
- ABACConditionConverter: Converts JSON DSL to SearchQuery
- AuthorizationFilter: Result type for authorization filter

Usage:
    from cqrs_ddd_auth.contrib.search_query_dsl import (
        FieldMapping,
        ABACConditionConverter,
        AuthorizationFilter,
    )

    # Configure field mapping
    mapping = FieldMapping(
        mappings={
            "owner_id": "created_by_id",
            "department": "department_code",
        },
        external_id_field="id",
        external_id_cast=int,
    )

    # Create converter
    converter = ABACConditionConverter(mapping)

    # Get conditions from ABAC port
    result = await abac_adapter.get_authorization_conditions(
        access_token=token,
        resource_type="document",
        action="read",
    )

    # Convert to SearchQuery
    if result.granted_all:
        auth_filter = AuthorizationFilter(granted_all=True)
    elif result.denied_all:
        auth_filter = AuthorizationFilter(denied_all=True)
    else:
        search_query = converter.convert(result.conditions_dsl)
        auth_filter = AuthorizationFilter(search_query=search_query)

    # Merge with user query
    if not auth_filter.granted_all and not auth_filter.denied_all:
        combined_query = user_query.merge(auth_filter.search_query)
"""

from cqrs_ddd_auth.contrib.search_query_dsl.converter import (
    FieldMapping,
    ABACConditionConverter,
)
from cqrs_ddd_auth.contrib.search_query_dsl.filter import AuthorizationFilter

__all__ = [
    "FieldMapping",
    "ABACConditionConverter",
    "AuthorizationFilter",
]
