"""
Authorization Filter result type.

Represents the result of converting ABAC conditions to a SearchQuery filter.
"""

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from search_query_dsl import SearchQuery


@dataclass
class AuthorizationFilter:
    """
    Authorization filter result for single-query authorization.

    Represents one of three outcomes:
    1. granted_all=True: User has blanket access, no filtering needed
    2. denied_all=True: User has no access at all
    3. search_query set: Apply this filter to restrict results

    Usage:
        # Get authorization filter
        auth_filter = await get_auth_filter(...)

        # Handle outcomes
        if auth_filter.denied_all:
            return []  # No access

        if auth_filter.granted_all:
            query = user_query  # No auth filtering needed
        else:
            query = user_query.merge(auth_filter.search_query)

        # Execute query
        results = await repository.search(query)

    Attributes:
        granted_all: True if user has blanket access (no filtering needed)
        denied_all: True if user has no access at all
        search_query: SearchQuery to apply as authorization filter
        has_context_refs: Whether original conditions had $context.* references
            (informational only - references are resolved server-side)
    """

    granted_all: bool = False
    denied_all: bool = False
    search_query: Optional["SearchQuery"] = None
    has_context_refs: bool = False

    def __post_init__(self):
        # Validate mutual exclusivity
        if self.granted_all and self.denied_all:
            raise ValueError("granted_all and denied_all cannot both be True")
        if self.granted_all and self.search_query is not None:
            raise ValueError("granted_all=True should not have search_query")
        if self.denied_all and self.search_query is not None:
            raise ValueError("denied_all=True should not have search_query")

    @property
    def has_filter(self) -> bool:
        """True if a search_query filter should be applied."""
        return (
            self.search_query is not None
            and not self.granted_all
            and not self.denied_all
        )

    def __bool__(self) -> bool:
        """
        Boolean value: True if access is possible (granted_all or has filter).

        Use this for quick access checks:
            if not auth_filter:
                return []  # Denied
        """
        return self.granted_all or self.has_filter
