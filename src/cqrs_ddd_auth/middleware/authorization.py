"""
Authorization Middleware for CQRS.

Provides pre/post execution authorization checks for commands and queries
using the ABAC (Attribute-Based Access Control) authorization port.

Two middleware types:
- AuthorizationMiddleware: Pre-check access before handler runs, post-filter results
- PermittedActionsMiddleware: Enrich results with permitted actions per entity
"""

from dataclasses import dataclass, field
from typing import Callable, Any, Optional
import logging

from cqrs_ddd.protocols import Middleware
from cqrs_ddd_auth.context import get_access_token
from cqrs_ddd_auth.infrastructure.ports.authorization import ABACAuthorizationPort
from cqrs_ddd_auth.domain.errors import AuthorizationError


logger = logging.getLogger("cqrs_ddd_auth.middleware")


@dataclass
class AuthorizationConfig:
    """
    Configuration for AuthorizationMiddleware.

    Attributes:
        resource_type: The ABAC resource type to check (e.g., "document", "order")
        required_actions: Actions required for access (e.g., ["read"], ["write", "delete"])
        quantifier: How to combine required actions:
            - "all": User must have ALL specified actions (default)
            - "any": User must have at least ONE of the specified actions
        resource_id_attr: Attribute on the command/query containing resource ID(s)
            - If None, performs type-level check (no specific resources)
            - Can be a dotted path: "filter.entity_id"
        result_entities_attr: Attribute on the result containing entities to post-filter
            - If None, no post-filtering is performed
            - Can be a dotted path: "data.items"
        entity_id_attr: Attribute on each result entity containing its ID
            - Default: "id" (from AggregateRoot)
        auth_context_provider: Optional callable to provide auth_context
            - Called with (message) -> Optional[dict[str, Any]]
        fail_silently: If True, filter unauthorized resources instead of raising
            - Default: False (raises AuthorizationError on pre-check failure)
            - Post-filtering always filters silently
        deny_anonymous: Immediately deny anonymous users without calling ABAC
            - Default: False (let ABAC decide - handles public resources, anonymous policies)
            - Set True only if you know the resource never allows anonymous access
    """

    resource_type: str
    required_actions: list[str] = field(default_factory=lambda: ["read"])
    quantifier: str = "all"  # "all" or "any"
    resource_id_attr: Optional[str] = None
    result_entities_attr: Optional[str] = None
    entity_id_attr: str = "id"
    auth_context_provider: Optional[Callable[[Any], Optional[dict[str, Any]]]] = None
    fail_silently: bool = False
    deny_anonymous: bool = False


class AuthorizationMiddleware(Middleware):
    """
    Middleware for ABAC authorization checks.

    Performs pre-execution access checks and optional post-execution filtering.

    Pre-check behavior:
    - Extracts resource IDs from command/query using `resource_id_attr`
    - Calls ABAC to check access for the specified actions
    - If unauthorized: raises AuthorizationError (or filters if fail_silently)

    Post-filter behavior (if result_entities_attr is set):
    - Extracts entities from result using `result_entities_attr`
    - Filters out entities the user doesn't have access to
    - Sets the filtered list back on the result

    Example usage:
    ```python
    from cqrs_ddd.middleware import middleware
    from cqrs_ddd_auth.middleware import AuthorizationMiddleware, AuthorizationConfig

    @middleware.apply(
        AuthorizationMiddleware,
        config=AuthorizationConfig(
            resource_type="document",
            required_actions=["read"],
            result_entities_attr="items",
        ),
        authorization_port=abac_adapter,
    )
    class ListDocumentsHandler:
        async def handle(self, query: ListDocuments) -> ListDocumentsResult:
            ...
    ```
    """

    def __init__(
        self,
        config: AuthorizationConfig,
        authorization_port: ABACAuthorizationPort,
    ):
        self.config = config
        self.authorization_port = authorization_port

    def apply(self, handler_func: Callable, message: Any) -> Callable:
        """Wrap handler with authorization checks."""

        async def wrapped(*args, **kwargs) -> Any:
            # Get access token from context
            access_token = get_access_token()
            # identity = get_identity()

            # Handle anonymous users
            if not access_token:
                if self.config.deny_anonymous:
                    logger.debug(
                        f"Denying anonymous user on {self.config.resource_type} (deny_anonymous=True)"
                    )
                    raise AuthorizationError(
                        "Authentication required",
                        resource_type=self.config.resource_type,
                        action=self.config.required_actions[0]
                        if self.config.required_actions
                        else None,
                    )
                # Let ABAC decide - it handles public resources and anonymous policies
                logger.debug(
                    f"Anonymous user accessing {self.config.resource_type} - letting ABAC decide"
                )

            # Get auth_context if provider is configured
            auth_context = None
            if self.config.auth_context_provider:
                auth_context = self.config.auth_context_provider(message)

            # Pre-check: Type-level or resource-level access
            await self._pre_check(access_token, message, auth_context)

            # Execute handler
            result = await handler_func(*args, **kwargs)

            # Post-filter: Filter result entities if configured
            if self.config.result_entities_attr:
                result = await self._post_filter(access_token, result, auth_context)

            return result

        return wrapped

    async def _pre_check(
        self,
        access_token: Optional[str],
        message: Any,
        auth_context: Optional[dict[str, Any]],
    ) -> None:
        """
        Pre-execution access check.

        Raises AuthorizationError if access is denied and fail_silently is False.
        For anonymous users (access_token=None), ABAC handles public resources
        and anonymous-friendly policies.
        """
        # Extract resource IDs from message
        resource_ids = self._extract_resource_ids(message)

        if resource_ids:
            # Resource-level check
            authorized_ids = await self.authorization_port.check_access(
                access_token=access_token,
                action=self.config.required_actions[0],  # Primary action
                resource_type=self.config.resource_type,
                resource_ids=resource_ids,
                auth_context=auth_context,
            )

            # Check if all/any required resources are authorized
            authorized_set = set(authorized_ids)
            requested_set = set(resource_ids)

            if self.config.quantifier == "all":
                is_authorized = requested_set.issubset(authorized_set)
            else:  # "any"
                is_authorized = not requested_set.isdisjoint(authorized_set)

            if not is_authorized:
                if self.config.fail_silently:
                    logger.warning(
                        f"Access denied to {self.config.resource_type} "
                        f"resources: {requested_set - authorized_set}"
                    )
                    return

                raise AuthorizationError(
                    f"Access denied to {self.config.resource_type}",
                    resource_type=self.config.resource_type,
                    action=self.config.required_actions[0],
                    resource_ids=list(requested_set - authorized_set),
                )
        else:
            # Type-level check (no specific resources)
            # Use get_type_level_permissions for efficient check
            permissions = await self.authorization_port.get_type_level_permissions(
                access_token=access_token,
                resource_types=[self.config.resource_type],
                auth_context=auth_context,
            )

            type_actions = set(permissions.get(self.config.resource_type, []))
            required_set = set(self.config.required_actions)

            if self.config.quantifier == "all":
                is_authorized = required_set.issubset(type_actions)
            else:  # "any"
                is_authorized = not required_set.isdisjoint(type_actions)

            if not is_authorized:
                if self.config.fail_silently:
                    logger.warning(
                        f"Type-level access denied to {self.config.resource_type}"
                    )
                    return

                raise AuthorizationError(
                    f"Access denied to {self.config.resource_type}",
                    resource_type=self.config.resource_type,
                    action=self.config.required_actions[0],
                )

    async def _post_filter(
        self,
        access_token: Optional[str],
        result: Any,
        auth_context: Optional[dict[str, Any]],
    ) -> Any:
        """
        Post-execution filtering of result entities.

        Filters out entities the user doesn't have access to.
        Returns the modified result.
        """
        # Extract entities from result
        entities = self._get_nested_attr(result, self.config.result_entities_attr)

        if not entities:
            return result

        # Ensure it's a list/sequence
        if not isinstance(entities, (list, tuple)):
            entities = [entities]

        if not entities:
            return result

        # Extract IDs from entities
        entity_ids = []
        for entity in entities:
            entity_id = self._get_nested_attr(entity, self.config.entity_id_attr)
            if entity_id is not None:
                entity_ids.append(str(entity_id))

        if not entity_ids:
            return result

        # Check access for all entities
        authorized_ids = await self.authorization_port.check_access(
            access_token=access_token,
            action=self.config.required_actions[0],
            resource_type=self.config.resource_type,
            resource_ids=entity_ids,
            auth_context=auth_context,
        )

        authorized_set = set(authorized_ids)

        # Filter entities
        filtered = [
            entity
            for entity in entities
            if str(self._get_nested_attr(entity, self.config.entity_id_attr))
            in authorized_set
        ]

        # Set filtered entities back on result
        self._set_nested_attr(result, self.config.result_entities_attr, filtered)

        logger.debug(
            f"Post-filtered {self.config.resource_type}: "
            f"{len(entities)} -> {len(filtered)} entities"
        )

        return result

    def _extract_resource_ids(self, message: Any) -> Optional[list[str]]:
        """Extract resource IDs from the message using resource_id_attr."""
        if not self.config.resource_id_attr:
            return None

        value = self._get_nested_attr(message, self.config.resource_id_attr)

        if value is None:
            return None

        # Normalize to list of strings
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value]
        else:
            return [str(value)]

    def _get_nested_attr(self, obj: Any, path: str) -> Any:
        """Get a nested attribute using dot notation (e.g., 'data.items')."""
        parts = path.split(".")
        current = obj

        for part in parts:
            if current is None:
                return None

            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict):
                current = current.get(part)
            else:
                return None

        return current

    def _set_nested_attr(self, obj: Any, path: str, value: Any) -> None:
        """Set a nested attribute using dot notation."""
        parts = path.split(".")
        current = obj

        # Navigate to the parent of the target attribute
        for part in parts[:-1]:
            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict):
                current = current[part]
            else:
                return

        # Set the final attribute
        final_attr = parts[-1]
        if hasattr(current, final_attr):
            setattr(current, final_attr, value)
        elif isinstance(current, dict):
            current[final_attr] = value


@dataclass
class PermittedActionsConfig:
    """
    Configuration for PermittedActionsMiddleware.

    Attributes:
        resource_type: The ABAC resource type
        result_entities_attr: Attribute on the result containing entities
            - Required for this middleware
        entity_id_attr: Attribute on each entity containing its ID
            - Default: "id" (from AggregateRoot)
        permitted_actions_attr: Attribute name to set on each entity with permitted actions
            - Default: "permitted_actions"
        include_type_level: Include type-level permissions in each entity
            - Default: False
        auth_context_provider: Optional callable to provide auth_context
    """

    resource_type: str
    result_entities_attr: str
    entity_id_attr: str = "id"
    permitted_actions_attr: str = "permitted_actions"
    include_type_level: bool = False
    auth_context_provider: Optional[Callable[[Any], Optional[dict[str, Any]]]] = None


class PermittedActionsMiddleware(Middleware):
    """
    Middleware to enrich result entities with permitted actions.

    After the handler executes, this middleware:
    1. Extracts entities from the result
    2. Queries ABAC for permitted actions per entity
    3. Adds a `permitted_actions` attribute to each entity

    This enables UI-level authorization decisions (show/hide buttons, etc.)
    without additional API calls.

    Example usage:
    ```python
    from cqrs_ddd.middleware import middleware
    from cqrs_ddd_auth.middleware import PermittedActionsMiddleware, PermittedActionsConfig

    @middleware.apply(
        PermittedActionsMiddleware,
        config=PermittedActionsConfig(
            resource_type="document",
            result_entities_attr="items",
        ),
        authorization_port=abac_adapter,
    )
    class ListDocumentsHandler:
        async def handle(self, query: ListDocuments) -> ListDocumentsResult:
            ...

    # Result entities will have:
    # item.permitted_actions = ["read", "update"]
    ```
    """

    def __init__(
        self,
        config: PermittedActionsConfig,
        authorization_port: ABACAuthorizationPort,
    ):
        self.config = config
        self.authorization_port = authorization_port

    def apply(self, handler_func: Callable, message: Any) -> Callable:
        """Wrap handler to enrich results with permitted actions."""

        async def wrapped(*args, **kwargs) -> Any:
            # Execute handler first
            result = await handler_func(*args, **kwargs)

            # Get access token from context
            access_token = get_access_token()

            if not access_token:
                # Anonymous user - no permitted actions
                return result

            # Get auth_context if provider is configured
            auth_context = None
            if self.config.auth_context_provider:
                auth_context = self.config.auth_context_provider(message)

            # Enrich entities with permitted actions
            result = await self._enrich_permitted_actions(
                access_token, result, auth_context
            )

            return result

        return wrapped

    async def _enrich_permitted_actions(
        self,
        access_token: str,
        result: Any,
        auth_context: Optional[dict[str, Any]],
    ) -> Any:
        """Add permitted_actions to each entity in the result."""
        # Extract entities from result
        entities = self._get_nested_attr(result, self.config.result_entities_attr)

        if not entities:
            return result

        # Ensure it's a list/sequence
        if not isinstance(entities, (list, tuple)):
            entities = [entities]

        if not entities:
            return result

        # Extract IDs from entities
        entity_ids = []
        for entity in entities:
            entity_id = self._get_nested_attr(entity, self.config.entity_id_attr)
            if entity_id is not None:
                entity_ids.append(str(entity_id))

        if not entity_ids:
            return result

        # Query permitted actions for all entities in one batch call
        permissions = await self.authorization_port.get_permitted_actions(
            access_token=access_token,
            resource_type=self.config.resource_type,
            resource_ids=entity_ids,
            auth_context=auth_context,
        )

        # Optionally get type-level permissions
        type_actions = []
        if self.config.include_type_level:
            type_permissions = await self.authorization_port.get_type_level_permissions(
                access_token=access_token,
                resource_types=[self.config.resource_type],
                auth_context=auth_context,
            )
            type_actions = type_permissions.get(self.config.resource_type, [])

        # Add permitted_actions to each entity
        for entity in entities:
            entity_id = str(self._get_nested_attr(entity, self.config.entity_id_attr))
            entity_actions = permissions.get(entity_id, [])

            # Merge with type-level if configured
            if self.config.include_type_level:
                entity_actions = list(set(entity_actions) | set(type_actions))

            # Set the permitted actions on the entity
            self._set_attr(entity, self.config.permitted_actions_attr, entity_actions)

        logger.debug(
            f"Enriched {len(entities)} {self.config.resource_type} entities "
            f"with permitted actions"
        )

        return result

    def _get_nested_attr(self, obj: Any, path: str) -> Any:
        """Get a nested attribute using dot notation."""
        parts = path.split(".")
        current = obj

        for part in parts:
            if current is None:
                return None

            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict):
                current = current.get(part)
            else:
                return None

        return current

    def _set_attr(self, obj: Any, attr: str, value: Any) -> None:
        """Set an attribute on an object."""
        if hasattr(obj, attr):
            setattr(obj, attr, value)
        elif isinstance(obj, dict):
            obj[attr] = value
        else:
            # Try to set even if it doesn't exist
            try:
                setattr(obj, attr, value)
            except AttributeError:
                # If the object doesn't support attribute setting,
                # try treating it as having a __dict__
                if hasattr(obj, "__dict__"):
                    obj.__dict__[attr] = value


# =============================================================================
# Convenience Functions
# =============================================================================


def authorize(
    resource_type: str,
    required_actions: Optional[list[str]] = None,
    quantifier: str = "all",
    resource_id_attr: Optional[str] = None,
    result_entities_attr: Optional[str] = None,
    entity_id_attr: str = "id",
    fail_silently: bool = False,
    deny_anonymous: bool = False,
) -> AuthorizationConfig:
    """
    Convenience function to create an AuthorizationConfig.

    Example:
    ```python
    from cqrs_ddd_auth.middleware import authorize

    config = authorize(
        resource_type="document",
        required_actions=["read"],
        result_entities_attr="items",
    )
    ```
    """
    return AuthorizationConfig(
        resource_type=resource_type,
        required_actions=required_actions or ["read"],
        quantifier=quantifier,
        resource_id_attr=resource_id_attr,
        result_entities_attr=result_entities_attr,
        entity_id_attr=entity_id_attr,
        fail_silently=fail_silently,
        deny_anonymous=deny_anonymous,
    )


def permitted_actions(
    resource_type: str,
    result_entities_attr: str,
    entity_id_attr: str = "id",
    permitted_actions_attr: str = "permitted_actions",
    include_type_level: bool = False,
) -> PermittedActionsConfig:
    """
    Convenience function to create a PermittedActionsConfig.

    Example:
    ```python
    from cqrs_ddd_auth.middleware import permitted_actions

    config = permitted_actions(
        resource_type="document",
        result_entities_attr="items",
    )
    ```
    """
    return PermittedActionsConfig(
        resource_type=resource_type,
        result_entities_attr=result_entities_attr,
        entity_id_attr=entity_id_attr,
        permitted_actions_attr=permitted_actions_attr,
        include_type_level=include_type_level,
    )


def register_abac_middleware(authorization_port: ABACAuthorizationPort) -> None:
    """
    Register ABAC authorization middleware into py-cqrs-ddd-toolkit's MiddlewareRegistry.

    This replaces the skeleton middlewares with our ABAC implementations,
    enabling usage of `@middleware.authorize()` and `@middleware.permitted_actions()` decorators.

    Registers:
    - `middleware.classes['authorization']` -> AuthorizationMiddleware
    - `middleware.classes['permitted_actions']` -> PermittedActionsMiddleware

    Example:
    ```python
    from cqrs_ddd.middleware import middleware
    from cqrs_ddd_auth.middleware import register_abac_middleware
    from cqrs_ddd_auth.contrib.stateful_abac import StatefulABACAdapter, ABACClientConfig

    # Setup ABAC adapter
    abac_adapter = StatefulABACAdapter(ABACClientConfig(...))

    # Register once at application startup
    register_abac_middleware(abac_adapter)

    # Now use the standard decorators
    @middleware.authorize(
        resource_type="document",
        required_actions=["read"],
    )
    class ListDocumentsHandler:
        ...

    @middleware.permitted_actions(
        resource_type="document",
        result_entities_attr="items",
    )
    class ListDocumentsWithActionsHandler:
        ...
    ```

    Args:
        authorization_port: The ABAC authorization adapter to use for all auth checks
    """
    from cqrs_ddd.middleware import middleware

    # Create a wrapper class that pre-binds the authorization_port
    class BoundAuthorizationMiddleware(AuthorizationMiddleware):
        def __init__(
            self,
            resource_type: str,
            required_actions: list[str] = None,
            quantifier: str = "all",
            resource_id_attr: str = None,
            result_entities_attr: str = None,
            entity_id_attr: str = "id",
            fail_silently: bool = False,
            deny_anonymous: bool = False,
            **kwargs,  # Ignore extra kwargs from legacy calls
        ):
            config = AuthorizationConfig(
                resource_type=resource_type,
                required_actions=required_actions or ["read"],
                quantifier=quantifier,
                resource_id_attr=resource_id_attr,
                result_entities_attr=result_entities_attr,
                entity_id_attr=entity_id_attr,
                fail_silently=fail_silently,
                deny_anonymous=deny_anonymous,
            )
            super().__init__(config=config, authorization_port=authorization_port)

    # Create a wrapper class for PermittedActionsMiddleware
    class BoundPermittedActionsMiddleware(PermittedActionsMiddleware):
        def __init__(
            self,
            resource_type: str,
            result_entities_attr: str,
            entity_id_attr: str = "id",
            permitted_actions_attr: str = "permitted_actions",
            include_type_level: bool = False,
            **kwargs,  # Ignore extra kwargs from legacy calls
        ):
            config = PermittedActionsConfig(
                resource_type=resource_type,
                result_entities_attr=result_entities_attr,
                entity_id_attr=entity_id_attr,
                permitted_actions_attr=permitted_actions_attr,
                include_type_level=include_type_level,
            )
            super().__init__(config=config, authorization_port=authorization_port)

    # Replace the skeletons in the registry
    middleware.classes["authorization"] = BoundAuthorizationMiddleware
    middleware.classes["permitted_actions"] = BoundPermittedActionsMiddleware

    # Monkey-patch the permitted_actions decorator onto the registry if missing
    if not hasattr(middleware, "permitted_actions"):

        def permitted_actions(
            resource_type: str,
            result_entities_attr: str,
            entity_id_attr: str = "id",
            permitted_actions_attr: str = "permitted_actions",
            include_type_level: bool = False,
        ):
            """Decorator to add permitted actions middleware."""

            def decorator(handler_class):
                return middleware._register(
                    handler_class,
                    middleware.classes["permitted_actions"],
                    resource_type=resource_type,
                    result_entities_attr=result_entities_attr,
                    entity_id_attr=entity_id_attr,
                    permitted_actions_attr=permitted_actions_attr,
                    include_type_level=include_type_level,
                )

            return decorator

        setattr(middleware, "permitted_actions", permitted_actions)
