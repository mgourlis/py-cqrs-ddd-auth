"""
Simple RBAC Adapter for Authorization.

Implements a basic role-based access control adapter that doesn't rely
on an external policy engine. Suitable for simple applications.
"""

from typing import Any, Optional, Dict, List, Set, Protocol
import logging

from cqrs_ddd_auth.infrastructure.ports.authorization import (
    ABACAuthorizationPort,
    AuthorizationConditionsResult,
    CheckAccessBatchResult,
    AuthorizationFilter,
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# PROTOCOLS & STRATEGIES
# ----------------------------------------------------------------------


class RoleExtractor(Protocol):
    """Protocol for extracting roles from context."""

    def __call__(
        self, access_token: Optional[str], auth_context: Optional[dict]
    ) -> List[str]:
        ...


def default_role_extractor(
    access_token: Optional[str], auth_context: Optional[dict]
) -> List[str]:
    """Default extractor looking in standard context keys."""
    if not auth_context:
        return []
    return auth_context.get("roles") or auth_context.get("groups") or []


class OwnershipStrategy(Protocol):
    """Protocol for checking resource ownership."""

    async def is_owner(
        self, user_id: str, resource_type: str, resource_id: str
    ) -> bool:
        """Check if user owns the specific resource."""
        ...


# ----------------------------------------------------------------------
# SIMPLE RBAC ADAPTER
# ----------------------------------------------------------------------


class SimpleRBACAdapter(ABACAuthorizationPort):
    """
    Simple Role-Based Access Control Adapter.

    Maps roles to permitted actions.
    Now supports pluggable role extraction and logging.

    Configuration format:
    {
        "role_name": ["action1", "action2", "*"],
        "admin": ["*"],
    }
    """

    def __init__(
        self,
        role_permissions: Dict[str, List[str]],
        role_extractor: Optional[RoleExtractor] = None,
    ):
        self.role_permissions = role_permissions
        self._role_map: Dict[str, Set[str]] = {
            role: set(actions) for role, actions in role_permissions.items()
        }
        self.role_extractor = role_extractor or default_role_extractor

    def _get_user_roles(
        self,
        access_token: Optional[str],
        auth_context: Optional[dict] = None,
        role_names: Optional[list[str]] = None,
    ) -> List[str]:
        """Extract roles using strategy."""
        if role_names:
            return role_names
        return self.role_extractor(access_token, auth_context)

    def _has_permission(self, user_roles: List[str], action: str) -> bool:
        """Check if any user role grants the action."""
        for role in user_roles:
            permissions = self._role_map.get(role, set())
            if "*" in permissions or action in permissions:
                return True
        return False

    def _log_decision(
        self, allowed: bool, action: str, resource: str, roles: List[str]
    ):
        """Log authorization decision."""
        level = logging.DEBUG if allowed else logging.WARNING
        logger.log(
            level,
            "Authz Decision: %s | Action: %s | Resource: %s | Roles: %s",
            "ALLOWED" if allowed else "DENIED",
            action,
            resource,
            roles,
        )

    async def check_access(
        self,
        access_token: Optional[str],
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> list[str]:
        roles = self._get_user_roles(access_token, auth_context, role_names)
        allowed = self._has_permission(roles, action)

        self._log_decision(allowed, action, resource_type, roles)

        if allowed:
            if resource_ids is None:
                return ["*"]
            return resource_ids

        return []

    async def check_access_batch(
        self,
        access_token: Optional[str],
        resources: list[dict[str, Any]],
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> CheckAccessBatchResult:
        result = CheckAccessBatchResult()
        roles = self._get_user_roles(access_token, auth_context, role_names)

        # Calculate global permissions once
        all_actions = set()
        for role in roles:
            all_actions.update(self._role_map.get(role, set()))
        result.global_permissions = all_actions

        for res_entry in resources:
            rtype = res_entry.get("resource_type_name")
            action = res_entry.get("action_name")
            r_ids = res_entry.get("external_resource_ids") or []

            if self._has_permission(roles, action):
                for rid in r_ids:
                    key = (rtype, rid)
                    if key not in result.access_map:
                        result.access_map[key] = set()
                    result.access_map[key].add(action)

        return result

    async def get_permitted_actions(
        self,
        access_token: Optional[str],
        resource_type: str,
        resource_ids: Optional[list[str]] = None,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> dict[str, list[str]]:
        roles = self._get_user_roles(access_token, auth_context, role_names)
        all_actions = set()
        for role in roles:
            all_actions.update(self._role_map.get(role, set()))
        action_list = list(all_actions)

        if resource_ids:
            return {rid: action_list for rid in resource_ids}
        return {resource_type: action_list}

    async def get_permitted_actions_batch(
        self,
        access_token: Optional[str],
        resources: list[dict[str, Any]],
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> dict[str, dict[str, list[str]]]:
        roles = self._get_user_roles(access_token, auth_context, role_names)
        all_actions = set()
        for role in roles:
            all_actions.update(self._role_map.get(role, set()))
        action_list = list(all_actions)

        result = {}
        for res_entry in resources:
            rtype = res_entry.get("resource_type_name")
            if rtype not in result:
                result[rtype] = {}
            r_ids = res_entry.get("external_resource_ids") or []
            for rid in r_ids:
                result[rtype][rid] = action_list
        return result

    async def list_resource_types(self) -> list[str]:
        return ["*"]

    async def list_actions(self, resource_type: str) -> list[str]:
        all_actions = set()
        for actions in self._role_map.values():
            all_actions.update(actions)
        return list(all_actions)

    async def get_type_level_permissions(
        self,
        access_token: Optional[str],
        resource_types: list[str],
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> dict[str, list[str]]:
        roles = self._get_user_roles(access_token, auth_context, role_names)
        all_actions = set()
        for role in roles:
            all_actions.update(self._role_map.get(role, set()))
        return {rtype: list(all_actions) for rtype in resource_types}

    async def get_authorization_conditions(
        self,
        access_token: Optional[str],
        resource_type: str,
        action: str,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> AuthorizationConditionsResult:
        roles = self._get_user_roles(access_token, auth_context, role_names)
        if self._has_permission(roles, action):
            return AuthorizationConditionsResult(filter_type="granted_all")
        return AuthorizationConditionsResult(filter_type="denied_all")

    async def get_authorization_filter(
        self,
        access_token: Optional[str],
        resource_type: str,
        action: str,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
        field_mapping: Optional[Any] = None,
    ) -> AuthorizationFilter:
        """Return concrete AuthorizationFilter."""
        roles = self._get_user_roles(access_token, auth_context, role_names)
        if self._has_permission(roles, action):
            return AuthorizationFilter.grant_all()
        return AuthorizationFilter.deny_all()

    async def sync_from_idp(self) -> dict[str, Any]:
        return {"status": "no_op"}


# ----------------------------------------------------------------------
# OWNERSHIP AWARE RBAC ADAPTER
# ----------------------------------------------------------------------


class OwnershipAwareRBACAdapter(SimpleRBACAdapter):
    """
    Extends SimpleRBACAdapter with ownership checks.

    If role-based check fails, it consults the OwnershipStrategy.
    """

    def __init__(
        self,
        role_permissions: Dict[str, List[str]],
        ownership_strategy: OwnershipStrategy,
        role_extractor: Optional[RoleExtractor] = None,
        ownership_actions: Optional[Set[str]] = None,
    ):
        super().__init__(role_permissions, role_extractor)
        self.ownership = ownership_strategy
        # Actions that are candidates for ownership check (e.g., "read", "update")
        # Defaults to allowing all actions if owner
        self.ownership_actions = ownership_actions

    def _is_ownership_candidate(self, action: str) -> bool:
        if not self.ownership_actions:
            return True
        return action in self.ownership_actions

    async def check_access(
        self,
        access_token: Optional[str],
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None,
        auth_context: Optional[dict[str, Any]] = None,
        role_names: Optional[list[str]] = None,
    ) -> list[str]:
        # 1. Broad Role Check (Admin, Editor)
        if await super().check_access(
            access_token, action, resource_type, None, auth_context, role_names
        ):
            return resource_ids or ["*"]

        # 2. Ownership Check
        if not self._is_ownership_candidate(action):
            return []

        if not resource_ids:
            # Type-level check with ownership is ambiguous without IDs...
            # usually implies "can I own things of this type?"
            # For safety, we return empty here unless we have specific ownership logic for types.
            return []

        user_id = (auth_context or {}).get("sub") or (auth_context or {}).get("user_id")
        if not user_id:
            # Can't check ownership without user ID
            return []

        allowed_ids = []
        for rid in resource_ids:
            if await self.ownership.is_owner(user_id, resource_type, rid):
                allowed_ids.append(rid)

        self._log_decision(bool(allowed_ids), action, resource_type, role_names or [])
        return allowed_ids
