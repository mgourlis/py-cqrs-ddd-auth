"""
Authorization Port.

Defines the interface for ABAC (Attribute-Based Access Control) authorization.
"""

from typing import Protocol


class ABACAuthorizationPort(Protocol):
    """
    Port for ABAC authorization checks.
    
    Integrates with the Stateful ABAC Policy Engine or
    similar authorization services.
    """
    
    async def check_access(
        self,
        access_token: str,
        action: str,
        resource_type: str,
        resource_ids: list[str] | None = None
    ) -> list[str]:
        """
        Check which resources the user can access.
        
        Args:
            access_token: JWT access token
            action: Action to check (read, write, delete, etc.)
            resource_type: Type of resource
            resource_ids: Optional list of specific resource IDs
        
        Returns:
            List of authorized resource IDs (empty if denied)
        """
        ...
    
    async def get_permitted_actions(
        self,
        access_token: str,
        resource_type: str,
        resource_ids: list[str]
    ) -> dict[str, list[str]]:
        """
        Get permitted actions per resource.
        
        Args:
            access_token: JWT access token
            resource_type: Type of resource
            resource_ids: List of resource IDs
        
        Returns:
            Dict mapping resource_id -> list of permitted actions
        """
        ...
    
    async def list_resource_types(self) -> list[str]:
        """List all available resource types."""
        ...
    
    async def list_actions(self, resource_type: str) -> list[str]:
        """List all actions for a resource type."""
        ...
