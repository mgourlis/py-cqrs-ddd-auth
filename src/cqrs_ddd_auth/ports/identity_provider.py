"""
Identity Provider Port.

Defines the interface for authentication with external Identity Providers
(Keycloak, Auth0, Cognito, etc.).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, Optional

from cqrs_ddd_auth.domain.value_objects import UserClaims


@dataclass
class TokenResponse:
    """Response from IdP authentication."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600  # seconds
    refresh_expires_in: int = 86400  # seconds
    scope: str = ""
    id_token: Optional[str] = None


class IdentityProviderPort(Protocol):
    """
    Port for delegating authentication to an Identity Provider.
    
    Implementations handle the specifics of communicating with
    Keycloak, Auth0, Cognito, or other IdPs.
    """
    
    async def authenticate(
        self, 
        username: str, 
        password: str
    ) -> TokenResponse:
        """
        Authenticate user with credentials.
        
        Args:
            username: User's username or email
            password: User's password
        
        Returns:
            TokenResponse with access/refresh tokens
        
        Raises:
            AuthenticationError: If credentials are invalid
        """
        ...
    
    async def refresh(self, refresh_token: str) -> TokenResponse:
        """
        Refresh tokens using a refresh token.
        
        Args:
            refresh_token: Valid refresh token
        
        Returns:
            New TokenResponse with fresh tokens
        
        Raises:
            AuthenticationError: If refresh token is invalid/expired
        """
        ...
    
    async def decode_token(self, access_token: str) -> UserClaims:
        """
        Decode and validate a JWT access token.
        
        Args:
            access_token: JWT access token
        
        Returns:
            UserClaims extracted from the token
        
        Raises:
            InvalidTokenError: If token is invalid or expired
        """
        ...
    
    async def logout(self, refresh_token: str) -> None:
        """
        Terminate the IdP session.
        
        Args:
            refresh_token: Refresh token to invalidate
        """
        ...
    
    async def get_user_info(self, access_token: str) -> dict:
        """
        Get user info from the IdP's userinfo endpoint.
        
        Args:
            access_token: Valid access token
        
        Returns:
            User profile information
        """
        ...
