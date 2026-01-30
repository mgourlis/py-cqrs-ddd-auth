"""
Keycloak Identity Provider Adapter.

Implements IdentityProviderPort for Keycloak authentication.
Uses python-keycloak and python-jose for robust JWT handling.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from keycloak import KeycloakOpenID
from jose import jwt, JWTError

from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort, TokenResponse
from cqrs_ddd_auth.domain.value_objects import UserClaims


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    def __init__(self, message: str, error_code: str = "AUTHENTICATION_FAILED"):
        super().__init__(message)
        self.error_code = error_code


class InvalidTokenError(Exception):
    """Raised when token validation fails."""
    def __init__(self, message: str, error_code: str = "INVALID_TOKEN"):
        super().__init__(message)
        self.error_code = error_code


@dataclass
class KeycloakConfig:
    """Configuration for Keycloak adapter."""
    server_url: str  # e.g., "https://keycloak.example.com"
    realm: str
    client_id: str
    client_secret: Optional[str] = None
    
    # Claim mapping - customize for your Keycloak setup
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    groups_claim: str = "groups"  # or "realm_access.roles"
    
    # Token validation
    verify: bool = True


class KeycloakAdapter:
    """
    Keycloak implementation of IdentityProviderPort.
    
    Uses python-keycloak for OpenID Connect operations and
    python-jose for JWT validation.
    
    Example usage:
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="my-realm",
            client_id="my-app",
            client_secret="secret",
        )
        adapter = KeycloakAdapter(config)
        
        # Authenticate
        tokens = await adapter.authenticate("user", "password")
        
        # Decode token to get claims
        claims = await adapter.decode_token(tokens.access_token)
    """
    
    def __init__(self, config: KeycloakConfig):
        self.config = config
        self._keycloak = KeycloakOpenID(
            server_url=config.server_url,
            realm_name=config.realm,
            client_id=config.client_id,
            client_secret_key=config.client_secret,
            verify=config.verify,
        )
        self._public_key: Optional[str] = None
    
    async def authenticate(self, username: str, password: str) -> TokenResponse:
        """
        Authenticate user with username/password via direct grant.
        
        Args:
            username: User's username or email
            password: User's password
        
        Returns:
            TokenResponse with access/refresh tokens
        
        Raises:
            AuthenticationError: If credentials are invalid
        """
        try:
            token_data = self._keycloak.token(username, password)
            
            return TokenResponse(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token", ""),
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 3600),
                refresh_expires_in=token_data.get("refresh_expires_in", 86400),
                scope=token_data.get("scope", ""),
                id_token=token_data.get("id_token"),
            )
        except Exception as e:
            raise AuthenticationError(str(e), "AUTHENTICATION_FAILED")
    
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
        try:
            token_data = self._keycloak.refresh_token(refresh_token)
            
            return TokenResponse(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token", ""),
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 3600),
                refresh_expires_in=token_data.get("refresh_expires_in", 86400),
                scope=token_data.get("scope", ""),
                id_token=token_data.get("id_token"),
            )
        except Exception as e:
            raise AuthenticationError(str(e), "REFRESH_FAILED")
    
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
        try:
            # Use Keycloak's introspect or decode with public key
            public_key = self._get_public_key()
            
            options = {
                "verify_signature": True,
                "verify_aud": True,
                "verify_exp": True,
            }
            
            payload = jwt.decode(
                access_token,
                public_key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                options=options,
            )
            
            return self._payload_to_claims(payload)
            
        except JWTError as e:
            raise InvalidTokenError(str(e), "INVALID_TOKEN")
        except Exception as e:
            raise InvalidTokenError(str(e), "TOKEN_DECODE_ERROR")
    
    async def logout(self, refresh_token: str) -> None:
        """
        Terminate the IdP session by revoking the refresh token.
        
        Args:
            refresh_token: Refresh token to invalidate
        """
        try:
            self._keycloak.logout(refresh_token)
        except Exception:
            # Logout is best-effort
            pass
    
    async def get_user_info(self, access_token: str) -> dict:
        """
        Get user info from Keycloak's userinfo endpoint.
        
        Args:
            access_token: Valid access token
        
        Returns:
            User profile information
        """
        try:
            return self._keycloak.userinfo(access_token)
        except Exception as e:
            raise InvalidTokenError(str(e), "USERINFO_FAILED")
    
    def _get_public_key(self) -> str:
        """Get Keycloak's public key for JWT verification."""
        if self._public_key is None:
            self._public_key = (
                "-----BEGIN PUBLIC KEY-----\n"
                + self._keycloak.public_key()
                + "\n-----END PUBLIC KEY-----"
            )
        return self._public_key
    
    def _payload_to_claims(self, payload: Dict[str, Any]) -> UserClaims:
        """
        Convert JWT payload to normalized UserClaims.
        
        This handles Keycloak-specific claim names and structures.
        """
        groups = self._extract_groups(payload)
        username = payload.get(self.config.username_claim, "")
        email = payload.get(self.config.email_claim, "")
        
        # Collect additional attributes
        attributes = {}
        for key in ["tenant_id", "org_id", "department"]:
            if key in payload:
                attributes[key] = payload[key]
        
        return UserClaims(
            sub=payload.get("sub", ""),
            username=username,
            email=email,
            groups=tuple(groups),
            attributes=attributes,
        )
    
    def _extract_groups(self, payload: Dict[str, Any]) -> list[str]:
        """
        Extract groups/roles from Keycloak payload.
        
        Keycloak can put roles in multiple places:
        - realm_access.roles (realm roles)
        - resource_access.{client}.roles (client roles)
        - groups (explicit group membership)
        """
        groups = []
        
        # Check configured groups claim first
        if self.config.groups_claim == "groups":
            groups.extend(payload.get("groups", []))
        elif self.config.groups_claim == "realm_access.roles":
            realm_access = payload.get("realm_access", {})
            groups.extend(realm_access.get("roles", []))
        
        # Also include realm roles if not already using them
        if self.config.groups_claim != "realm_access.roles":
            realm_access = payload.get("realm_access", {})
            groups.extend(realm_access.get("roles", []))
        
        # Include client-specific roles
        resource_access = payload.get("resource_access", {})
        client_roles = resource_access.get(self.config.client_id, {})
        groups.extend(client_roles.get("roles", []))
        
        # Deduplicate while preserving order
        seen = set()
        unique_groups = []
        for g in groups:
            if g not in seen:
                seen.add(g)
                unique_groups.append(g)
        
        return unique_groups
    
    def clear_key_cache(self) -> None:
        """Clear cached public key. Call this if keys are rotated."""
        self._public_key = None
