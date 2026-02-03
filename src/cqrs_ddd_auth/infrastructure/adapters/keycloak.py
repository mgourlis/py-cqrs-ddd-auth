"""
Keycloak Identity Provider Adapter.

Implements IdentityProviderPort for Keycloak authentication.
Uses python-keycloak and python-jose for robust JWT handling.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any, List

from keycloak import KeycloakOpenID
from jose import jwt, JWTError

from cqrs_ddd_auth.infrastructure.ports.identity_provider import (
    IdentityProviderPort,
    TokenResponse,
)
from cqrs_ddd_auth.domain.value_objects import (
    UserClaims,
    AuthRole,
    RoleSource,
)
from cqrs_ddd_auth.domain.errors import AuthenticationError, InvalidTokenError


# ═══════════════════════════════════════════════════════════════
# KEYCLOAK-SPECIFIC ENUMS
# ═══════════════════════════════════════════════════════════════


class GroupPathStrategy(Enum):
    """
    How to convert Keycloak group paths to role names.

    Example group path: /web/admin/editor

    Strategies:
    - FULL_PATH:    → "web/admin/editor" (default, preserves hierarchy)
    - LAST_SEGMENT: → "editor" (simple, loses context)
    - ALL_SEGMENTS: → ["web", "admin", "editor"] (flexible, adds multiple roles)
    """

    FULL_PATH = "full_path"
    LAST_SEGMENT = "last_segment"
    ALL_SEGMENTS = "all_segments"


# ═══════════════════════════════════════════════════════════════


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

    # ═══════ GROUP HANDLING (Role Unification) ═══════
    merge_groups_as_roles: bool = True  # Groups become authorization roles
    group_path_strategy: GroupPathStrategy = (
        GroupPathStrategy.FULL_PATH
    )  # Default: preserve hierarchy
    group_prefix: str = ""  # Optional prefix for group-derived roles


class KeycloakAdapter(IdentityProviderPort):
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

        This handles Keycloak-specific claim names, structures, and
        role unification (groups as roles).
        """
        roles: List[AuthRole] = []

        # 1. Realm roles from realm_access
        realm_access = payload.get("realm_access", {})
        for role_name in realm_access.get("roles", []):
            roles.append(AuthRole(name=role_name, source=RoleSource.IDP_ROLE))

        # 2. Client roles from resource_access
        resource_access = payload.get("resource_access", {})
        for client, client_data in resource_access.items():
            for role_name in client_data.get("roles", []):
                # Include client prefix in name if not our client
                if client == self.config.client_id:
                    prefixed_name = role_name
                else:
                    prefixed_name = f"{client}:{role_name}"
                roles.append(
                    AuthRole(
                        name=prefixed_name,
                        source=RoleSource.IDP_CLIENT_ROLE,
                        attributes={"client": client},
                    )
                )

        # 3. Groups - both as raw groups and optionally as roles
        raw_groups = tuple(payload.get("groups", []))

        if self.config.merge_groups_as_roles:
            for group_path in raw_groups:
                group_roles = self._group_path_to_roles(
                    group_path,
                    strategy=self.config.group_path_strategy,
                    prefix=self.config.group_prefix,
                )
                roles.extend(group_roles)

        return UserClaims(
            sub=payload.get("sub", ""),
            username=payload.get("preferred_username", payload.get("sub", "")),
            email=payload.get("email", ""),
            groups=raw_groups,
            roles=tuple(roles),
            attributes=payload,
        )

    def _group_path_to_roles(
        self, group_path: str, strategy: GroupPathStrategy, prefix: str = ""
    ) -> List[AuthRole]:
        """
        Convert Keycloak group path to one or more roles.

        Args:
            group_path: Full group path, e.g., "/web/admin/editor"
            strategy: How to handle the path
            prefix: Optional prefix for role names

        Returns:
            List of AuthRole objects (usually 1, but may be multiple for ALL_SEGMENTS)
        """
        path = group_path.strip("/")
        segments = path.split("/") if path else []

        if not segments:
            return []

        roles: List[AuthRole] = []

        if strategy == GroupPathStrategy.FULL_PATH:
            # /web/admin/editor → "web/admin/editor"
            name = f"{prefix}{path}" if prefix else path
            roles.append(AuthRole(name=name, source=RoleSource.DERIVED))

        elif strategy == GroupPathStrategy.LAST_SEGMENT:
            # /web/admin/editor → "editor"
            name = f"{prefix}{segments[-1]}" if prefix else segments[-1]
            roles.append(AuthRole(name=name, source=RoleSource.DERIVED))

        elif strategy == GroupPathStrategy.ALL_SEGMENTS:
            # /web/admin/editor → ["web", "admin", "editor"]
            for segment in segments:
                name = f"{prefix}{segment}" if prefix else segment
                roles.append(AuthRole(name=name, source=RoleSource.DERIVED))

        return roles

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

    def requires_otp(self, claims: UserClaims) -> bool:
        """
        Check if Keycloak requires OTP based on token claims.

        Note: In Keycloak, this can be detected if the 'acr' claim
        is not at the level required by the policy, or if specific
        MFA flags are present in the access token.
        """
        # For now, simple check - if 'otp_required' flag is in attributes
        return claims.attributes.get("otp_required") is True
