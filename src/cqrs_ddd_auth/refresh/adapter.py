"""
Token refresh logic.

Encapsulates the decision of whether to:
- Use the current token (still valid)
- Refresh the token (expired but refresh token valid)
- Require re-authentication (both tokens invalid)
"""

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING


@dataclass
class TokenRefreshResult:
    """
    Result of a token refresh check.

    Used by TokenRefreshAdapter to indicate what action is needed.
    """

    needs_auth: bool = False  # User must re-authenticate (both tokens invalid)
    current_token: Optional[str] = None  # No refresh needed, use existing token
    new_access_token: Optional[str] = None
    new_refresh_token: Optional[str] = None

    @property
    def was_refreshed(self) -> bool:
        """Check if tokens were refreshed."""
        return self.new_access_token is not None


class TokenRefreshAdapter:
    """
    Framework-agnostic token refresh logic.

    Used by framework middleware to transparently refresh tokens.
    """

    def __init__(
        self,
        idp: "IdentityProviderPort",
        access_token_threshold_seconds: int = 60,  # Refresh if expires within N seconds
    ):
        self.idp = idp
        self.threshold = access_token_threshold_seconds

    async def process_request(
        self,
        access_token: Optional[str],
        refresh_token: Optional[str],
    ) -> TokenRefreshResult:
        """
        Process a request and determine if token refresh is needed.

        Args:
            access_token: Current access token (may be expired)
            refresh_token: Refresh token for obtaining new access token

        Returns:
            TokenRefreshResult indicating what action was taken
        """
        if not access_token:
            return TokenRefreshResult(needs_auth=True)

        # Check if access token is still valid
        try:
            claims = await self.idp.decode_token(access_token)

            # Check if token expires soon
            import time

            if hasattr(claims, "exp"):
                time_remaining = claims.exp - time.time()
                if time_remaining > self.threshold:
                    # Token still valid for a while
                    return TokenRefreshResult(current_token=access_token)
            else:
                # No expiry info, assume valid
                return TokenRefreshResult(current_token=access_token)

        except Exception:
            # Token invalid or expired, try to refresh
            pass

        # Attempt refresh
        if not refresh_token:
            return TokenRefreshResult(needs_auth=True)

        try:
            token_response = await self.idp.refresh(refresh_token)
            return TokenRefreshResult(
                new_access_token=token_response.access_token,
                new_refresh_token=token_response.refresh_token,
            )
        except Exception:
            # Refresh failed, require re-auth
            return TokenRefreshResult(needs_auth=True)


# Type hint for circular import
if TYPE_CHECKING:
    from cqrs_ddd_auth.infrastructure.ports.identity_provider import (
        IdentityProviderPort,
    )
