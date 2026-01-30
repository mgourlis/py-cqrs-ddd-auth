"""
Token handling utilities.

Framework-agnostic token extraction and delivery logic.
Used by framework adapters (FastAPI, Django) to handle
header vs cookie token delivery transparently.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class TokenSource(Enum):
    """
    Where tokens were extracted from—determines response format.
    
    Auto-detection allows responding via the same channel:
    - HEADER: Authorization header → respond with headers
    - COOKIE: httpOnly cookie → respond with cookies
    """
    HEADER = "header"
    COOKIE = "cookie"


@dataclass
class TokenExtractionResult:
    """
    Result of extracting tokens from an HTTP request.
    
    Tracks both the tokens and their source, enabling
    the response to use the same delivery mechanism.
    """
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    source: Optional[TokenSource] = None
    
    @property
    def is_present(self) -> bool:
        """Check if any token was found."""
        return self.access_token is not None
    
    @property
    def has_refresh(self) -> bool:
        """Check if refresh token is available."""
        return self.refresh_token is not None


@dataclass
class TokenRefreshResult:
    """
    Result of a token refresh check.
    
    Used by TokenRefreshAdapter to indicate what action is needed.
    """
    needs_auth: bool = False              # User must re-authenticate (both tokens invalid)
    current_token: Optional[str] = None   # No refresh needed, use existing token
    new_access_token: Optional[str] = None
    new_refresh_token: Optional[str] = None
    
    @property
    def was_refreshed(self) -> bool:
        """Check if tokens were refreshed."""
        return self.new_access_token is not None


class TokenRefreshAdapter:
    """
    Framework-agnostic token refresh logic.
    
    Encapsulates the decision of whether to:
    - Use the current token (still valid)
    - Refresh the token (expired but refresh token valid)
    - Require re-authentication (both tokens invalid)
    
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
            if hasattr(claims, 'exp'):
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
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from cqrs_ddd_auth.ports.identity_provider import IdentityProviderPort
