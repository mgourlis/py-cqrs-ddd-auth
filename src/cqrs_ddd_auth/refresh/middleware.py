"""
Framework-agnostic middleware logic for token refresh.

This module provides the core logic for inspecting requests, detecting token
sources (header vs cookie), and determining if a refresh is needed.
Framework-specific middleware can then delegate to this logic.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from .adapter import TokenRefreshAdapter, TokenRefreshResult


class TokenSource(str, Enum):
    """Source of the token in the request."""

    HEADER = "header"
    COOKIE = "cookie"


@dataclass
class TokenExtractionResult:
    """Result of extracting tokens from a request."""

    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    source: Optional[TokenSource] = None

    @property
    def has_tokens(self) -> bool:
        return bool(self.access_token or self.refresh_token)


class BaseTokenRefreshMiddleware:
    """
    Base class for Token Refresh Middleware.

    Contains the core logic for:
    1. Extracting tokens from request
    2. Delegating to adapter for refresh decision
    3. Applying new tokens to response
    """

    def __init__(
        self,
        adapter: TokenRefreshAdapter,
        cookie_name_access: str = "access_token",
        cookie_name_refresh: str = "refresh_token",
        header_name: str = "Authorization",
        header_scheme: str = "Bearer",
    ):
        self.adapter = adapter
        self.cookie_name_access = cookie_name_access
        self.cookie_name_refresh = cookie_name_refresh
        self.header_name = header_name
        self.header_scheme = header_scheme

    async def process_refresh_logic(
        self, extraction: TokenExtractionResult
    ) -> TokenRefreshResult:
        """
        Process the core refresh logic.

        Args:
            extraction: The extracted tokens and source

        Returns:
            Result indicating if refresh happened or auth is needed
        """
        if not extraction.has_tokens:
            return TokenRefreshResult()

        return await self.adapter.process_request(
            access_token=extraction.access_token, refresh_token=extraction.refresh_token
        )

    def extract_from_headers(
        self, headers: dict
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract tokens from headers."""
        # Typically only access token is in header
        auth_header = headers.get(self.header_name)
        if auth_header and auth_header.startswith(f"{self.header_scheme} "):
            return auth_header[len(self.header_scheme) + 1 :], None
        # Some clients might send refresh token in a custom header, but standard is usually body/cookie
        return None, None

    def extract_from_cookies(
        self, cookies: dict
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract tokens from cookies."""
        return (
            cookies.get(self.cookie_name_access),
            cookies.get(self.cookie_name_refresh),
        )
