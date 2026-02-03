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
