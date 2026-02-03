import json
import logging
from typing import Dict, Any, Tuple
from cqrs_ddd_auth.application.results import TokenPair

logger = logging.getLogger(__name__)


class PreAuthTokenService:
    """
    Service for encrypting and decrypting pre-authentication context.

    Used in stateless multi-step authentication (e.g., MFA) to avoid
    storing session state on the server or calling the IdP multiple times.

    The context is encrypted into a JWE (JSON Web Encryption) token
    sent to the client, which must be returned in subsequent requests.
    """

    def __init__(self, secret_key: str):
        """
        Initialize with a secret key.

        Args:
            secret_key: Secret key for encryption.
                If using AES-GCM (default), should be 32 bytes for A256GCM.
        """
        self.secret_key = secret_key

    def encrypt(self, user_claims: Dict[str, Any], tokens: TokenPair) -> str:
        """
        Encrypt user claims and tokens into a JWE.

        Args:
            user_claims: Decoded user claims (dict)
            tokens: Original TokenPair from IdP

        Returns:
            str: Encrypted JWE token
        """
        from jose import jwe

        payload = {
            "claims": user_claims,
            "tokens": {
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "token_type": tokens.token_type,
                "expires_in": tokens.expires_in,
                "refresh_expires_in": tokens.refresh_expires_in,
                "scope": tokens.scope,
            },
        }

        # Use AES-256-GCM for authenticated encryption
        # Algorithm 'dir' means we use the secret key directly as the CEK
        encrypted = jwe.encrypt(
            json.dumps(payload).encode("utf-8"),
            self.secret_key,
            algorithm="dir",
            encryption="A256GCM",
        )
        return encrypted.decode("utf-8")

    def decrypt(self, token: str) -> Tuple[Dict[str, Any], TokenPair]:
        """
        Decrypt JWE back into claims and tokens.

        Args:
            token: JWE token from client

        Returns:
            Tuple[dict, TokenPair]: Recovered (claims, tokens)
        """
        from jose import jwe

        try:
            payload_bytes = jwe.decrypt(token, self.secret_key)
            data = json.loads(payload_bytes.decode("utf-8"))

            t_data = data["tokens"]
            tokens = TokenPair(
                access_token=t_data["access_token"],
                refresh_token=t_data["refresh_token"],
                token_type=t_data.get("token_type", "Bearer"),
                expires_in=t_data.get("expires_in", 3600),
                refresh_expires_in=t_data.get("refresh_expires_in", 86400),
                scope=t_data.get("scope", ""),
            )
            return data["claims"], tokens
        except Exception as e:
            logger.error(f"Failed to decrypt pre-auth token: {e}")
            raise ValueError("Invalid or expired pre-auth token")
