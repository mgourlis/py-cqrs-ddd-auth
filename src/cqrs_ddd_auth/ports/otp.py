"""
OTP Service Port.

Defines the interface for OTP (One-Time Password) operations
including TOTP, Email, and SMS methods.
"""

from typing import Protocol, Optional
from datetime import datetime

from cqrs_ddd_auth.domain.value_objects import UserClaims, TOTPSecret, OTPChallenge


class OTPServicePort(Protocol):
    """
    Port for OTP operations.
    
    Implementations handle TOTP (authenticator apps), Email OTP, 
    and SMS OTP using pyotp.
    """
    
    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """
        Check if user requires OTP for authentication.
        
        Args:
            claims: User claims from IdP
        
        Returns:
            True if 2FA is required for this user
        """
        ...
    
    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """
        Get OTP methods available for the user.
        
        Args:
            claims: User claims from IdP
        
        Returns:
            List of available methods: ['totp', 'email', 'sms']
        """
        ...
    
    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """
        Send OTP challenge via the specified method.
        
        For TOTP, this is a no-op (user already has the code).
        For email/SMS, this generates and sends the code.
        
        Args:
            claims: User claims from IdP
            method: OTP method ('totp', 'email', 'sms')
        
        Returns:
            Message for UI (e.g., "Code sent to j****@example.com")
        """
        ...
    
    async def validate(
        self, 
        claims: UserClaims, 
        method: str, 
        code: str
    ) -> bool:
        """
        Validate an OTP code.
        
        Args:
            claims: User claims from IdP
            method: OTP method used
            code: The OTP code to validate
        
        Returns:
            True if code is valid
        """
        ...


class TOTPSecretRepository(Protocol):
    """
    Repository for storing user TOTP secrets.
    
    Used for authenticator app-based 2FA where secrets
    persist across sessions.
    """
    
    async def get_by_user_id(self, user_id: str) -> Optional[TOTPSecret]:
        """Get TOTP secret for a user."""
        ...
    
    async def save(self, user_id: str, secret: TOTPSecret) -> None:
        """Save TOTP secret for a user."""
        ...
    
    async def delete(self, user_id: str) -> None:
        """Remove TOTP secret (disable 2FA)."""
        ...


class OTPChallengeRepository(Protocol):
    """
    Repository for storing OTP challenges (email/SMS).
    
    Used for temporary OTP codes that expire after a short time.
    """
    
    async def save_challenge(
        self, 
        user_id: str, 
        method: str, 
        secret: str, 
        expires_at: datetime
    ) -> str:
        """
        Save a new OTP challenge.
        
        Returns:
            Challenge ID
        """
        ...
    
    async def get_challenge(
        self, 
        user_id: str, 
        method: str
    ) -> Optional[OTPChallenge]:
        """Get active OTP challenge for user."""
        ...
    
    async def mark_used(self, user_id: str, method: str) -> None:
        """Mark challenge as used after successful validation."""
        ...
    
    async def increment_attempts(self, user_id: str, method: str) -> None:
        """Increment failed attempts counter."""
        ...
    
    async def delete_expired(self) -> int:
        """Delete expired challenges. Returns count deleted."""
        ...
