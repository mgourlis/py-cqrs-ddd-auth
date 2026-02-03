"""
OTP Service Adapters.

Concrete implementations of OTPServicePort for TOTP, Email, and SMS methods.
Uses pyotp for code generation and validation.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
import pyotp

from cqrs_ddd_auth.domain.value_objects import UserClaims, TOTPSecret
from cqrs_ddd_auth.domain.errors import OTPError, InvalidOTPError
from cqrs_ddd_auth.infrastructure.ports.otp import (
    OTPServicePort,
    TOTPSecretRepository,
    OTPChallengeRepository,
)
from cqrs_ddd_auth.infrastructure.ports.communication import (
    EmailSenderPort,
    SMSSenderPort,
)


class TOTPService(OTPServicePort):
    """
    TOTP implementation using pyotp for authenticator app-based 2FA.

    Supports Google Authenticator, Authy, Microsoft Authenticator, etc.
    """

    def __init__(
        self,
        secret_repository: TOTPSecretRepository,
        issuer_name: str = "MyApp",
        valid_window: int = 1,
    ):
        self.secrets = secret_repository
        self.issuer_name = issuer_name
        self.valid_window = valid_window

    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """Check if user has TOTP enabled."""
        if not self.secrets:
            return False
        secret = await self.secrets.get_by_user_id(claims.sub)
        return secret is not None

    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """TOTP only supports 'totp' method."""
        if not self.secrets:
            return []
        secret = await self.secrets.get_by_user_id(claims.sub)
        return ["totp"] if secret else []

    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """
        TOTP doesn't require sending a challenge.
        The code is generated on the user's device.
        """
        return "Enter the code from your authenticator app"

    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate a TOTP code from the user's authenticator app."""
        if not self.secrets:
            return False

        secret = await self.secrets.get_by_user_id(claims.sub)
        if not secret:
            return False

        totp = pyotp.TOTP(secret.secret)
        if totp.verify(code, valid_window=self.valid_window):
            return True

        raise InvalidOTPError("Invalid TOTP code")

    async def setup_totp(self, claims: UserClaims) -> tuple[TOTPSecret, str]:
        """
        Generate a new TOTP secret for a user.

        Returns:
            Tuple of (TOTPSecret, provisioning_uri for QR code)
        """
        secret = TOTPSecret.generate()
        totp = pyotp.TOTP(secret.secret)
        uri = totp.provisioning_uri(name=claims.email, issuer_name=self.issuer_name)

        return secret, uri

    async def confirm_setup(self, user_id: str, secret: TOTPSecret, code: str) -> bool:
        """
        Confirm TOTP setup by validating the first code.
        """
        totp = pyotp.TOTP(secret.secret)
        if totp.verify(code, valid_window=self.valid_window):
            await self.secrets.save(user_id, secret)
            return True
        return False


class EmailOTPService(OTPServicePort):
    """
    Email-based OTP implementation using pyotp.

    Generates a TOTP code and sends it via email.
    """

    def __init__(
        self,
        otp_repository: OTPChallengeRepository,
        email_sender: EmailSenderPort,
        token_length: int = 6,
        expiration_seconds: int = 120,
        app_name: str = "MyApp",
    ):
        self.otp_repo = otp_repository
        self.email_sender = email_sender
        self.token_length = token_length
        self.expiration_seconds = expiration_seconds
        self.app_name = app_name

    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """Email OTP is available if user has a verified email."""
        return bool(claims.email)

    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """Return email method if user has email."""
        return ["email"] if claims.email else []

    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """Generate and send OTP code via email."""
        if not self.otp_repo or not self.email_sender:
            raise OTPError("Email OTP not configured")

        # Generate secret and code
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(
            secret, digits=self.token_length, interval=self.expiration_seconds
        )
        code = totp.now()

        # Store challenge
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self.expiration_seconds
        )
        await self.otp_repo.save_challenge(
            user_id=claims.sub, method="email", secret=secret, expires_at=expires_at
        )

        # Send email
        await self.email_sender.send(
            to=claims.email,
            subject=f"{self.app_name} - Your Verification Code",
            body=f"Your verification code is: {code}\n\nThis code expires in {self.expiration_seconds // 60} minutes.",
        )

        return f"Code sent to {self._obfuscate_email(claims.email)}"

    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate the emailed OTP code."""
        if not self.otp_repo:
            return False

        challenge = await self.otp_repo.get_challenge(claims.sub, "email")
        if not challenge:
            raise InvalidOTPError("No pending challenge found")

        # Check expiration
        if datetime.now(timezone.utc) > challenge.expires_at:
            raise InvalidOTPError("Code expired")

        # Validate with pyotp
        totp = pyotp.TOTP(
            challenge.secret, digits=len(code), interval=self.expiration_seconds
        )

        if totp.verify(code, valid_window=1):
            await self.otp_repo.mark_used(claims.sub, "email")
            return True

        await self.otp_repo.increment_attempts(claims.sub, "email")
        raise InvalidOTPError("Invalid code")

    def _obfuscate_email(self, email: str) -> str:
        """Obfuscate email for display: j****@example.com"""
        local, domain = email.split("@")
        obfuscated = local[0] + "****" if len(local) > 1 else local + "****"
        return f"{obfuscated}@{domain}"


class SMSOTPService(OTPServicePort):
    """
    SMS-based OTP implementation using pyotp.

    Generates a TOTP code and sends it via SMS.
    """

    def __init__(
        self,
        otp_repository: OTPChallengeRepository,
        sms_sender: SMSSenderPort,
        token_length: int = 6,
        expiration_seconds: int = 120,
        app_name: str = "MyApp",
    ):
        self.otp_repo = otp_repository
        self.sms_sender = sms_sender
        self.token_length = token_length
        self.expiration_seconds = expiration_seconds
        self.app_name = app_name

    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """SMS OTP is available if user has a phone number."""
        phone = claims.attributes.get("phone_number")
        return bool(phone)

    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """Return sms method if user has phone."""
        phone = claims.attributes.get("phone_number")
        return ["sms"] if phone else []

    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """Generate and send OTP code via SMS."""
        if not self.otp_repo or not self.sms_sender:
            raise OTPError("SMS OTP not configured")

        phone = claims.attributes.get("phone_number")
        if not phone:
            raise OTPError("User has no phone number")

        # Generate secret and code
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(
            secret, digits=self.token_length, interval=self.expiration_seconds
        )
        code = totp.now()

        # Store challenge
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self.expiration_seconds
        )
        await self.otp_repo.save_challenge(
            user_id=claims.sub, method="sms", secret=secret, expires_at=expires_at
        )

        # Send SMS
        await self.sms_sender.send(
            to=phone, message=f"{self.app_name}: Your verification code is {code}"
        )

        return f"Code sent to {self._obfuscate_phone(phone)}"

    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate the SMS OTP code."""
        if not self.otp_repo:
            return False

        challenge = await self.otp_repo.get_challenge(claims.sub, "sms")
        if not challenge:
            raise InvalidOTPError("No pending challenge found")

        # Check expiration
        if datetime.now(timezone.utc) > challenge.expires_at:
            raise InvalidOTPError("Code expired")

        # Validate with pyotp
        totp = pyotp.TOTP(
            challenge.secret, digits=len(code), interval=self.expiration_seconds
        )

        if totp.verify(code, valid_window=1):
            await self.otp_repo.mark_used(claims.sub, "sms")
            return True

        await self.otp_repo.increment_attempts(claims.sub, "sms")
        raise InvalidOTPError("Invalid code")

    def _obfuscate_phone(self, phone: str) -> str:
        """Obfuscate phone for display: +1***-**56"""
        if len(phone) < 4:
            return "****"
        return phone[:2] + "***-**" + phone[-2:]


class CompositeOTPService(OTPServicePort):
    """
    Composite OTP service that delegates to the appropriate method.

    Combines TOTP, Email, and SMS services into a single interface.
    """

    def __init__(
        self,
        totp_service: Optional[TOTPService] = None,
        email_service: Optional[EmailOTPService] = None,
        sms_service: Optional[SMSOTPService] = None,
    ):
        self.services = {
            "totp": totp_service,
            "email": email_service,
            "sms": sms_service,
        }

    def _get_service(self, method: str):
        service = self.services.get(method)
        if not service:
            raise OTPError(f"OTP method '{method}' not configured")
        return service

    async def is_required_for_user(self, claims: UserClaims) -> bool:
        """Check if any OTP method is required for the user."""
        for service in self.services.values():
            if service and await service.is_required_for_user(claims):
                return True
        return False

    async def get_available_methods(self, claims: UserClaims) -> list[str]:
        """Get all OTP methods available for the user."""
        methods = []
        for service in self.services.values():
            if service:
                methods.extend(await service.get_available_methods(claims))
        return methods

    async def send_challenge(self, claims: UserClaims, method: str) -> str:
        """Send OTP challenge via the specified method."""
        service = self._get_service(method)
        return await service.send_challenge(claims, method)

    async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
        """Validate OTP code for the specified method."""
        service = self._get_service(method)
        return await service.validate(claims, method, code)
