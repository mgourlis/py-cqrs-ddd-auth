"""
Bulker.gr SMS Adapter for Django.

Integrates with Django settings and uses asgiref for async support.
"""

import logging
import time
from typing import Optional

import httpx

try:
    from django.conf import settings
    from asgiref.sync import sync_to_async
except ImportError:
    settings = None
    sync_to_async = None

from cqrs_ddd_auth.infrastructure.ports.communication import (
    SMSSenderPort,
    SMSMessage,
)

logger = logging.getLogger("cqrs_ddd_auth.contrib.django.sms")


class BulkerSMSSender(SMSSenderPort):
    """
    Django implementation of SMSSenderPort using Bulker.gr.
    """

    def __init__(
        self,
        auth_key: Optional[str] = None,
        sms_url: Optional[str] = None,
        default_from_sms: Optional[str] = None,
        validity: Optional[int] = None,
    ):
        # Pull from settings if not provided
        self.auth_key = auth_key or (
            getattr(settings, "BULKER_AUTH_KEY", None) if settings else None
        )
        self.sms_url = sms_url or (
            getattr(settings, "BULKER_SMS_URL", "https://www.bulker.gr/api/v1/sms/send")
            if settings
            else "https://www.bulker.gr/api/v1/sms/send"
        )
        self.default_from_sms = default_from_sms or (
            getattr(settings, "BULKER_DEFAULT_FROM_SMS", None) if settings else None
        )
        self.validity = validity or (
            getattr(settings, "BULKER_SMS_VALIDITY", 1) if settings else 1
        )

        if not self.auth_key:
            logger.warning("Bulker auth_key not configured. SMS will fail.")

    async def send(self, message: SMSMessage) -> None:
        """
        Send an SMS via Bulker.gr.
        """
        if not self.auth_key:
            raise ValueError("Bulker AUTH_KEY is not configured.")

        originator = message.from_number or self.default_from_sms
        if not originator:
            raise ValueError("Sender number (from_number) is required.")

        # Recipient numbers without leading '+'
        recipient = message.to.lstrip("+")

        # Use sync-to-async bridge for Django context if needed,
        # but Bulker uses HTTP which is naturally async with httpx.
        # However, to maintain consistency with other Django adapters, we can wrap it.
        await self._send_async(recipient, originator, message.body, message.to)

    async def _send_async(
        self, recipient: str, originator: str, body: str, raw_to: str
    ) -> None:
        async with httpx.AsyncClient() as client:
            data = {
                "auth_key": self.auth_key,
                "id": int(time.time_ns() / 1_000_000),
                "from": originator,
                "to": recipient,
                "text": body,
                "validity": self.validity,
            }

            try:
                response = await client.post(self.sms_url, data=data)

                if response.status_code == 200:
                    content = response.text
                    ack, *rest = content.split(";")
                    if ack == "OK":
                        logger.info(f"SMS sent successfully to {raw_to}")
                    else:
                        error_msg = f"Bulker API returned error: {content}"
                        logger.error(error_msg)
                        raise Exception(error_msg)
                else:
                    response.raise_for_status()

            except Exception as e:
                logger.error(f"Failed to send SMS to {raw_to}: {str(e)}")
                raise
