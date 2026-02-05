"""
Bulker.gr SMS Adapter for FastAPI.

Uses httpx for asynchronous communication with Bulker.gr API.
"""

import logging
import time
from typing import Optional

import httpx

from cqrs_ddd_auth.infrastructure.ports.communication import (
    SMSSenderPort,
    SMSMessage,
)

logger = logging.getLogger("cqrs_ddd_auth.contrib.fastapi.sms")


class BulkerSMSSender(SMSSenderPort):
    """
    FastAPI/Async implementation of SMSSenderPort using Bulker.gr.
    """

    def __init__(
        self,
        auth_key: str,
        sms_url: str = "https://www.bulker.gr/api/v1/sms/send",
        default_from_sms: Optional[str] = None,
        validity: int = 1,
    ):
        self.auth_key = auth_key
        self.sms_url = sms_url
        self.default_from_sms = default_from_sms
        self.validity = validity

    async def send(self, message: SMSMessage) -> None:
        """
        Send an SMS via Bulker.gr.
        """
        originator = message.from_number or self.default_from_sms
        if not originator:
            raise ValueError("Sender number (from_number) is required.")

        async with httpx.AsyncClient() as client:
            # Bulker expects recipient numbers without leading '+'
            recipient = message.to.lstrip("+")

            data = {
                "auth_key": self.auth_key,
                "id": int(time.time_ns() / 1_000_000),
                "from": originator,
                "to": recipient,
                "text": message.body,
                "validity": self.validity,
            }

            try:
                response = await client.post(self.sms_url, data=data)

                if response.status_code == 200:
                    # Bulker returns "OK;MSG_ID;CHARGE" or "ERROR;CODE;DESCRIPTION"
                    content = response.text
                    ack, *rest = content.split(";")
                    if ack == "OK":
                        logger.info(f"SMS sent successfully to {message.to}")
                    else:
                        error_msg = f"Bulker API returned error: {content}"
                        logger.error(error_msg)
                        raise Exception(error_msg)
                else:
                    response.raise_for_status()

            except Exception as e:
                logger.error(f"Failed to send SMS to {message.to}: {str(e)}")
                raise
