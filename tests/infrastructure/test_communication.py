"""
Tests for Communication Adapters.
"""

import pytest
from unittest.mock import patch

from cqrs_ddd_auth.infrastructure.adapters.communication import (
    ConsoleEmailSender,
    ConsoleSMSSender,
)
from cqrs_ddd_auth.infrastructure.ports.communication import EmailMessage, SMSMessage


@pytest.mark.asyncio
async def test_email_console_send():
    sender = ConsoleEmailSender(output_to_stdout=True)

    msg = EmailMessage(
        to=["user@example.com"],
        subject="Test",
        body_text="Hello",
        body_html="<b>Hello</b>",
        cc=["cc@example.com"],
        bcc=["bcc@example.com"],
    )

    with patch("builtins.print") as mock_print:
        await sender.send(msg)
        assert mock_print.called
        args = mock_print.call_args[0][0]
        assert "EMAIL SENT" in args
        assert "To: user@example.com" in args
        assert "CC: cc@example.com" in args
        assert "Body (HTML available)" in args


@pytest.mark.asyncio
async def test_sms_console_send():
    sender = ConsoleSMSSender(output_to_stdout=True)

    msg = SMSMessage(to="+1234567890", body="OTP: 123456")

    with patch("builtins.print") as mock_print:
        await sender.send(msg)
        assert mock_print.called
        assert "SMS SENT" in mock_print.call_args[0][0]
