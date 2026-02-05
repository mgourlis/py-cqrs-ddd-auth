"""
Tests for AsyncSMTPEmailSender.
"""

import pytest
from unittest.mock import AsyncMock, patch
from cqrs_ddd_auth.contrib.fastapi.mail import AsyncSMTPEmailSender
from cqrs_ddd_auth.infrastructure.ports.communication import EmailMessage


@pytest.mark.asyncio
async def test_async_smtp_send_success():
    # Mock aiosmtplib.SMTP
    with patch("cqrs_ddd_auth.contrib.fastapi.mail.aiosmtplib") as mock_smtp_module:
        if mock_smtp_module is None:
            pytest.skip("aiosmtplib not available for testing")

        mock_smtp_instance = AsyncMock()
        mock_smtp_module.SMTP.return_value = mock_smtp_instance

        sender = AsyncSMTPEmailSender(
            host="mail.example.com",
            port=587,
            user="user",
            password="password",
            use_starttls=True,
        )

        msg = EmailMessage(
            to=["recipient@example.com"],
            subject="Hello",
            body_text="Welcome",
            from_email="noreply@example.com",
        )

        await sender.send(msg)

        # Verify SMTP interaction
        mock_smtp_module.SMTP.assert_called_with(
            hostname="mail.example.com", port=587, use_tls=False, timeout=10
        )

        assert mock_smtp_instance.__aenter__.called
        assert mock_smtp_instance.starttls.called
        assert mock_smtp_instance.login.called
        assert mock_smtp_instance.send_message.called

        sent_msg = mock_smtp_instance.send_message.call_args[0][0]
        assert sent_msg["Subject"] == "Hello"
        assert sent_msg["To"] == "recipient@example.com"
        assert sent_msg["From"] == "noreply@example.com"


@pytest.mark.asyncio
async def test_async_smtp_send_with_attachments():
    from cqrs_ddd_auth.infrastructure.ports.communication import EmailAttachment

    with patch("cqrs_ddd_auth.contrib.fastapi.mail.aiosmtplib") as mock_smtp_module:
        mock_smtp_instance = AsyncMock()
        mock_smtp_module.SMTP.return_value = mock_smtp_instance

        sender = AsyncSMTPEmailSender()
        msg = EmailMessage(
            to=["to@example.com"],
            subject="Attachments",
            body_text="Plain",
            attachments=[
                EmailAttachment(
                    filename="test.txt", content=b"hello", mimetype="text/plain"
                )
            ],
        )

        await sender.send(msg)

        mock_smtp_instance.send_message.assert_called()
        sent_msg = mock_smtp_instance.send_message.call_args[0][0]

        # Verify it's a multipart message
        assert sent_msg.is_multipart()
        parts = sent_msg.get_payload()

        # Parts: text body, then attachment
        # Note: MIMEMultipart("alternative") might have different payload structure
        # but here we added 1 body and 1 attachment.
        assert len(parts) >= 2

        # Find attachment part
        attachment_found = False
        for part in parts:
            if part.get_filename() == "test.txt":
                attachment_found = True
                assert part.get_payload(decode=True) == b"hello"

        assert attachment_found


@pytest.mark.asyncio
async def test_async_smtp_send_with_html_and_cc():
    with patch("cqrs_ddd_auth.contrib.fastapi.mail.aiosmtplib") as mock_smtp_module:
        mock_smtp_instance = AsyncMock()
        mock_smtp_module.SMTP.return_value = mock_smtp_instance

        sender = AsyncSMTPEmailSender()
        msg = EmailMessage(
            to=["to@example.com"],
            subject="Html",
            body_text="Plain",
            body_html="<h1>Html</h1>",
            cc=["cc@example.com"],
            bcc=["bcc@example.com"],
        )

        await sender.send(msg)

        mock_smtp_instance.send_message.assert_called()
        recipients = mock_smtp_instance.send_message.call_args[1]["recipients"]
        assert "to@example.com" in recipients
        assert "cc@example.com" in recipients
        assert "bcc@example.com" in recipients


@pytest.mark.asyncio
async def test_async_smtp_import_error():
    with patch("cqrs_ddd_auth.contrib.fastapi.mail.aiosmtplib", None):
        sender = AsyncSMTPEmailSender()
        msg = EmailMessage(to=["test@example.com"], subject="T", body_text="B")

        with pytest.raises(ImportError, match="aiosmtplib is required"):
            await sender.send(msg)
