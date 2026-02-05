"""
Tests for DjangoEmailSender.
"""

import pytest
from unittest.mock import MagicMock, patch
from cqrs_ddd_auth.contrib.django.mail import DjangoEmailSender
from cqrs_ddd_auth.infrastructure.ports.communication import EmailMessage


@pytest.mark.asyncio
async def test_django_send_with_attachments():
    from cqrs_ddd_auth.infrastructure.ports.communication import EmailAttachment

    # Mock settings to avoid ImproperlyConfigured
    with patch("cqrs_ddd_auth.contrib.django.mail.settings", new=MagicMock()):
        with patch(
            "cqrs_ddd_auth.contrib.django.mail.EmailMultiAlternatives"
        ) as mock_mail_class:
            with patch(
                "cqrs_ddd_auth.contrib.django.mail.sync_to_async"
            ) as mock_sync_to_async:

                def mock_sta(f):
                    async def wrapper(*args, **kwargs):
                        return f(*args, **kwargs)

                    return wrapper

                mock_sync_to_async.side_effect = mock_sta

                mock_mail_instance = MagicMock()
                mock_mail_class.return_value = mock_mail_instance

                sender = DjangoEmailSender()
                msg = EmailMessage(
                    to=["user@example.com"],
                    subject="Docs",
                    body_text="See attached",
                    attachments=[
                        EmailAttachment(
                            filename="doc.pdf",
                            content=b"%PDF-1.4",
                            mimetype="application/pdf",
                        )
                    ],
                )

                await sender.send(msg)

                mock_mail_instance.attach.assert_called_with(
                    "doc.pdf", b"%PDF-1.4", "application/pdf"
                )


@pytest.mark.asyncio
async def test_django_send_success():
    # Mock Django and sync_to_async
    with patch("cqrs_ddd_auth.contrib.django.mail.settings", new=MagicMock()):
        with patch(
            "cqrs_ddd_auth.contrib.django.mail.EmailMultiAlternatives"
        ) as mock_mail_class:
            with patch(
                "cqrs_ddd_auth.contrib.django.mail.sync_to_async"
            ) as mock_sync_to_async:
                if mock_mail_class is None:
                    pytest.skip("Django not available for testing")

                # Mock sync_to_async to return an AsyncMock that calls the function
                def mock_sta(f):
                    async def wrapper(*args, **kwargs):
                        return f(*args, **kwargs)

                    return wrapper

                mock_sync_to_async.side_effect = mock_sta

                mock_mail_instance = MagicMock()
                mock_mail_class.return_value = mock_mail_instance

                sender = DjangoEmailSender(from_email="default@example.com")

                msg = EmailMessage(
                    to=["user@example.com"],
                    subject="Test",
                    body_text="Hello",
                    body_html="<b>Hello</b>",
                )

                await sender.send(msg)

                mock_mail_class.assert_called_once()
                args, kwargs = mock_mail_class.call_args
                assert kwargs["subject"] == "Test"
                assert kwargs["to"] == ["user@example.com"]
                assert kwargs["from_email"] == "default@example.com"

                mock_mail_instance.attach_alternative.assert_called_with(
                    "<b>Hello</b>", "text/html"
                )
                mock_mail_instance.send.assert_called_once()


@pytest.mark.asyncio
async def test_django_import_error():
    # Patch settings to None to simulate missing config or import error
    with patch("cqrs_ddd_auth.contrib.django.mail.settings", None):
        with patch("cqrs_ddd_auth.contrib.django.mail.EmailMultiAlternatives", None):
            sender = DjangoEmailSender()
            msg = EmailMessage(to=["test@example.com"], subject="T", body_text="B")

            with pytest.raises(ImportError, match="Django and asgiref are required"):
                await sender.send(msg)
