"""
Django Email Adapter.
"""

import logging
from typing import Optional

try:
    from django.core.mail import EmailMultiAlternatives
    from django.conf import settings
    from asgiref.sync import sync_to_async
except ImportError:
    EmailMultiAlternatives = None  # type: ignore
    settings = None  # type: ignore
    sync_to_async = None  # type: ignore

from cqrs_ddd_auth.infrastructure.ports.communication import (
    EmailSenderPort,
    EmailMessage,
)

logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.django_mail")


class DjangoEmailSender(EmailSenderPort):
    """
    Django implementation of EmailSenderPort using django.core.mail.
    """

    def __init__(self, from_email: Optional[str] = None):
        self._from_email = from_email or (
            getattr(settings, "DEFAULT_FROM_EMAIL", None) if settings else None
        )

        if EmailMultiAlternatives is None:
            logger.warning("Django is not installed. DjangoEmailSender will not work.")

    async def send(self, message: EmailMessage) -> None:
        """Send an email using Django's email system."""
        if EmailMultiAlternatives is None or sync_to_async is None:
            raise ImportError("Django and asgiref are required for DjangoEmailSender.")

        # Wrap the synchronous Django mail call
        await sync_to_async(self._send_sync)(message)

    def _send_sync(self, message: EmailMessage) -> None:
        """Synchronous part of the email sending."""
        from_email = message.from_email or self._from_email

        email = EmailMultiAlternatives(
            subject=message.subject,
            body=message.body_text,
            from_email=from_email,
            to=message.to,
            cc=message.cc,
            bcc=message.bcc,
            reply_to=[message.reply_to] if message.reply_to else None,
        )

        if message.body_html:
            email.attach_alternative(message.body_html, "text/html")

        # Add attachments
        for attachment in message.attachments:
            email.attach(
                attachment.filename,
                attachment.content,
                attachment.mimetype,
            )

        try:
            email.send()
            logger.info(f"Email sent successfully to {', '.join(message.to)}")
        except Exception as e:
            logger.error(f"Failed to send email to {', '.join(message.to)}: {str(e)}")
            raise
