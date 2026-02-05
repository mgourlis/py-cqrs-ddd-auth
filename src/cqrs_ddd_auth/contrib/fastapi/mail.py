"""
Async SMTP Email Adapter for FastAPI.
"""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional

try:
    import aiosmtplib
except ImportError:
    aiosmtplib = None  # type: ignore

from cqrs_ddd_auth.infrastructure.ports.communication import (
    EmailSenderPort,
    EmailMessage,
)

logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.fastapi_mail")


class AsyncSMTPEmailSender(EmailSenderPort):
    """
    SMTP implementation of EmailSenderPort using aiosmtplib.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 1025,
        user: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = False,
        use_ssl: bool = False,
        timeout: int = 10,
        use_starttls: bool = False,
        default_from: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.use_starttls = use_starttls
        self.default_from = default_from

        if aiosmtplib is None:
            logger.warning(
                "aiosmtplib is not installed. AsyncSMTPEmailSender will not work."
                "Install it with: pip install aiosmtplib"
            )

    async def send(self, message: EmailMessage) -> None:
        """Send an email using aiosmtplib."""
        if aiosmtplib is None:
            raise ImportError(
                "aiosmtplib is required for AsyncSMTPEmailSender. "
                "Install it with: pip install aiosmtplib"
            )

        # Build MIME Message
        mime_msg = MIMEMultipart("alternative")
        mime_msg["Subject"] = message.subject

        from_email = message.from_email or self.default_from or f"noreply@{self.host}"
        mime_msg["From"] = from_email
        mime_msg["To"] = ", ".join(message.to)

        if message.cc:
            mime_msg["Cc"] = ", ".join(message.cc)
        if message.reply_to:
            mime_msg["Reply-To"] = message.reply_to

        # Add text body
        mime_msg.attach(MIMEText(message.body_text, "plain"))

        # Add HTML body if provided
        if message.body_html:
            mime_msg.attach(MIMEText(message.body_html, "html"))

        # Add attachments
        for attachment in message.attachments:
            part = MIMEBase(*attachment.mimetype.split("/", 1))
            part.set_payload(attachment.content)
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={attachment.filename}",
            )
            mime_msg.attach(part)

        # Recipients list (including CC and BCC)
        recipients = message.to + message.cc + message.bcc

        try:
            smtp = aiosmtplib.SMTP(
                hostname=self.host,
                port=self.port,
                use_tls=self.use_ssl,  # aiosmtplib uses use_tls for SMTPS (usually 465)
                timeout=self.timeout,
            )

            async with smtp:
                if self.use_starttls and not self.use_ssl:
                    await smtp.starttls()

                if self.user and self.password:
                    await smtp.login(self.user, self.password)

                await smtp.send_message(mime_msg, recipients=recipients)

            logger.info(f"Email sent successfully to {', '.join(message.to)}")

        except Exception as e:
            logger.error(f"Failed to send email to {', '.join(message.to)}: {str(e)}")
            raise
