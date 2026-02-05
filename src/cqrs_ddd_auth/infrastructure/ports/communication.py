"""
Communication Ports.

Defines protocols for sending messages via various channels (Email, SMS).
"""

from dataclasses import dataclass, field
from typing import Protocol, List, Optional


# ═══════════════════════════════════════════════════════════════
# DATA TRANSFER OBJECTS
# ═══════════════════════════════════════════════════════════════


@dataclass
class EmailAttachment:
    """Structure for email attachments."""

    filename: str
    content: bytes
    mimetype: str


@dataclass
class EmailMessage:
    """Standard email message structure."""

    to: List[str]
    subject: str
    body_text: str
    body_html: Optional[str] = None
    from_email: Optional[str] = None
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    reply_to: Optional[str] = None
    attachments: List[EmailAttachment] = field(default_factory=list)


@dataclass
class SMSMessage:
    """Standard SMS message structure."""

    to: str  # Phone number
    body: str
    from_number: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# PORTS
# ═══════════════════════════════════════════════════════════════


class EmailSenderPort(Protocol):
    """
    Port for sending emails.

    Implementations: SMTP, SendGrid, AWS SES, Console (dev), etc.
    """

    async def send(self, message: EmailMessage) -> None:
        """
        Send an email message.

        Args:
            message: EmailMessage object

        Raises:
            Exception: If sending fails (implementations should use specific exceptions)
        """
        ...


class SMSSenderPort(Protocol):
    """
    Port for sending SMS.

    Implementations: Twilio, AWS SNS, Console (dev), etc.
    """

    async def send(self, message: SMSMessage) -> None:
        """
        Send an SMS message.

        Args:
            message: SMSMessage object

        Raises:
            Exception: If sending fails
        """
        ...
