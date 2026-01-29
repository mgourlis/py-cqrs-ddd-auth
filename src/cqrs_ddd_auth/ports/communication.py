"""
Communication Ports.

Defines interfaces for email and SMS sending.
"""

from typing import Protocol


class EmailSenderPort(Protocol):
    """Port for sending emails."""
    
    async def send(
        self, 
        to: str, 
        subject: str, 
        body: str,
        html_body: str | None = None
    ) -> None:
        """
        Send an email.
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Plain text body
            html_body: Optional HTML body
        """
        ...
    
    async def send_template(
        self,
        to: str,
        template_name: str,
        context: dict
    ) -> None:
        """
        Send a templated email.
        
        Args:
            to: Recipient email address
            template_name: Name of the template
            context: Template variables
        """
        ...


class SMSSenderPort(Protocol):
    """Port for sending SMS messages."""
    
    async def send(self, to: str, message: str) -> None:
        """
        Send an SMS.
        
        Args:
            to: Recipient phone number (E.164 format)
            message: SMS message content
        """
        ...
