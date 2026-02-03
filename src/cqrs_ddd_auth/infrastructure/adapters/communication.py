"""
Communication Adapters.

Concrete implementations of communication ports.
"""

import logging

from cqrs_ddd_auth.infrastructure.ports.communication import (
    EmailSenderPort,
    SMSSenderPort,
    EmailMessage,
    SMSMessage,
)

logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.communication")


# ═══════════════════════════════════════════════════════════════
# CONSOLE EMAIL SENDER (Dev/Test)
# ═══════════════════════════════════════════════════════════════


class ConsoleEmailSender(EmailSenderPort):
    """
    Console implementation of EmailSenderPort.

    Prints emails to stdout/logger. Useful for development.
    """

    def __init__(self, output_to_stdout: bool = True):
        self.output_to_stdout = output_to_stdout

    async def send(self, message: EmailMessage) -> None:
        """Log the email message."""
        output = [
            "--------------------------------------------------",
            "EMAIL SENT (Console)",
            f"To: {', '.join(message.to)}",
            f"Subject: {message.subject}",
            f"From: {message.from_email or '(default)'}",
        ]

        if message.cc:
            output.append(f"CC: {', '.join(message.cc)}")
        if message.bcc:
            output.append(f"BCC: {', '.join(message.bcc)}")

        output.append("Body:")
        output.append(message.body_text)

        if message.body_html:
            output.append("Body (HTML available)")

        output.append("--------------------------------------------------")

        full_output = "\n".join(output)
        logger.info(full_output)

        if self.output_to_stdout:
            print(full_output)


# ═══════════════════════════════════════════════════════════════
# CONSOLE SMS SENDER (Dev/Test)
# ═══════════════════════════════════════════════════════════════


class ConsoleSMSSender(SMSSenderPort):
    """
    Console implementation of SMSSenderPort.

    Prints SMS to stdout/logger. Useful for development.
    """

    def __init__(self, output_to_stdout: bool = True):
        self.output_to_stdout = output_to_stdout

    async def send(self, message: SMSMessage) -> None:
        """Log the SMS message."""
        output = [
            "--------------------------------------------------",
            "SMS SENT (Console)",
            f"To: {message.to}",
            f"From: {message.from_number or '(default)'}",
            "Body:",
            message.body,
            "--------------------------------------------------",
        ]

        full_output = "\n".join(output)
        logger.info(full_output)

        if self.output_to_stdout:
            print(full_output)


__all__ = [
    "ConsoleEmailSender",
    "ConsoleSMSSender",
]
