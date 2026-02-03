from __future__ import annotations
from dataclasses import dataclass
from cqrs_ddd.saga import Saga, saga_step
from cqrs_ddd_auth.domain.events import (
    SensitiveOperationRequested,
    OTPValidated,
    SensitiveOperationCompleted,
)
from cqrs_ddd_auth.application.commands import (
    SendOTPChallenge,
    GrantTemporaryElevation,
    RevokeElevation,
    ResumeSensitiveOperation,
)


@dataclass
class StepUpState:
    """State for step-up authentication flow."""

    operation_id: str = None
    user_id: str = None
    required_action: str = None


class StepUpAuthenticationSaga(Saga[StepUpState]):
    """
    Handles step-up authentication for sensitive operations.

    Flow:
    1. Sensitive operation requested → Issue OTP challenge
    2. OTP validated → Grant temporary elevated access & resume operation
    3. Operation completed OR timeout → Revoke elevation
    """

    @saga_step(SensitiveOperationRequested)
    async def on_sensitive_operation_requested(
        self, event: SensitiveOperationRequested
    ):
        self.state.operation_id = event.operation_id
        self.state.user_id = event.user_id
        self.state.required_action = event.action

        # Use user_id to identify the user for OTP challenge
        self.dispatch_command(
            SendOTPChallenge(
                user_id=event.user_id,
                method="email",
            )
        )

    @saga_step(OTPValidated)
    async def on_otp_validated(self, event: OTPValidated):
        # Verify this OTP validation belongs to our user
        if event.user_id != self.state.user_id:
            return

        if self.state.required_action and self.state.operation_id:
            self.dispatch_command(
                GrantTemporaryElevation(
                    user_id=event.user_id,
                    action=self.state.required_action,
                    ttl_seconds=300,
                )
            )

            # Register compensation to revoke elevation if subsequent steps fail
            self.add_compensation(RevokeElevation(user_id=event.user_id))

            self.dispatch_command(
                ResumeSensitiveOperation(operation_id=self.state.operation_id)
            )

    @saga_step(SensitiveOperationCompleted)
    async def on_operation_completed(self, event: SensitiveOperationCompleted):
        if self.state.user_id:
            self.dispatch_command(RevokeElevation(user_id=self.state.user_id))
        self.complete()
