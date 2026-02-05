from datetime import timedelta
from dataclasses import dataclass
from cqrs_ddd.saga import Saga, saga_step
from cqrs_ddd.contrib.tracing import traced_saga
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


@traced_saga
class StepUpAuthenticationSaga(Saga[StepUpState]):
    """
    Handles step-up authentication for sensitive operations.

    Flow:
    1. Sensitive operation requested → Issue OTP challenge & Suspend
    2. OTP validated → Resume, Grant temporary elevated access & resume operation
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

        # Suspend saga while waiting for user interaction (OTP)
        # Timeout after 5 minutes (standard security practice)
        self.suspend(reason="waiting_for_otp", timeout=timedelta(minutes=5))

    @saga_step(OTPValidated)
    async def on_otp_validated(self, event: OTPValidated):
        # Verify this OTP validation belongs to our user
        if event.user_id != self.state.user_id:
            return

        # Resume execution
        self.resume()

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

    async def on_timeout(self) -> None:
        """
        Handle MFA timeout.
        If the user takes too long, we ensure any partial progress is cleared.
        """
        if self.state.user_id:
            # Ensure any lingering elevation is revoked
            self.dispatch_command(RevokeElevation(user_id=self.state.user_id))

        # Mark saga as failed due to timeout
        self.fail(f"MFA timeout for operation {self.state.operation_id}")
