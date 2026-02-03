import pytest
import uuid
from unittest.mock import AsyncMock, Mock
from cqrs_ddd_auth.application.event_handlers import (
    IdentityChangeSyncHandler,
    register_identity_sync_handlers,
)
from cqrs_ddd_auth.application.sagas import StepUpAuthenticationSaga
from cqrs_ddd_auth.domain.events import (
    UserCreatedInIdP,
    SensitiveOperationRequested,
    OTPValidated,
    SensitiveOperationCompleted,
)
from cqrs_ddd_auth.application.commands import (
    SendOTPChallenge,
    GrantTemporaryElevation,
    ResumeSensitiveOperation,
    RevokeElevation,
)
from cqrs_ddd.saga import SagaContext


@pytest.mark.asyncio
async def test_identity_change_sync_handler_success():
    abac_adapter = AsyncMock()
    abac_adapter.sync_from_idp.return_value = {"status": "sync_started"}
    handler = IdentityChangeSyncHandler(abac_adapter)

    event = UserCreatedInIdP(idp_user_id="u1", username="user1")
    await handler.handle(event)

    assert abac_adapter.sync_from_idp.called


@pytest.mark.asyncio
async def test_identity_change_sync_handler_nosync():
    abac_adapter = Mock()  # No sync_from_idp
    handler = IdentityChangeSyncHandler(abac_adapter)

    event = UserCreatedInIdP(idp_user_id="u1", username="user1")
    await handler.handle(event)
    # Just verify no crash


@pytest.mark.asyncio
async def test_identity_change_sync_handler_error():
    abac_adapter = AsyncMock()
    abac_adapter.sync_from_idp.side_effect = Exception("Sync failed")
    handler = IdentityChangeSyncHandler(abac_adapter)

    event = UserCreatedInIdP(idp_user_id="u1", username="user1")
    await handler.handle(event)
    # Just verify no crash despite error


def test_register_identity_sync_handlers():
    dispatcher = Mock()
    abac_adapter = Mock()
    register_identity_sync_handlers(dispatcher, abac_adapter)
    assert dispatcher.register.call_count == 7


@pytest.mark.asyncio
async def test_step_up_saga_flow():
    context = SagaContext(
        saga_id=str(uuid.uuid4()),
        saga_type="StepUpAuthenticationSaga",
        correlation_id="corr1",
        current_step="start",
        state={},
    )
    mediator = Mock()
    saga = StepUpAuthenticationSaga(context, mediator)
    saga.dispatch_command = Mock()

    # 1. Requested
    await saga.on_sensitive_operation_requested(
        SensitiveOperationRequested(
            user_id="u1", operation_id="op1", action="delete_all"
        )
    )
    assert saga.state.operation_id == "op1"
    assert saga.state.user_id == "u1"
    assert any(
        isinstance(c, SendOTPChallenge)
        for c in saga.dispatch_command.call_args_list[0][0]
    )

    # 2. OTP Validated
    saga.dispatch_command.reset_mock()
    await saga.on_otp_validated(OTPValidated(user_id="u1", method="email"))

    # Check commands: GrantTemporaryElevation, ResumeSensitiveOperation
    commands = [args[0] for args, _ in saga.dispatch_command.call_args_list]
    assert any(isinstance(c, GrantTemporaryElevation) for c in commands)
    assert any(isinstance(c, ResumeSensitiveOperation) for c in commands)

    # 3. Completed
    saga.dispatch_command.reset_mock()
    await saga.on_operation_completed(SensitiveOperationCompleted(operation_id="op1"))
    assert any(
        isinstance(c, RevokeElevation)
        for c in saga.dispatch_command.call_args_list[0][0]
    )


@pytest.mark.asyncio
async def test_step_up_saga_wrong_user():
    context = SagaContext(
        saga_id=str(uuid.uuid4()),
        saga_type="StepUpAuthenticationSaga",
        correlation_id="corr1",
        current_step="start",
        state={"user_id": "u1"},
    )
    mediator = Mock()
    saga = StepUpAuthenticationSaga(context, mediator)
    saga.dispatch_command = Mock()

    await saga.on_otp_validated(OTPValidated(user_id="u2", method="email"))
    assert not saga.dispatch_command.called
