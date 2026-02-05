"""
Identity-aware SQLAlchemy Event Store.
"""

import json
from datetime import datetime, timezone
from typing import Optional, Any
from cqrs_ddd.backends.sqlalchemy_event_store import SQLAlchemyEventStore
from cqrs_ddd.exceptions import ConcurrencyError
from cqrs_ddd_auth.ddd import get_identity


class AuthSQLAlchemyEventStore(SQLAlchemyEventStore):
    """
    SQLAlchemy-based Event Store that persists user identity.

    Expected table schema:
        CREATE TABLE domain_events (
            ... standard toolkit columns ...
            user_id VARCHAR(255),
            username VARCHAR(255),
            undone_by VARCHAR(255)
        );
    """

    async def append(
        self, event, expected_version: Optional[int] = None, unit_of_work: Any = None
    ):
        """Append event with identity persistence."""
        from sqlalchemy import text

        # Manage UoW lifecycle (matches toolkit implementation but with extra fields)
        uow = unit_of_work
        own_uow = False

        if uow is None:
            uow = self._uow_factory()
            await uow.__aenter__()
            own_uow = True

        try:
            if not hasattr(uow, "session"):
                raise TypeError(
                    "AuthSQLAlchemyEventStore requires a UnitOfWork with a 'session' attribute"
                )

            session = uow.session
            current_version = await self._get_version(
                session, event.aggregate_type, event.aggregate_id
            )

            if expected_version is not None and current_version != expected_version:
                raise ConcurrencyError(
                    expected=expected_version, actual=current_version
                )

            new_version = current_version + 1
            identity = get_identity()

            # Use identity from event (if already enriched) or global context
            user_id = getattr(event, "user_id", None) or identity.user_id
            username = getattr(event, "username", None) or identity.username

            insert_sql = text(
                f"""
                INSERT INTO {self._table_name} (
                    event_id, aggregate_type, aggregate_id, event_type,
                    event_version, occurred_at, user_id, username, correlation_id,
                    causation_id, payload, aggregate_version
                ) VALUES (
                    :event_id, :aggregate_type, :aggregate_id, :event_type,
                    :event_version, :occurred_at, :user_id, :username, :correlation_id,
                    :causation_id, :payload, :aggregate_version
                ) RETURNING id
            """
            )

            payload = event.to_dict()
            # Ensure identity is also in payload for dual-layer audit if needed
            if user_id:
                payload["user_id"] = user_id
            if username:
                payload["username"] = username

            payload_json = json.dumps(payload)

            result = await session.execute(
                insert_sql,
                {
                    "event_id": event.event_id,
                    "aggregate_type": event.aggregate_type,
                    "aggregate_id": str(event.aggregate_id),
                    "event_type": event.event_type,
                    "event_version": event.version,
                    "occurred_at": event.occurred_at or datetime.now(timezone.utc),
                    "user_id": user_id,
                    "username": username,
                    "correlation_id": event.correlation_id,
                    "causation_id": event.causation_id,
                    "payload": payload_json,
                    "aggregate_version": new_version,
                },
            )

            row_id = result.scalar()
            await session.flush()

            if own_uow:
                await uow.__aexit__(None, None, None)

            return {
                "id": row_id,
                "event_id": event.event_id,
                "aggregate_type": event.aggregate_type,
                "aggregate_id": event.aggregate_id,
                "event_type": event.event_type,
                "user_id": user_id,
                "username": username,
                "aggregate_version": new_version,
            }

        except Exception:
            if own_uow:
                import sys

                await uow.__aexit__(*sys.exc_info())
            raise

    async def mark_as_undone(
        self,
        event_id: str,
        undo_event_id: Optional[str] = None,
        unit_of_work: Any = None,
    ) -> None:
        """Mark an event as undone with identity tracking."""
        from sqlalchemy import text

        async def _execute(session):
            identity = get_identity()
            # Capture identify for undone_by
            undone_by = identity.user_id or identity.username

            sql = text(
                f"""
                UPDATE {self._table_name}
                SET is_undone = TRUE,
                    undone_at = :undone_at,
                    undone_by = :undone_by,
                    undo_event_id = :undo_event_id
                WHERE event_id = :event_id
            """
            )

            await session.execute(
                sql,
                {
                    "event_id": event_id,
                    "undone_at": datetime.now(timezone.utc),
                    "undone_by": undone_by,
                    "undo_event_id": undo_event_id,
                },
            )

        if unit_of_work:
            await _execute(unit_of_work.session)
        else:
            async with self._uow_factory() as uow:
                await _execute(uow.session)
