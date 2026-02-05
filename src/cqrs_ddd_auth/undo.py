"""
Identity-aware Undo/Redo services.
"""

import logging
from typing import Optional
from cqrs_ddd.undo import DefaultUndoService, UndoResult, RedoResult
from cqrs_ddd.event_registry import EventTypeRegistry
from cqrs_ddd_auth.ddd import enrich_auth_metadata

logger = logging.getLogger("cqrs_ddd")


class AuthUndoService(DefaultUndoService):
    """
    Identity-aware Undo Service.
    Automatically enriches compensating events with the active user's identity.
    """

    async def undo(
        self,
        event_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> UndoResult:
        """
        Undo a specific event or a correlation group, with identity enrichment.
        """
        return await self._execute_auth_undo(event_id, correlation_id)

    async def _execute_auth_undo(
        self, event_id: Optional[str], correlation_id: Optional[str]
    ) -> UndoResult:
        """
        Implementation of undo logic using enrich_auth_metadata.
        """
        from cqrs_ddd.undo import UndoResult, generate_correlation_id

        if not event_id and not correlation_id:
            return UndoResult(
                success=False,
                undone_events=[],
                new_events=[],
                errors=["Must provide either event_id or correlation_id"],
            )

        events_to_undo = []
        if event_id:
            stored = await self.event_store.get_event(event_id)
            if stored:
                events_to_undo = [stored]
            else:
                return UndoResult(
                    success=False,
                    undone_events=[],
                    new_events=[],
                    errors=[f"Event not found: {event_id}"],
                )
        elif correlation_id:
            stored_events = await self.event_store.get_events_by_correlation(
                correlation_id
            )
            events_to_undo = sorted(
                [e for e in stored_events if not e.is_undone],
                key=lambda e: (e.occurred_at, getattr(e, "aggregate_version", 0)),
                reverse=True,
            )

        if not events_to_undo:
            return UndoResult(
                success=False,
                undone_events=[],
                new_events=[],
                errors=["No events found to undo"],
            )

        undo_corr_id = generate_correlation_id()
        undone_ids, new_event_ids, all_domain_events, errors = [], [], [], []

        for stored in events_to_undo:
            if stored.is_undone:
                continue

            executor = self.executor_registry.get(stored.event_type)
            if not executor:
                errors.append(f"No undo executor for {stored.event_type}")
                continue

            domain_event = EventTypeRegistry.hydrate(stored)
            if domain_event is None:
                errors.append(f"Cannot hydrate event type: {stored.event_type}")
                continue

            try:
                if not await executor.can_undo(domain_event):
                    errors.append(
                        f"Cannot undo event {stored.event_id}: business rule violation"
                    )
                    continue

                compensating_events = await executor.undo(domain_event)
                for comp_event in compensating_events:
                    comp_event = enrich_auth_metadata(
                        comp_event,
                        correlation_id=undo_corr_id,
                        causation_id=stored.event_id,
                    )
                    await self.event_store.append(comp_event)
                    new_event_ids.append(comp_event.event_id)
                    all_domain_events.append(comp_event)

                await self.event_store.mark_as_undone(
                    event_id=stored.event_id,
                    undo_event_id=compensating_events[0].event_id
                    if compensating_events
                    else None,
                )
                undone_ids.append(stored.event_id)
                await self._invalidate_cache(stored.aggregate_type, stored.aggregate_id)
                logger.info(f"AuthUndone event {stored.event_id}")
            except Exception as e:
                errors.append(f"Error undoing {stored.event_id}: {str(e)}")

        return UndoResult(
            success=len(undone_ids) > 0 and len(errors) == 0,
            undone_events=undone_ids,
            new_events=new_event_ids,
            events=all_domain_events,
            correlation_id=undo_corr_id,
            causation_id=event_id,
            errors=errors,
        )

    async def redo(
        self, undo_event_id: Optional[str] = None, correlation_id: Optional[str] = None
    ) -> RedoResult:
        """
        Redo undone operations with identity enrichment.
        """
        return await self._execute_auth_redo(undo_event_id, correlation_id)

    async def _execute_auth_redo(
        self, undo_event_id: Optional[str], correlation_id: Optional[str]
    ) -> RedoResult:
        """
        Implementation of redo logic using enrich_auth_metadata.
        """
        from cqrs_ddd.undo import RedoResult, generate_correlation_id

        if not undo_event_id and not correlation_id:
            return RedoResult(
                success=False,
                redone_events=[],
                errors=["Must provide either undo_event_id or correlation_id"],
            )

        events_to_redo_from = []
        if undo_event_id:
            undo_event = await self.event_store.get_event(undo_event_id)
            if undo_event:
                events_to_redo_from = [undo_event]
        elif correlation_id:
            events_to_redo_from = await self.event_store.get_events_by_correlation(
                correlation_id
            )
            events_to_redo_from = sorted(
                events_to_redo_from,
                key=lambda e: (e.occurred_at, getattr(e, "aggregate_version", 0)),
            )

        if not events_to_redo_from:
            return RedoResult(
                success=False, redone_events=[], errors=["No undo events found to redo"]
            )

        redo_corr_id = generate_correlation_id()
        redone_ids, redone_domain_events, errors = [], [], []

        for undo_event in events_to_redo_from:
            orig_id = undo_event.causation_id
            if not orig_id:
                continue

            original_event = await self.event_store.get_event(orig_id)
            if not original_event or not original_event.is_undone:
                continue

            executor = self.executor_registry.get(original_event.event_type)
            if not executor:
                continue

            original_domain = EventTypeRegistry.hydrate(original_event)
            undo_domain = EventTypeRegistry.hydrate(undo_event)
            if not original_domain or not undo_domain:
                continue

            try:
                redo_events = await executor.redo(original_domain, undo_domain)
                for redo_event in redo_events:
                    redo_event = enrich_auth_metadata(
                        redo_event,
                        correlation_id=redo_corr_id,
                        causation_id=undo_event.event_id,
                    )
                    await self.event_store.append(redo_event)
                    redone_ids.append(redo_event.event_id)
                    redone_domain_events.append(redo_event)
                await self.event_store.mark_as_redone(orig_id)
                await self._invalidate_cache(
                    original_event.aggregate_type, original_event.aggregate_id
                )
            except Exception as e:
                errors.append(f"Error redoing {orig_id}: {str(e)}")

        return RedoResult(
            success=len(redone_ids) > 0 and len(errors) == 0,
            redone_events=redone_ids,
            events=redone_domain_events,
            correlation_id=redo_corr_id,
            causation_id=undo_event_id or correlation_id,
            errors=errors,
        )
