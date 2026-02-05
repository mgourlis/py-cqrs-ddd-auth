"""
Pydantic-based DDD base classes with identity awareness.
"""
from typing import Any

try:
    from pydantic import Field

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    Field = None

from cqrs_ddd.contrib.pydantic import PydanticEntity, PydanticDomainEvent
from cqrs_ddd_auth.identity import get_identity


class PydanticAuthEntity(PydanticEntity):
    """
    Base class for identity-aware entities using Pydantic.
    Automatically captures user_id and username from identity context.
    """

    user_id: str = Field(default_factory=lambda: get_identity().user_id)
    username: str = Field(default_factory=lambda: get_identity().username)


class PydanticAuthDomainEvent(PydanticDomainEvent):
    """
    Base class for identity-aware domain events using Pydantic.
    Automatically captures user_id and username from identity context.
    """

    user_id: str = Field(default_factory=lambda: get_identity().user_id)
    username: str = Field(default_factory=lambda: get_identity().username)

    @property
    def aggregate_id(self) -> Any:
        # PydanticDomainEvent expects this to be implemented by subclasses
        # if using the default hydrate functionality.
        raise NotImplementedError("Subclasses must implement aggregate_id")
