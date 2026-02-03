from functools import wraps
from typing import Callable
from django.http import JsonResponse
from cqrs_ddd_auth.identity import get_identity


def require_authenticated(view_func: Callable) -> Callable:
    """Decorator to require authentication for a view."""

    @wraps(view_func)
    async def wrapper(request, *args, **kwargs):
        identity = get_identity()
        if not identity.is_authenticated:
            return JsonResponse(
                {"error": "UNAUTHORIZED", "message": "Authentication required"},
                status=401,
            )
        return await view_func(request, *args, **kwargs)

    return wrapper


def require_groups(*required_groups: str) -> Callable:
    """Decorator to require specific group membership."""

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        async def wrapper(request, *args, **kwargs):
            identity = get_identity()
            if not identity.is_authenticated:
                return JsonResponse(
                    {"error": "UNAUTHORIZED", "message": "Authentication required"},
                    status=401,
                )
            user_groups = set(identity.groups)
            if not any(g in user_groups for g in required_groups):
                return JsonResponse(
                    {"error": "FORBIDDEN", "message": "Insufficient permissions"},
                    status=403,
                )
            return await view_func(request, *args, **kwargs)

        return wrapper

    return decorator
