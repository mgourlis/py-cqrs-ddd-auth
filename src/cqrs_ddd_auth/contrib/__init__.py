"""Contrib modules for framework and library integrations."""

# Conditional imports based on installed packages

try:
    from cqrs_ddd_auth.contrib.dependency_injector import AuthContainer
    HAS_DEPENDENCY_INJECTOR = True
except ImportError:
    HAS_DEPENDENCY_INJECTOR = False
    AuthContainer = None

__all__ = []

if HAS_DEPENDENCY_INJECTOR:
    __all__.append("AuthContainer")
