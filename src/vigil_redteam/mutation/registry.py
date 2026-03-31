"""Mutator registry — discover and chain transforms by name."""

from __future__ import annotations

from collections.abc import Callable

# Mutator = function (str) -> str
Mutator = Callable[[str], str]

_REGISTRY: dict[str, Mutator] = {}


def register(name: str) -> Callable[[Mutator], Mutator]:
    """Decorator to register a mutator function."""

    def wrapper(fn: Mutator) -> Mutator:
        _REGISTRY[name] = fn
        return fn

    return wrapper


def get_mutator(name: str) -> Mutator:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown mutator: {name}. Available: {list_mutators()}")
    return _REGISTRY[name]


def list_mutators() -> list[str]:
    return sorted(_REGISTRY.keys())
