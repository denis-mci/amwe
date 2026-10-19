"""Collector plugin contract.

A collector takes a :class:`Target` and yields :class:`Finding` objects from
one public source. Each source is its own small module — the same shape that
lets yt-dlp and uBlock scale through community contributions. Add a collector
by implementing :class:`Collector` and decorating it with :func:`register`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from typing import Protocol, runtime_checkable

from amwe.models import Finding, Target


@runtime_checkable
class Collector(Protocol):
    """One public data source. Keep each implementation small and single-purpose."""

    name: str

    def collect(self, target: Target) -> AsyncIterator[Finding]:
        """Yield findings for ``target``. Must only touch public, keyless sources.

        Implemented as an ``async def`` generator, so the declared return type is
        the resulting :class:`AsyncIterator`, not a coroutine wrapping one.
        """
        ...


_REGISTRY: dict[str, Collector] = {}


def register(collector: Collector) -> Collector:
    """Register a collector instance so the CLI can discover it."""
    if collector.name in _REGISTRY:
        raise ValueError(f"duplicate collector name: {collector.name!r}")
    _REGISTRY[collector.name] = collector
    return collector


def all_collectors() -> Iterable[Collector]:
    """Return every registered collector, in registration order."""
    return tuple(_REGISTRY.values())
