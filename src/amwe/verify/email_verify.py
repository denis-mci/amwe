"""Ownership gate.

AMWE only ever scans an address the user controls. Before any collector runs,
the caller must prove control of the target email via a one-time code. This is
the single rule that separates a self-defense tool from a stalking tool, and it
lives in the code — not just the docs.

The v0.1 transport is intentionally abstract: :class:`Verifier` defines the
contract, and :class:`ConsoleVerifier` is a local stand-in. A real deployment
swaps in an SMTP-backed implementation without touching the collectors.
"""

from __future__ import annotations

import secrets
from typing import Protocol


class Verifier(Protocol):
    def challenge(self, email: str) -> None:
        """Send a one-time code to ``email``."""
        ...

    def check(self, email: str, code: str) -> bool:
        """Return True iff ``code`` matches the code issued for ``email``."""
        ...


class ConsoleVerifier:
    """Local verifier for development and self-scans on your own machine.

    It prints the code instead of emailing it. Swap for an SMTP verifier before
    exposing AMWE to anyone but yourself.
    """

    def __init__(self) -> None:
        self._issued: dict[str, str] = {}

    def challenge(self, email: str) -> None:
        code = f"{secrets.randbelow(1_000_000):06d}"
        self._issued[email] = code
        print(f"[verify] one-time code for {email}: {code}")

    def check(self, email: str, code: str) -> bool:
        expected = self._issued.get(email)
        return expected is not None and secrets.compare_digest(expected, code)
