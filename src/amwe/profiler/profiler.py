"""Turns a :class:`ScanResult` into the attacker's view of the target.

Everything happens on the user's machine. A deterministic summary is always
available from the findings alone; a local Ollama model, if present, rewrites it
into something more fluent. Nothing is sent to a remote service.
"""

from __future__ import annotations

from dataclasses import dataclass

from amwe.models import Profile, ScanResult
from amwe.profiler import ollama


async def build_profile(result: ScanResult, *, host: str = ollama.DEFAULT_HOST) -> Profile:
    """Summarize ``result`` locally, enriched by a local model when one is available."""
    deterministic = deterministic_summary(result)
    narrative = await ollama.narrate(_prompt(result, deterministic), host=host)
    if narrative is not None:
        return Profile(summary=narrative, source="ollama")
    return Profile(summary=deterministic, source="deterministic")


def deterministic_summary(result: ScanResult) -> str:
    """Build the attacker's-view summary from the findings alone, without any model."""
    facts = _Facts.of(result)
    if not facts.any_known():
        return "No public traces were found, so there is nothing to profile yet."
    return " ".join(facts.sentences())


@dataclass(frozen=True, slots=True)
class _Facts:
    names: tuple[str, ...]
    emails: tuple[str, ...]
    accounts: tuple[str, ...]
    locations: tuple[str, ...]

    @classmethod
    def of(cls, result: ScanResult) -> _Facts:
        return cls(
            names=_values(result, "real-name"),
            emails=_values(result, "email"),
            accounts=_values(result, "account"),
            locations=_values(result, "gps"),
        )

    def any_known(self) -> bool:
        return bool(self.names or self.emails or self.accounts or self.locations)

    def sentences(self) -> list[str]:
        parts = ["From public sources alone, an attacker can already assemble a picture of you."]
        if self.names:
            parts.append(f"Your real name shows up in your public commits: {_join(self.names)}.")
        if self.emails:
            parts.append(
                f"An address an attacker can write to directly is public: {_join(self.emails)}."
            )
        if self.accounts:
            parts.append(
                f"Your handle ties these accounts into one identity: {_join(self.accounts)}."
            )
        if self.locations:
            parts.append(
                f"A photo you shared still carries GPS coordinates ({_join(self.locations)}), "
                "revealing where it was taken."
            )
        parts.append(_closing(self))
        return parts


def _closing(facts: _Facts) -> str:
    if facts.emails and (facts.names or facts.accounts):
        return "Together this is enough to write a phishing message that sounds like it knows you."
    return "Even this partial trail narrows down who you are."


def _values(result: ScanResult, kind: str) -> tuple[str, ...]:
    seen = dict.fromkeys(f.value for f in result.findings if f.kind == kind)
    return tuple(seen)


def _join(values: tuple[str, ...]) -> str:
    return ", ".join(values)


def _prompt(result: ScanResult, deterministic: str) -> str:
    facts = "\n".join(f"- {f.value}" for f in result.findings)
    return (
        "You are helping a person see their own public exposure, from an attacker's "
        "perspective. Using only the facts below, write three or four plain sentences in "
        "the second person. No preamble, no markdown, no headings.\n\n"
        f"Facts about {result.target.email}:\n{facts}\n\n"
        f"For reference, a baseline summary is: {deterministic}"
    )
