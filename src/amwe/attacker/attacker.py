"""Builds the simulated attack from a profile: a phishing email and a service name.

The email is a teaching artifact shown to the target, never sent — there is no
delivery path here. A local Ollama model may write the persuasive text; without
one, a deterministic version is used. Either way AMWE owns the subject and the
simulation markers, so the marking cannot be dropped by the model.
"""

from __future__ import annotations

from amwe.models import Attack, PhishingEmail, Profile, ScanResult
from amwe.profiler import ollama

_SIMULATION = "AMWE SIMULATION - no attacker sent this; it shows what one could craft about you."
_FALLBACK_SERVICE = "your email provider"


async def build_attack(
    result: ScanResult, profile: Profile, *, host: str = ollama.DEFAULT_HOST
) -> Attack:
    """Compose the phishing email for ``profile``, enriched by a local model when available."""
    service = _pretext_service(result)
    core = await ollama.narrate(_prompt(profile, service), host=host)
    if core is not None:
        email = _compose(core, service, source="ollama")
    else:
        email = _compose(_deterministic_core(result, service), service, source="deterministic")
    return Attack(email=email, service=service)


def _compose(core: str, service: str, source: str) -> PhishingEmail:
    body = f"[{_SIMULATION}]\n\n{core.strip()}\n\n[{_SIMULATION}]"
    subject = f"[SIMULATION] Verify your {service} account to avoid suspension"
    return PhishingEmail(subject=subject, body=body, source=source)


def _deterministic_core(result: ScanResult, service: str) -> str:
    name = _first(result, "real-name")
    greeting = f"Hi {name}," if name else "Hi there,"
    return "\n".join(
        [
            greeting,
            "",
            f"We detected an unusual sign-in to your {service} account. For your "
            "security, confirm it is really you within 24 hours or access will be "
            "suspended.",
            "",
            "Verify now using the teaching login page shown in this report.",
            "",
            f"{service} Security Team",
        ]
    )


def _pretext_service(result: ScanResult) -> str:
    for finding in result.findings:
        if finding.kind == "account":
            platform = finding.value.split(":", 1)[0].strip()
            if platform:
                return platform
    return _FALLBACK_SERVICE


def _first(result: ScanResult, kind: str) -> str | None:
    return next((f.value for f in result.findings if f.kind == kind), None)


def _prompt(profile: Profile, service: str) -> str:
    return (
        "Write the body of a phishing email that an attacker could send to this person "
        f"to make them sign in to a fake {service} page. Make it specific to the profile "
        "below so the person sees how convincing it would be. Plain text, no subject line, "
        "no markdown, no preamble.\n\n"
        f"Profile: {profile.summary}"
    )
