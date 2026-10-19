"""The attacker stage: build a simulated phishing email and teaching login page."""

from amwe.attacker.attacker import build_attack
from amwe.attacker.login_page import (
    INTERCEPTION_NOTICE,
    render_interception_page,
    render_login_page,
)

__all__ = [
    "INTERCEPTION_NOTICE",
    "build_attack",
    "render_interception_page",
    "render_login_page",
]
