"""Username collector — finds where a handle exists across public platforms.

Keyless and read-only: it issues the same GET a browser would and infers
existence from the HTTP status. This is the Sherlock idea, trimmed to a seed
set. Contributors extend coverage by adding entries to ``SITES`` — that is the
low-barrier contribution path for this project.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from amwe.collectors.base import register
from amwe.models import Finding, Severity, Target

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; amwe/0.1; +self-scan)"}


@dataclass(frozen=True, slots=True)
class Site:
    """A platform whose public profile URL encodes the username."""

    name: str
    url_template: str  # must contain a single ``{username}`` field
    present_when_status: int = 200


# Seed set. Keep entries alphabetical; one site per line for clean diffs.
SITES: tuple[Site, ...] = (
    Site("GitHub", "https://github.com/{username}"),
    Site("GitLab", "https://gitlab.com/{username}"),
    Site("Instagram", "https://www.instagram.com/{username}/"),
    Site("Reddit", "https://www.reddit.com/user/{username}"),
    Site("npm", "https://www.npmjs.com/~{username}"),
)


class UsernameCollector:
    name = "username"

    async def collect(self, target: Target) -> AsyncIterator[Finding]:
        if target.username is None:
            return
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True
        ) as client:
            tasks = [self._check(client, site, target.username) for site in SITES]
            for finding in await asyncio.gather(*tasks):
                if finding is not None:
                    yield finding

    async def _check(self, client: httpx.AsyncClient, site: Site, username: str) -> Finding | None:
        url = site.url_template.format(username=username)
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return None
        if response.status_code != site.present_when_status:
            return None
        return Finding(
            source=self.name,
            kind="account",
            value=f"{site.name}: {username}",
            severity=Severity.MEDIUM,
            url=url,
        )


register(UsernameCollector())
