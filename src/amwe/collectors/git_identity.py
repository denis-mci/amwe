"""Git identity collector — finds the name and email behind a GitHub user's commits.

Git stamps every commit with an author name and email, and GitHub serves both
for any public commit. The user's public event feed names the commits they
pushed, so no key is needed. Only commits GitHub attributes to the target login
are read: a collaborator's identity in the same push is never reported.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx

from amwe.collectors.base import register
from amwe.models import Finding, Severity, Target

_API = "https://api.github.com"
_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; amwe/0.1; +self-scan)",
    "Accept": "application/vnd.github+json",
}
# Each commit lookup spends one of GitHub's 60 hourly anonymous requests.
_MAX_COMMITS = 5
_NOREPLY_SUFFIX = "@users.noreply.github.com"


@dataclass(frozen=True, slots=True)
class CommitIdentity:
    """The author stamp of one commit."""

    name: str
    email: str


class GitIdentityCollector:
    name = "git-identity"

    async def collect(self, target: Target) -> AsyncIterator[Finding]:
        if target.username is None:
            return
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS) as client:
            commit_urls = await _pushed_commit_urls(client, target.username)
            lookups = [_own_identity(client, url, target.username) for url in commit_urls]
            identities = {
                identity for identity in await asyncio.gather(*lookups) if identity is not None
            }
        for finding in self._findings(identities, target.username):
            yield finding

    def _findings(self, identities: set[CommitIdentity], username: str) -> list[Finding]:
        profile = f"https://github.com/{username}"
        names = sorted({identity.name for identity in identities if identity.name})
        emails = sorted({identity.email for identity in identities if _is_public(identity.email)})
        return [
            *(Finding(self.name, "real-name", name, Severity.MEDIUM, profile) for name in names),
            *(Finding(self.name, "email", email, Severity.HIGH, profile) for email in emails),
        ]


def _is_public(email: str) -> bool:
    # GitHub's noreply alias is the privacy setting working, not a leak.
    return bool(email) and not email.endswith(_NOREPLY_SUFFIX)


async def _get_json(client: httpx.AsyncClient, url: str) -> Any:
    """Return the decoded body, or None on any failure — including rate limiting."""
    try:
        response = await client.get(url)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


async def _pushed_commit_urls(client: httpx.AsyncClient, username: str) -> list[str]:
    events = await _get_json(client, f"{_API}/users/{username}/events/public")
    if not isinstance(events, list):
        return []
    urls = dict.fromkeys(
        f"{_API}/repos/{event['repo']['name']}/commits/{event['payload']['head']}"
        for event in events
        if event.get("type") == "PushEvent" and "head" in event.get("payload", {})
    )
    return list(urls)[:_MAX_COMMITS]


async def _own_identity(
    client: httpx.AsyncClient, commit_url: str, username: str
) -> CommitIdentity | None:
    commit = await _get_json(client, commit_url)
    if not isinstance(commit, dict):
        return None
    login = (commit.get("author") or {}).get("login", "")
    if login.lower() != username.lower():
        return None
    author = commit["commit"]["author"]
    return CommitIdentity(name=author["name"], email=author["email"])


register(GitIdentityCollector())
