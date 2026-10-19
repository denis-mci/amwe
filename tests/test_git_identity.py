import httpx
import pytest

from amwe.collectors.git_identity import GitIdentityCollector
from amwe.models import Severity, Target

EVENTS = [
    {"type": "PushEvent", "repo": {"name": "denis/app"}, "payload": {"head": "aaa"}},
    {"type": "PushEvent", "repo": {"name": "denis/app"}, "payload": {"head": "aaa"}},
    {"type": "PushEvent", "repo": {"name": "team/lib"}, "payload": {"head": "bbb"}},
    {"type": "PushEvent", "repo": {"name": "denis/dots"}, "payload": {"head": "ccc"}},
    {"type": "WatchEvent", "repo": {"name": "other/repo"}, "payload": {}},
]

COMMITS = {
    "/repos/denis/app/commits/aaa": ("Denis", "denis@example.com", "Denis"),
    "/repos/team/lib/commits/bbb": ("Colleague", "colleague@example.com", "colleague"),
    "/repos/denis/dots/commits/ccc": ("Denis", "1+denis@users.noreply.github.com", "denis"),
}


def github(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/users/denis/events/public":
        return httpx.Response(200, json=EVENTS)
    if path in COMMITS:
        name, email, login = COMMITS[path]
        return httpx.Response(
            200,
            json={"commit": {"author": {"name": name, "email": email}}, "author": {"login": login}},
        )
    return httpx.Response(404)


async def collect(username: str | None) -> list:
    target = Target("me@example.com", username)
    return [f async for f in GitIdentityCollector().collect(target)]


@pytest.mark.asyncio
async def test_reports_own_name_and_email(mock_http):
    mock_http(github)

    findings = await collect("denis")

    assert {(f.kind, f.value) for f in findings} == {
        ("real-name", "Denis"),
        ("email", "denis@example.com"),
    }
    assert next(f for f in findings if f.kind == "email").severity is Severity.HIGH


@pytest.mark.asyncio
async def test_ignores_collaborators_and_noreply(mock_http):
    mock_http(github)

    values = {f.value for f in await collect("denis")}

    assert "Colleague" not in values
    assert "colleague@example.com" not in values
    assert not any(v.endswith("@users.noreply.github.com") for v in values)


@pytest.mark.asyncio
async def test_rate_limited_yields_nothing(mock_http):
    mock_http(lambda request: httpx.Response(403, json={"message": "API rate limit exceeded"}))

    assert await collect("denis") == []


@pytest.mark.asyncio
async def test_no_username_yields_nothing():
    assert await collect(None) == []
