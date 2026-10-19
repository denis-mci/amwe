import httpx
import pytest

from amwe.collectors.username import UsernameCollector
from amwe.models import Target


@pytest.mark.asyncio
async def test_hit_yields_account_finding(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # Pretend only the GitHub profile exists.
        if "github.com" in str(request.url):
            return httpx.Response(200)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def patched(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched)

    findings = [f async for f in UsernameCollector().collect(Target("me@example.com", "denis"))]
    values = {f.value for f in findings}
    assert any("GitHub" in v for v in values)
    assert all(f.kind == "account" for f in findings)


@pytest.mark.asyncio
async def test_no_username_yields_nothing():
    findings = [f async for f in UsernameCollector().collect(Target("me@example.com", None))]
    assert findings == []
