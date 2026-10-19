import httpx
import pytest

from amwe.models import Finding, ScanResult, Severity, Target
from amwe.profiler import build_profile, deterministic_summary

HOST = "http://testserver"


def result_with(*findings: Finding) -> ScanResult:
    return ScanResult(target=Target("me@example.com"), findings=list(findings))


FULL = result_with(
    Finding("git-identity", "real-name", "Denis N", Severity.MEDIUM),
    Finding("git-identity", "email", "denis@example.com", Severity.HIGH),
    Finding("username", "account", "GitHub: denis", Severity.MEDIUM),
    Finding("exif", "gps", "52.520000, 13.405000", Severity.HIGH),
)


def test_deterministic_summary_names_every_fact():
    summary = deterministic_summary(FULL)

    assert "Denis N" in summary
    assert "denis@example.com" in summary
    assert "GitHub: denis" in summary
    assert "52.520000, 13.405000" in summary


def test_deterministic_summary_deduplicates_repeated_values():
    summary = deterministic_summary(
        result_with(
            Finding("username", "account", "GitHub: denis"),
            Finding("username", "account", "GitHub: denis"),
        )
    )

    assert summary.count("GitHub: denis") == 1


def test_deterministic_summary_handles_empty_result():
    assert "nothing to profile" in deterministic_summary(result_with())


def test_deterministic_summary_is_stable():
    assert deterministic_summary(FULL) == deterministic_summary(FULL)


@pytest.mark.asyncio
async def test_falls_back_to_deterministic_when_no_model(mock_http):
    mock_http(lambda request: httpx.Response(200, json={"models": []}))

    profile = await build_profile(FULL, host=HOST)

    assert profile.source == "deterministic"
    assert profile.summary == deterministic_summary(FULL)


@pytest.mark.asyncio
async def test_falls_back_when_ollama_unreachable(mock_http):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no ollama", request=request)

    mock_http(refuse)

    profile = await build_profile(FULL, host=HOST)

    assert profile.source == "deterministic"


@pytest.mark.asyncio
async def test_uses_local_model_when_available(mock_http):
    def ollama(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3"}]})
        if request.url.path == "/api/generate":
            return httpx.Response(200, json={"response": "  An attacker knows your name.  "})
        return httpx.Response(404)

    mock_http(ollama)

    profile = await build_profile(FULL, host=HOST)

    assert profile.source == "ollama"
    assert profile.summary == "An attacker knows your name."


@pytest.mark.asyncio
async def test_blank_model_response_falls_back(mock_http):
    def ollama(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3"}]})
        return httpx.Response(200, json={"response": "   "})

    mock_http(ollama)

    profile = await build_profile(FULL, host=HOST)

    assert profile.source == "deterministic"
