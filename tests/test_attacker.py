import httpx
import pytest

from amwe.attacker import build_attack, render_interception_page, render_login_page
from amwe.attacker.login_page import INTERCEPTION_NOTICE
from amwe.models import Finding, Profile, ScanResult, Severity, Target

HOST = "http://testserver"
PROFILE = Profile("An attacker knows your name and your GitHub.", "deterministic")


def result_with(*findings: Finding) -> ScanResult:
    return ScanResult(target=Target("me@example.com"), findings=list(findings))


WITH_GITHUB = result_with(
    Finding("git-identity", "real-name", "Denis N", Severity.MEDIUM),
    Finding("username", "account", "GitHub: denis", Severity.MEDIUM),
)


@pytest.mark.asyncio
async def test_email_marked_simulation_and_targets_used_service(mock_http):
    mock_http(lambda request: httpx.Response(200, json={"models": []}))

    attack = await build_attack(WITH_GITHUB, PROFILE, host=HOST)

    assert attack.service == "GitHub"
    assert "SIMULATION" in attack.email.subject
    assert attack.email.body.count("AMWE SIMULATION") == 2
    assert "Denis N" in attack.email.body
    assert attack.email.source == "deterministic"


@pytest.mark.asyncio
async def test_falls_back_to_generic_service_without_accounts(mock_http):
    mock_http(lambda request: httpx.Response(200, json={"models": []}))

    attack = await build_attack(result_with(), PROFILE, host=HOST)

    assert attack.service == "your email provider"


@pytest.mark.asyncio
async def test_model_text_is_wrapped_in_non_removable_markers(mock_http):
    def ollama(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3"}]})
        return httpx.Response(200, json={"response": "Click here to keep your account."})

    mock_http(ollama)

    attack = await build_attack(WITH_GITHUB, PROFILE, host=HOST)

    assert attack.email.source == "ollama"
    assert "Click here to keep your account." in attack.email.body
    assert attack.email.body.count("AMWE SIMULATION") == 2


def test_login_page_cannot_post_anywhere_but_local():
    page = render_login_page("GitHub")

    assert "form-action 'self'" in page
    assert "SIMULATION" in page
    # No external endpoint the form could reach.
    assert "http://" not in page
    assert "https://" not in page
    assert INTERCEPTION_NOTICE in page


def test_login_page_intercepts_input_client_side():
    page = render_login_page("GitHub")

    assert "preventDefault" in page
    assert "addEventListener('submit'" in page
    assert "addEventListener('input'" in page


def test_interception_page_carries_notice_and_marker():
    page = render_interception_page()

    assert INTERCEPTION_NOTICE in page
    assert "SIMULATION" in page
