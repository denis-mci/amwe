import threading
import urllib.error
import urllib.request

import pytest

from amwe.models import Finding, ScanResult, Severity, Target
from amwe.reporter import local_server, render_html, server_url


def result_with(*findings: Finding) -> ScanResult:
    return ScanResult(target=Target("me@example.com"), findings=list(findings))


def test_lists_findings_highest_severity_first():
    page = render_html(
        result_with(
            Finding("username", "account", "GitHub: me", Severity.MEDIUM),
            Finding("git-identity", "email", "me@example.com", Severity.HIGH),
        )
    )

    assert page.index("me@example.com</li>") < page.index("GitHub: me")
    assert "2 public traces found" in page


def test_escapes_finding_values():
    page = render_html(result_with(Finding("x", "account", "<script>alert(1)</script>")))

    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_links_only_web_urls():
    page = render_html(
        result_with(
            Finding("x", "account", "web", url="https://example.com/me"),
            Finding("x", "account", "script", url="javascript:alert(1)"),
        )
    )

    assert 'href="https://example.com/me"' in page
    assert "javascript:" not in page


def test_gps_finding_gets_local_map_hint():
    page = render_html(result_with(Finding("exif", "gps", "52.520000, 13.405000", Severity.HIGH)))

    assert 'href="geo:52.520000,13.405000"' in page


def test_page_loads_nothing_from_the_network():
    page = render_html(result_with())

    assert "default-src 'none'" in page
    assert "No public traces found." in page


@pytest.fixture
def served_report():
    server = local_server("<p>report</p>")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server_url(server)
    server.shutdown()
    server.server_close()


def test_server_binds_loopback_only(served_report):
    assert served_report.startswith("http://127.0.0.1:")


def test_server_serves_page(served_report):
    with urllib.request.urlopen(served_report) as response:
        assert response.read() == b"<p>report</p>"
        assert response.headers["Content-Type"] == "text/html; charset=utf-8"


def test_server_rejects_other_paths(served_report):
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(served_report + "other")
    assert error.value.code == 404


def test_profile_section_shown_when_provided():
    from amwe.models import Profile

    page = render_html(result_with(), Profile("You are exposed.", "deterministic"))

    assert "The picture this builds" in page
    assert "You are exposed." in page
    assert "without a model" in page


def test_profile_summary_is_escaped():
    from amwe.models import Profile

    page = render_html(result_with(), Profile("<b>name</b>", "ollama"))

    assert "<b>name</b>" not in page
    assert "&lt;b&gt;name&lt;/b&gt;" in page
    assert "local model" in page


def test_no_profile_section_without_profile():
    assert "The picture this builds" not in render_html(result_with())


@pytest.fixture
def served_attack():
    import threading

    server = local_server(
        "<p>report</p>",
        login_page='<form action="/login" method="post"><input name="password"></form>',
        notice_page="<p>Nothing you submitted was stored or sent.</p>",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server_url(server)
    server.shutdown()
    server.server_close()


def test_login_page_served_at_login(served_attack):
    with urllib.request.urlopen(served_attack + "login") as response:
        assert b"<form" in response.read()


def test_login_post_persists_nothing_and_sends_nothing(tmp_path, monkeypatch, served_attack):
    # Run from an empty dir so we can prove the handler writes no file anywhere local.
    monkeypatch.chdir(tmp_path)
    secret = "pw-UNIQUE-TOKEN-7f3a9"
    request = urllib.request.Request(
        served_attack + "login",
        data=f"username=me&password={secret}".encode(),
        method="POST",
    )

    with urllib.request.urlopen(request) as response:
        body = response.read().decode()

    # The response is the notice, and it never echoes the submitted secret back.
    assert "Nothing you submitted was stored or sent." in body
    assert secret not in body
    # No credential store was created on disk by handling the POST.
    assert list(tmp_path.rglob("*")) == []


def test_post_to_unknown_path_is_rejected(served_attack):
    request = urllib.request.Request(served_attack + "elsewhere", data=b"x=1", method="POST")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request)
    assert error.value.code == 404


def test_attack_section_marked_simulation():
    from amwe.models import Attack, PhishingEmail

    attack = Attack(PhishingEmail("[SIMULATION] Verify", "body here", "deterministic"), "GitHub")
    page = render_html(result_with(), None, attack)

    assert "The attack this makes possible" in page
    assert "Simulation" in page
    assert 'href="/login"' in page


def test_attack_email_body_is_escaped():
    from amwe.models import Attack, PhishingEmail

    attack = Attack(PhishingEmail("s", "<img src=x>", "deterministic"), "GitHub")
    page = render_html(result_with(), None, attack)

    assert "<img src=x>" not in page
    assert "&lt;img src=x&gt;" in page
