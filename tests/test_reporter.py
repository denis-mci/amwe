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
