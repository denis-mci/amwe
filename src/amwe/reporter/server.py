"""Serves the report page on localhost, using only the standard library.

The server binds to the loopback interface so the report is reachable from this
machine alone.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

_LOOPBACK = "127.0.0.1"


def local_server(
    page: str, *, login_page: str | None = None, notice_page: str | None = None
) -> HTTPServer:
    """Bind a server for ``page`` to a free localhost port. The caller runs and closes it.

    When ``login_page`` is given, the teaching login page is served at ``/login``.
    A POST there (only possible if the page's scripts were disabled) is answered
    with ``notice_page`` and otherwise discarded: see :meth:`_ReportHandler.do_POST`.
    """
    report = page.encode()
    login = login_page.encode() if login_page is not None else None
    notice = (notice_page or "Nothing you submitted was stored or sent.").encode()

    class _ReportHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/":
                self._send(report)
            elif login is not None and self.path == "/login":
                self._send(login)
            else:
                self.send_error(404)

        def do_POST(self) -> None:
            # The teaching login page may reach here only with scripts disabled.
            # We never store or forward credentials: drain the body and drop it,
            # then show the notice. There is deliberately no persistence or sending.
            if login is None or self.path != "/login":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._send(notice)

        def _send(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass  # Keep the terminal for the scan output, not request logs.

    return HTTPServer((_LOOPBACK, 0), _ReportHandler)


def server_url(server: HTTPServer) -> str:
    """Return the address a browser should open for ``server``."""
    return f"http://{_LOOPBACK}:{server.server_port}/"
