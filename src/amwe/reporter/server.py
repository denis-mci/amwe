"""Serves the report page on localhost, using only the standard library.

The server binds to the loopback interface so the report is reachable from this
machine alone.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

_LOOPBACK = "127.0.0.1"


def local_server(page: str) -> HTTPServer:
    """Bind a server for ``page`` to a free localhost port. The caller runs and closes it."""
    body = page.encode()

    class _ReportHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/":
                self.send_error(404)
                return
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
