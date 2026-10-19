"""The reporter stage: one self-contained HTML page, served on localhost."""

from amwe.reporter.page import render_html
from amwe.reporter.server import local_server, server_url

__all__ = ["local_server", "render_html", "server_url"]
