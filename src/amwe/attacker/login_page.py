"""The teaching login page and the notice shown when someone submits it.

The page imitates a service the target actually uses, then refuses every input.
Two independent guards make leaking credentials impossible, by construction:
``form-action 'self'`` in the Content-Security-Policy, so the browser can only
ever post to the local AMWE server, and client-side interception that replaces
the form on the first input. The server that may receive a submission (if the
user disabled scripts) discards it; see :mod:`amwe.reporter.server`.
"""

from __future__ import annotations

from html import escape
from string import Template

INTERCEPTION_NOTICE = (
    "This is exactly how credentials are stolen. You just handed a username and "
    "password to a page you never verified. AMWE discarded them instantly and kept "
    "nothing - a real attacker would have everything. Nothing you typed was stored "
    "or sent anywhere."
)

_SIMULATION_BANNER = (
    "SIMULATION - this is an AMWE teaching page. It looks like a real login and "
    "never accepts input. Do not enter real credentials anywhere you did not reach "
    "on your own."
)

# script-src is needed for the interception guard; form-action 'self' means the
# browser cannot post these fields anywhere but the local AMWE server.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'"
)

_STYLE = (
    "body { font: 16px/1.5 system-ui, sans-serif; max-width: 22rem; margin: 3rem auto;"
    " padding: 0 1rem; } .banner { background: #c0392b; color: #fff; padding: 0.75rem;"
    " border-radius: 6px; font-weight: 600; } label { display: block; margin-top: 1rem; }"
    " input { width: 100%; padding: 0.5rem; box-sizing: border-box; } button { margin-top:"
    " 1rem; padding: 0.5rem 1rem; } .notice { background: #c0392b; color: #fff; padding: 1rem;"
    " border-radius: 6px; }"
)

# Any input or submit swaps the form for the notice, so nothing is ever posted.
_SCRIPT = (
    "const f=document.getElementById('login');"
    "const n=document.getElementById('notice');"
    "function stop(e){if(e)e.preventDefault();f.hidden=true;n.hidden=false;}"
    "f.addEventListener('submit',stop);"
    "f.addEventListener('input',stop);"
)

_LOGIN = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="$csp">
<title>Sign in to $service</title>
<style>$style</style>
</head>
<body>
<p class="banner">$banner</p>
<h1>Sign in to $service</h1>
<form id="login" action="/login" method="post" autocomplete="off">
<label>Username or email<input name="username" type="text"></label>
<label>Password<input name="password" type="password"></label>
<button type="submit">Sign in</button>
</form>
<div id="notice" class="notice" hidden>$notice</div>
<script>$script</script>
</body>
</html>
""")

_NOTICE_PAGE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Nothing was kept</title>
<style>$style</style>
</head>
<body>
<p class="banner">$banner</p>
<div class="notice">$notice</div>
</body>
</html>
""")


def render_login_page(service: str) -> str:
    """Return the teaching login page imitating ``service``. It never accepts input."""
    return _LOGIN.substitute(
        csp=_CSP,
        style=_STYLE,
        banner=_SIMULATION_BANNER,
        service=escape(service),
        notice=escape(INTERCEPTION_NOTICE),
        script=_SCRIPT,
    )


def render_interception_page() -> str:
    """Return the page served when a submission reaches the server despite the guards."""
    return _NOTICE_PAGE.substitute(
        style=_STYLE,
        banner=_SIMULATION_BANNER,
        notice=escape(INTERCEPTION_NOTICE),
    )
