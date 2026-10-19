"""Renders a :class:`ScanResult` as one self-contained HTML page.

The page loads nothing from the network — its Content-Security-Policy forbids
it — so opening the report never tells a third party what was found.
"""

from __future__ import annotations

from html import escape
from string import Template

from amwe.models import Finding, Profile, ScanResult, Severity

_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}

_PAGE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>AMWE report</title>
<style>
:root { color-scheme: light dark; }
body { font: 16px/1.5 system-ui, sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; }
ul { list-style: none; padding: 0; }
li { border-left: 4px solid #7f8c8d; padding: 0.5rem 0.75rem; margin: 0.5rem 0; }
li.high { border-color: #c0392b; }
li.medium { border-color: #d35400; }
li.low { border-color: #b7950b; }
.severity { font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
.source { opacity: 0.7; }
.map { display: block; margin-top: 0.25rem; }
.profile { background: rgba(127, 140, 141, 0.12); padding: 0.75rem 1rem; border-radius: 6px; }
.provenance { opacity: 0.6; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>What an attacker can already see about you</h1>
<p>Scan of <strong>$email</strong>: $count public traces found.
All of this is legal to look up — that is the point.</p>
$profile
<ul>
$items
</ul>
</body>
</html>
""")

_PROVENANCE = {
    "ollama": "Written by a local model on your machine.",
    "deterministic": "Assembled on your machine without a model — "
    "run a local Ollama model for a richer picture.",
}


def render_html(result: ScanResult, profile: Profile | None = None) -> str:
    """Return the report for ``result`` as a complete HTML document."""
    findings = sorted(result.findings, key=lambda f: _SEVERITY_RANK[f.severity], reverse=True)
    items = "\n".join(_finding_item(finding) for finding in findings)
    return _PAGE.substitute(
        email=escape(result.target.email),
        count=len(findings),
        profile=_profile_section(profile),
        items=items or "<li>No public traces found.</li>",
    )


def _profile_section(profile: Profile | None) -> str:
    if profile is None:
        return ""
    note = _PROVENANCE.get(profile.source, "")
    return (
        '<section class="profile"><h2>The picture this builds</h2>'
        f"<p>{escape(profile.summary)}</p>"
        f'<p class="provenance">{escape(note)}</p></section>'
    )


def _finding_item(finding: Finding) -> str:
    parts = [
        f'<span class="severity">{finding.severity}</span>',
        f'<span class="source">{escape(finding.source)}</span>',
        escape(finding.value),
    ]
    # Only web links: a URL comes from scan input and must never become a javascript: link.
    if finding.url and finding.url.startswith(("https://", "http://")):
        parts.append(f'<a href="{escape(finding.url)}" rel="noreferrer">source</a>')
    if finding.kind == "gps":
        parts.append(_map_hint(finding.value))
    return f'<li class="{finding.severity}">{" ".join(parts)}</li>'


def _map_hint(coordinates: str) -> str:
    geo = escape(coordinates.replace(" ", ""))
    return (
        f'<a class="map" href="geo:{geo}">Open this spot in your map app</a>'
        " — anyone who has the photo can see where it was taken."
    )
