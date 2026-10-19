<div align="center">

# AMWE

### Attack Me With Everything.

**See exactly what an attacker can build from your own public data — then watch them do it.**

[![CI](https://github.com/denis-mci/amwe/actions/workflows/ci.yml/badge.svg)](https://github.com/denis-mci/amwe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/amwe.svg)](https://pypi.org/project/amwe/)
[![Python](https://img.shields.io/pypi/pyversions/amwe.svg)](https://pypi.org/project/amwe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

AMWE points the tools of an attacker at **one person: you.** It gathers the traces
you leave in public, assembles them into the picture a stranger could build, and
then generates the phishing attack that picture makes possible — so you feel,
first-hand, how exposed you already are.

Everything it finds is public and legal to look up. That is the uncomfortable part.

```bash
uvx amwe you@example.com
```

That's it. No install, no API key, no account. Your data never leaves your machine.

## Why

Reconnaissance tools have always existed — `sherlock`, `maigret`, `holehe`,
`theHarvester`. They are powerful, fragmented, and pointed at *other people*.
AMWE bundles that power behind one command, points it at **yourself**, and turns
the raw hits into something you actually understand: a story, and then an attack.

## What it does

| Stage | What happens |
| --- | --- |
| **Verify** | Proves you own the target address. No proof, no scan. This is enforced in code, not just policy. |
| **Collect** | Runs every source module — accounts, leaks, metadata, public git identity — keyless and read-only. |
| **Profile** | Links the scattered hits into one readable picture, locally. No cloud, no key. |
| **Attack** | Builds the personalized phishing email an attacker would send you, plus a teaching login page that *never accepts input*. |
| **Report** | Renders it all as one shareable local page. |

## The attack it simulates

With `--attack`, AMWE turns the profile into the phishing email an attacker would
send you and a teaching login page styled after a service you actually use. Both
are shown to you in the local report and marked as a simulation in their own
content. AMWE sends nothing — there is no delivery path — and the login page
rejects every input, enforced by `form-action 'self'` and client-side
interception, not just a warning. Nothing you type into it is stored or sent.

## Install

```bash
# recommended — one command, nothing to install first
uvx amwe you@example.com

# or, as a persistent tool
pipx install amwe
```

A single-binary release and a Homebrew tap are on the roadmap.

## Usage

```bash
amwe you@example.com                 # scan your address
amwe you@example.com --username me   # check a specific handle too
amwe you@example.com --image-url https://example.com/me.jpg  # check a photo for GPS data
amwe you@example.com --report        # open the findings as a local web page
amwe you@example.com --attack        # also build the simulated phishing mail and login page
```

The profile — the attacker's view of you — is built on your machine from the findings. If a local [Ollama](https://ollama.com) model is running it writes the summary; otherwise AMWE assembles a deterministic one. Either way nothing leaves your machine, and the report says which path was used.

The report is served on `127.0.0.1` only and loads nothing from the network.
GPS findings link to your own map app via a `geo:` URI, not to an online map.

AMWE will only scan an address you can prove you control. See [LEGAL.md](LEGAL.md).

## Sources

Every collector is keyless, read-only, and queries only what a logged-out browser can see.

| Collector | Public source | Reports |
| --- | --- | --- |
| `exif` | A public photo URL you pass with `--image-url` | GPS coordinates embedded in the JPEG |
| `git-identity` | GitHub public events and commit metadata | Name and email stamped on your commits |
| `username` | Profile URLs on GitHub, GitLab, Instagram, Reddit, npm | Accounts that exist under your handle |

## The one rule

**AMWE scans you, or someone who has explicitly asked you to.** It is a mirror,
not a magnifying glass pointed at strangers. The ownership check is the core of
the project. Removing it is not a feature request — see [LEGAL.md](LEGAL.md).

## Contributing

New source modules are the heart of AMWE and the easiest way in — a collector is
a single small file. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[`good first issue`](https://github.com/denis-mci/amwe/labels/good%20first%20issue) label.

## License

[MIT](LICENSE). Built in the open.
