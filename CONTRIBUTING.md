# Contributing to AMWE

Thanks for helping people see their own exposure. The most valuable contribution
is a new **collector** — a single source module. It is deliberately a small,
self-contained file so the barrier is low.

## Setup

```bash
git clone https://github.com/denis-mci/amwe
cd amwe
uv sync --extra dev        # or: pip install -e ".[dev]"
```

## Add a collector in three steps

1. Create `src/amwe/collectors/<source>.py`.
2. Implement the `Collector` protocol (see `collectors/username.py` for the
   smallest complete example) and `register()` your instance.
3. Add a test in `tests/` using `httpx.MockTransport` — no live network in CI.

A collector **must** be keyless, read-only, and touch only public sources. If it
needs a login, a key, or bypasses any access control, it does not belong here
(see [LEGAL.md](LEGAL.md)).

## Before you open a PR

```bash
ruff check . && ruff format --check .
mypy src
pytest
```

## PR workflow

- Branch from `main`, keep PRs focused (one collector or one fix).
- Fill in the PR template. Describe what source you add and how you tested it.
- CI must be green. A maintainer (or an automated reviewer such as Codex /
  Claude Code) will review; address comments by pushing follow-up commits.
- By contributing you agree your work is released under the project's MIT license.

## What gets declined

Anything that weakens the ownership gate, captures credentials, targets third
parties, or bypasses access controls. No exceptions.
