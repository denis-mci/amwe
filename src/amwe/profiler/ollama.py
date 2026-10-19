"""Minimal client for a local Ollama server. Keyless and localhost only.

Ollama serves an HTTP API on the loopback interface with no authentication.
AMWE uses it only when it is already running, never starts or installs it, and
never falls back to a remote service.
"""

from __future__ import annotations

import httpx

DEFAULT_HOST = "http://127.0.0.1:11434"
# Connect fast so a missing Ollama costs nothing; give a present model time to answer.
_TIMEOUT = httpx.Timeout(60.0, connect=2.0)
_OPTIONS = {"temperature": 0.2}


async def narrate(prompt: str, *, host: str = DEFAULT_HOST) -> str | None:
    """Return a local model's answer to ``prompt``, or None if no model is available."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        model = await _first_model(client, host)
        if model is None:
            return None
        return await _generate(client, host, model, prompt)


async def _first_model(client: httpx.AsyncClient, host: str) -> str | None:
    tags = await _get_json(client, f"{host}/api/tags")
    models = tags.get("models") if isinstance(tags, dict) else None
    if not isinstance(models, list):
        return None
    for entry in models:
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name:
            return name
    return None


async def _generate(client: httpx.AsyncClient, host: str, model: str, prompt: str) -> str | None:
    payload = {"model": model, "prompt": prompt, "stream": False, "options": _OPTIONS}
    try:
        response = await client.post(f"{host}/api/generate", json=payload)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    text = body.get("response") if isinstance(body, dict) else None
    if isinstance(text, str) and text.strip():
        return text.strip()
    return None


async def _get_json(client: httpx.AsyncClient, url: str) -> object:
    try:
        response = await client.get(url)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None
