from collections.abc import Callable
from typing import Any

import httpx
import pytest

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> Callable[[Handler], None]:
    """Route every ``httpx.AsyncClient`` created during the test through ``handler``."""
    original = httpx.AsyncClient

    def install(handler: Handler) -> None:
        transport = httpx.MockTransport(handler)

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return original(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", patched)

    return install
