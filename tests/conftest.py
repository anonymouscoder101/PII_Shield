"""Keep application tests independent of a live local model.

Mode tests supply specific reviewer factories. Adapter tests exercise their own
mock HTTP/SDK clients; the explicit benchmark is the only live inference runner.
"""

import pytest
from pydantic import SecretStr


class EmptyLocalReviewer:
    async def review(self, text):
        return SecretStr('{"spans":[]}')

    async def aclose(self):
        pass


@pytest.fixture(autouse=True)
def isolate_default_local_reviewer(monkeypatch):
    monkeypatch.setattr(
        "shield.processing.default_reviewer", lambda config: EmptyLocalReviewer()
    )
