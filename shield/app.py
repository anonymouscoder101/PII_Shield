"""ASGI scaffold. Protection and proxy endpoints are not implemented yet."""

from fastapi import FastAPI

from shield import __version__
from shield.config import ShieldConfig


def create_app(config: ShieldConfig | None = None) -> FastAPI:
    """Retain validated settings for future protection components."""
    app = FastAPI(
        title="PII Shield",
        description=(
            "Foundation scaffold. PII protection endpoints are not available yet."
        ),
        version=__version__,
    )
    app.state.config = config if config is not None else ShieldConfig()
    return app


app = create_app()
