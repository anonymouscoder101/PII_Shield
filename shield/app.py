"""ASGI scaffold. Protection and proxy endpoints are not implemented yet."""

from fastapi import FastAPI

from shield import __version__

app = FastAPI(
    title="PII Shield",
    description="Foundation scaffold. PII protection endpoints are not available yet.",
    version=__version__,
)
