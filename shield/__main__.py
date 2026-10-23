"""Start the localhost scaffold with validated configuration."""

import argparse
from pathlib import Path

import uvicorn

from shield.app import create_app
from shield.config import ConfigurationError, load_config


def main() -> None:
    """Validate settings before starting the server."""
    parser = argparse.ArgumentParser(description="PII Shield localhost scaffold")
    parser.add_argument(
        "--config", type=Path, help="YAML config file (default: optional ./shield.yaml)"
    )
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except ConfigurationError as exc:
        parser.error(str(exc))
    uvicorn.run(create_app(config), host=config.server.host, port=config.server.port)


if __name__ == "__main__":
    main()
