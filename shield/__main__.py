"""Start the localhost scaffold with validated configuration."""

import argparse
from pathlib import Path

import uvicorn

from shield.app import create_app
from shield.config import ConfigurationError, load_config
from shield.credentials import CredentialError, load_credentials


def main() -> None:
    """Validate settings before starting the server."""
    parser = argparse.ArgumentParser(description="PII Shield localhost scaffold")
    parser.add_argument(
        "--config", type=Path, help="YAML config file (default: optional ./shield.yaml)"
    )
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        credentials = load_credentials(config)
    except (ConfigurationError, CredentialError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        parser.exit(130, "Startup cancelled.\n")
    app = create_app(config, credentials)
    del credentials  # Lifespan owns the startup reference until authentication.
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
    )


if __name__ == "__main__":
    main()
