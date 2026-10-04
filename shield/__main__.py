"""Start the package skeleton on the loopback interface."""

import uvicorn


def main() -> None:
    """Run the scaffold; configuration loading is a later foundation task."""
    uvicorn.run("shield.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
