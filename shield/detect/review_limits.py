"""Shared static local-review limits; no response content in exception messages."""

from pydantic import SecretStr

DEFAULT_MAX_OUTPUT_BYTES = 65536


class ReviewerUnavailable(ValueError):
    def __init__(self):
        super().__init__("Local reviewer is unavailable.")


class ReviewerOutputLimit(ReviewerUnavailable):
    pass


def checked_limit(limit):
    if type(limit) is not int or limit <= 0:
        raise ReviewerUnavailable()
    return limit


def check_output(output: SecretStr, limit: int = DEFAULT_MAX_OUTPUT_BYTES) -> str:
    checked_limit(limit)
    if not isinstance(output, SecretStr):
        raise ReviewerUnavailable()
    text = output.get_secret_value()
    # Reject huge strings before creating an equally huge UTF-8 allocation.
    if len(text) > limit or len(text.encode("utf-8")) > limit:
        raise ReviewerOutputLimit()
    return text
