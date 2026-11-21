"""Restore complete known identities in original response coordinates, once."""

import re
from typing import Protocol

from pydantic import Field, SecretBytes, computed_field

from shield.contracts import Contract, Count, TokenMapping
from shield.pseudonym import TOKEN_LABELS, validate_token_identity

_LABELS = "|".join(TOKEN_LABELS.values())
_EXACT = re.compile(r"\[(?:" + _LABELS + r")_[A-Z2-7]{4,32}\]")
# Permit line wrapping within a label or suffix, but not arbitrary spaces that
# could swallow following prose after a bare token.
_BREAK = r"(?:[ \t]*\r?\n[ \t]*)?"
_LABEL_VARIANTS = "|".join(_BREAK.join(label) for label in TOKEN_LABELS.values())
_CORE = (
    r"(?:" + _LABEL_VARIANTS + r")"
    r"(?:[ \t\r\n]*[_-][ \t\r\n]*|[ \t\r\n]+)"
    r"[A-Z2-7](?:" + _BREAK + r"[A-Z2-7]){3,31}"
)
# Consume malformed single-bracket forms too, so they cannot be salvaged into a
# shorter bare match. Possessive closing brackets prevent backtracking into a
# bare identity before an unmatched bracket. Word boundaries prevent guesses.
_VARIANT = re.compile(
    r"(?<!\w)(?ai:\[[ \t\r\n]*" + _CORE + r"[ \t\r\n]*\]?+|" + _CORE + r"\]?+)(?!\w)",
)
_CANONICAL = re.compile(r"(" + _LABELS + r")[ _-]([A-Z2-7]{4,32})", re.ASCII)


_UNKNOWN_LABEL = re.compile(
    r"\[([A-Z][A-Z0-9]{0,31})[_ -]([A-Z2-7]{4,32})\]", re.I | re.ASCII
)


class MappingReader(Protocol):
    session_id: str

    @property
    def key(self) -> SecretBytes: ...
    def read_mapping(self, token: str) -> TokenMapping | None: ...


class RehydrationError(ValueError):
    def __init__(self):
        super().__init__("Response restoration failed.")


class RehydrationResult(Contract):
    text: str = Field(repr=False)
    exact_count: Count
    variant_count: Count
    unknown_token_count: Count

    @computed_field
    @property
    def restored_count(self) -> int:
        return self.exact_count + self.variant_count


def _canonical(value: str) -> str | None:
    if value.startswith("[") != value.endswith("]"):
        return None
    value = value.removeprefix("[").removesuffix("]").strip(" \t\r\n")
    # Newlines inside identity parts represent wrapping. A newline used as the
    # separator is retained as a space before collapsing the separator run.
    value = re.sub(r"[ \t\r\n]*[_-][ \t\r\n]*", "_", value)
    for label in TOKEN_LABELS.values():
        pattern = re.compile(r"^(?:" + _BREAK.join(label) + r")", re.I | re.ASCII)
        match = pattern.match(value)
        if match:
            tail = value[match.end() :]
            if not tail or tail[0] not in "_ \t\r\n":
                continue
            suffix = re.sub(r"[ \t\r\n]", "", tail[1:]).upper()
            normalized = label + "_" + suffix
            if _CANONICAL.fullmatch(normalized):
                return "[" + normalized + "]"
    return None


def rehydrate_text(text: str, session: MappingReader) -> RehydrationResult:
    """Exact known tokens win; tolerant matches require the same full identity.

    Markdown and possessive punctuation stay outside matches. Never rescan
    inserted originals, consult another session, or guess missing characters.
    Unknown candidate pairs remain unchanged. Caller retains scope through use.
    """
    try:
        if not isinstance(text, str) or not isinstance(session.key, SecretBytes):
            raise RehydrationError()
        replacements = []
        exact_ranges = []
        counts = [0, 0]
        unknown = 0
        cache = {}

        def original(token):
            if token not in cache:
                mapping = session.read_mapping(token)
                if mapping is not None:
                    if (
                        not isinstance(mapping, TokenMapping)
                        or mapping.session_id != session.session_id
                        or mapping.token != token
                    ):
                        raise RehydrationError()
                    validate_token_identity(
                        mapping.entity_type, mapping.entity_digest, token
                    )
                    cache[token] = mapping.original_value.get_secret_value()
                else:
                    cache[token] = None
            return cache[token]

        for match in _EXACT.finditer(text):
            value = original(match.group())
            exact_ranges.append(match.span())
            if value is not None:
                replacements.append((match.start(), match.end(), value))
                counts[0] += 1
            else:
                unknown += 1
        index = 0
        for match in _VARIANT.finditer(text):
            while index < len(exact_ranges) and exact_ranges[index][1] <= match.start():
                index += 1
            if index < len(exact_ranges) and exact_ranges[index][0] < match.end():
                continue
            token = _canonical(match.group())
            value = original(token) if token is not None else None
            if value is not None:
                replacements.append((match.start(), match.end(), value))
                counts[1] += 1
            elif token is not None:
                unknown += 1
        unknown += sum(
            match[1].upper() not in TOKEN_LABELS.values()
            for match in _UNKNOWN_LABEL.finditer(text)
        )
        chunks, cursor = [], 0
        for start, end, value in sorted(replacements):
            chunks.extend((text[cursor:start], value))
            cursor = end
        chunks.append(text[cursor:])
        return RehydrationResult(
            text="".join(chunks),
            exact_count=counts[0],
            variant_count=counts[1],
            unknown_token_count=unknown,
        )
    except Exception:
        raise RehydrationError() from None
