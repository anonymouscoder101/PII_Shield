"""Session-scoped deterministic restoration using synthetic originals."""

import pytest
from pydantic import SecretStr

from shield.contracts import EntityType
from shield.session import ephemeral_session


def allocated(state, value="Alice", entity=EntityType.PERSON):
    return state.allocate(entity, SecretStr(value)).token


@pytest.mark.parametrize(
    "variant",
    [
        lambda t: t,
        lambda t: t.lower(),
        lambda t: t[1:-1],
        lambda t: t.replace("_", "-"),
        lambda t: t.replace("_", " "),
        lambda t: t.replace("_", "\n"),
        lambda t: t.replace("_", " _\n "),
        lambda t: t[:4] + "\n" + t[4:],
        lambda t: t[:-3] + "\n" + t[-3:],
        lambda t: "[ " + t[1:-1] + " ]",
    ],
)
def test_supported_variants_restore_first_spelling(variant):
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state, "Alice Example")
        result = rehydrate_text("Meet " + variant(token) + ".", state)
        assert result.text == "Meet Alice Example."
        assert result.restored_count == 1
        assert "Alice" not in repr(result)


def test_markdown_possessives_and_multiple_tokens():
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state)
        email = allocated(state, "synthetic@example.test", EntityType.EMAIL_ADDRESS)
        text = f"**{token}**'s `{email.lower()}` and {token[1:-1]}’s notes"
        result = rehydrate_text(text, state)
        assert result.text == "**Alice**'s `synthetic@example.test` and Alice’s notes"
        assert result.exact_count == 1 and result.variant_count == 2


def test_complete_pairs_only_no_fuzzy_or_partial_matching():
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state)
        core = token[1:-1]
        values = [
            token.replace("PERSON", "EMAIL"),
            token.replace("PERSON", "PERS0N"),
            core + "A",
            "prefix" + core,
            core + "_suffix",
            core + "0",
            token[:-2] + "]",
            token[:-1],
            token[1:],
        ]
        for text in values:
            assert rehydrate_text(text, state).text == text


def test_cross_session_and_unknown_tokens_are_unchanged():
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as first, ephemeral_session() as second:
        token = allocated(first)
        allocated(second, "Different Person")
        assert rehydrate_text(token, second).text == token
        assert rehydrate_text("[PERSON_ABCD]", second).text == "[PERSON_ABCD]"


def test_restored_values_are_never_rescanned():
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        inner = allocated(state, "Nested Value")
        outer = allocated(state, "Literal " + inner)
        result = rehydrate_text(outer + " " + inner, state)
        assert result.text == "Literal " + inner + " Nested Value"
        assert result.restored_count == 2


def test_closed_session_fails_even_for_empty_text():
    from shield.rehydrate import RehydrationError, rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state)
    for text in (token, ""):
        with pytest.raises(RehydrationError, match="Response restoration failed"):
            rehydrate_text(text, state)


def test_unicode_word_boundaries_and_confusables_are_not_guesses():
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state)
        bare = token[1:-1]
        for text in ("é" + bare, bare + "é", bare.replace("S", "ſ")):
            assert rehydrate_text(text, state).text == text


def test_persistent_restoration_after_restart_is_scoped(tmp_path):
    from shield.config import Argon2Config, VaultConfig
    from shield.persistent import PersistentSessions
    from shield.rehydrate import rehydrate_text

    config = VaultConfig(
        path=tmp_path / "vault.db",
        argon2=Argon2Config(memory_kib=32, time_cost=1, parallelism=1),
    )
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        sid = service.create().session_id
        other = service.create().session_id
        with service.use(sid) as state:
            token = allocated(state, "Alice Example")
    with PersistentSessions.open(config, SecretStr("synthetic")) as service:
        with service.use(sid) as state:
            assert rehydrate_text(token.lower(), state).text == "Alice Example"
        with service.use(other) as state:
            assert rehydrate_text(token, state).text == token


def test_invalid_mapping_and_lookup_failures_are_static(monkeypatch):
    from shield.rehydrate import RehydrationError, rehydrate_text
    from shield.session import EphemeralSession

    with ephemeral_session() as state:
        token = allocated(state)

        def failed(self, token):
            raise RuntimeError("private original Alice")

        monkeypatch.setattr(EphemeralSession, "read_mapping", failed)
        with pytest.raises(RehydrationError) as error:
            rehydrate_text(token, state)
        assert "Alice" not in str(error.value)


@pytest.mark.parametrize("suffix", ["suffix", "é", "_suffix"])
def test_unmatched_closing_bracket_cannot_backtrack_to_bare_match(suffix):
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state)
        malformed = token[1:] + suffix
        assert rehydrate_text(malformed, state).text == malformed


@pytest.mark.parametrize(
    "unknown", ["[PERSON_ABCD]", "person-abcd", "[ Person ABCD ]", "[ALIEN_ABCD]"]
)
def test_unknown_occurrences_count_without_changing_text(unknown):
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state)
        text = token + " / " + unknown + " / " + unknown
        result = rehydrate_text(text, state)
        assert result.text == "Alice / " + unknown + " / " + unknown
        assert result.restored_count == 1 and result.unknown_token_count == 2


def test_inserted_token_literals_are_not_counted_as_unknown():
    from shield.rehydrate import rehydrate_text

    with ephemeral_session() as state:
        token = allocated(state, "Literal [PERSON_ABCD]")
        result = rehydrate_text(token, state)
        assert result.text == "Literal [PERSON_ABCD]"
        assert result.unknown_token_count == 0
