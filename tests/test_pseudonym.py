"""Synthetic normalization and deterministic HMAC derivation; no storage or model."""

import base64
import hashlib
import hmac

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretBytes, SecretStr

from shield.contracts import EntityType
from shield.pseudonym import (
    TOKEN_LABELS,
    PseudonymError,
    derive_token,
    normalize_entity,
)
from shield.session import ephemeral_session

KEY = SecretBytes(bytes(range(32)))


def norm(entity, value):
    return normalize_entity(entity, SecretStr(value)).get_secret_value()


@pytest.mark.parametrize(
    "entity,first,second",
    [
        (EntityType.PERSON, "  JOSÉ\tSmith ", "Jose\u0301 smith"),
        (EntityType.LOCATION, " New\nYork ", "new york"),
        (EntityType.ADDRESS, " 123  Example Street ", "123 example street"),
        (EntityType.DATE_OF_BIRTH, "14  JUNE 1990", "14 june 1990"),
        (EntityType.PHONE_NUMBER, "+1 (202) 555-0147", "1-202-555-0147"),
        (EntityType.PHONE_NUMBER, "+١ ٢٠٢ ٥٥٥ ٠١٤٧", "12025550147"),
        (EntityType.CREDIT_CARD, "4111 1111 1111 1111", "4111-1111-1111-1111"),
        (EntityType.US_SSN, "219-09-9999", "219.09.9999"),
        (EntityType.EMAIL_ADDRESS, "Synthetic@EXAMPLE.TEST", "Synthetic@example.test"),
        (
            EntityType.IP_ADDRESS,
            "2001:0DB8:0000:0000:0000:0000:0000:0042",
            "2001:db8::42",
        ),
    ],
)
def test_defined_formatting_variants_have_same_digest(entity, first, second):
    assert norm(entity, first) == norm(entity, second)
    assert derive_token(entity, SecretStr(first), KEY) == derive_token(
        entity, SecretStr(second), KEY
    )


@pytest.mark.parametrize(
    "entity", [EntityType.API_KEY, EntityType.SECRET, EntityType.EMPLOYEE_ID]
)
def test_case_sensitive_identifiers_are_preserved_verbatim(entity):
    for value in ["AbC123", " abc123 ", "é", "e\u0301", "\tAbC123\n"]:
        assert norm(entity, value) == value
    assert (
        derive_token(entity, SecretStr("AbC123"), KEY).entity_digest
        != derive_token(entity, SecretStr("abc123"), KEY).entity_digest
    )
    assert (
        derive_token(entity, SecretStr("abc123 "), KEY).entity_digest
        != derive_token(entity, SecretStr("abc123"), KEY).entity_digest
    )


def test_email_local_part_remains_case_sensitive():
    assert norm(EntityType.EMAIL_ADDRESS, "Name@example.test") != norm(
        EntityType.EMAIL_ADDRESS, "name@example.test"
    )
    assert norm(EntityType.EMAIL_ADDRESS, "name@faß.test") != norm(
        EntityType.EMAIL_ADDRESS, "name@fass.test"
    )


def test_phone_extensions_do_not_alias_longer_numbers():
    assert norm(EntityType.PHONE_NUMBER, "202-555-0147 ext. 9") == norm(
        EntityType.PHONE_NUMBER, "2025550147 x9"
    )
    assert norm(EntityType.PHONE_NUMBER, "2025550147 x9") != norm(
        EntityType.PHONE_NUMBER, "20255501479"
    )


def test_conservative_numeric_fallback_does_not_erase_merged_text():
    assert norm(EntityType.CREDIT_CARD, "Synthetic 4111") != norm(
        EntityType.CREDIT_CARD, "Other 4111"
    )
    assert norm(EntityType.CREDIT_CARD, "Synthetic 4111") != norm(
        EntityType.CREDIT_CARD, "4111"
    )
    assert norm(EntityType.PHONE_NUMBER, "020 7946 0958") != norm(
        EntityType.PHONE_NUMBER, "+44 20 7946 0958"
    )


def test_ip_prefix_zone_and_ambiguous_date_identity_are_preserved():
    assert norm(EntityType.IP_ADDRESS, "192.0.2.14/24") != norm(
        EntityType.IP_ADDRESS, "192.0.2.14"
    )
    assert norm(EntityType.IP_ADDRESS, "fe80::1%Eth0") != norm(
        EntityType.IP_ADDRESS, "fe80::1%eth0"
    )
    assert norm(EntityType.DATE_OF_BIRTH, "01/02/1990") != norm(
        EntityType.DATE_OF_BIRTH, "02/01/1990"
    )


def test_hmac_known_input_and_full_digest_match_document_format():
    derived = derive_token(EntityType.PERSON, SecretStr(" Alice "), KEY)
    expected = hmac.new(bytes(range(32)), b"PERSON\x00alice", hashlib.sha256).digest()
    assert derived.entity_digest == expected
    assert len(derived.entity_digest) == 32
    assert derived.token == "[PERSON_" + base64.b32encode(expected).decode()[:4] + "]"
    email = derive_token(EntityType.EMAIL_ADDRESS, SecretStr("Name@EXAMPLE.TEST"), KEY)
    assert (
        email.entity_digest
        == hmac.new(
            bytes(range(32)), b"EMAIL_ADDRESS\0Name@example.test", hashlib.sha256
        ).digest()
    )


def test_all_types_have_stable_distinct_labels_and_domains():
    expected = dict(
        PERSON="PERSON",
        EMAIL_ADDRESS="EMAIL",
        PHONE_NUMBER="PHONE",
        CREDIT_CARD="CARD",
        US_SSN="SSN",
        LOCATION="LOCATION",
        ADDRESS="ADDRESS",
        IP_ADDRESS="IP",
        DATE_OF_BIRTH="DOB",
        API_KEY="APIKEY",
        SECRET="SECRET",
        EMPLOYEE_ID="EMPLOYEE",
    )
    assert dict(TOKEN_LABELS) == {
        EntityType(name): label for name, label in expected.items()
    }
    values = [
        derive_token(entity, SecretStr("Synthetic"), KEY) for entity in EntityType
    ]
    assert len({value.entity_digest for value in values}) == len(EntityType)
    assert all(
        value.token.startswith("[" + TOKEN_LABELS[value.entity_type] + "_")
        for value in values
    )
    with pytest.raises(TypeError):
        TOKEN_LABELS[EntityType.PERSON] = "OTHER"


def test_ephemeral_keys_produce_independent_digests_without_writes(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    with ephemeral_session() as one, ephemeral_session() as two:
        assert (
            derive_token(
                EntityType.PERSON, SecretStr("Synthetic"), one.key
            ).entity_digest
            != derive_token(
                EntityType.PERSON, SecretStr("Synthetic"), two.key
            ).entity_digest
        )
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("length", [4, 6, 8, 32])
def test_requested_suffix_is_prefix_of_full_unpadded_base32(length):
    derived = derive_token(
        EntityType.SECRET, SecretStr("Synthetic"), KEY, suffix_length=length
    )
    suffix = derived.token.removeprefix("[SECRET_").removesuffix("]")
    assert (
        suffix == base64.b32encode(derived.entity_digest).decode().rstrip("=")[:length]
    )
    assert "=" not in derived.token


@pytest.mark.parametrize("length", [0, 3, 33, 52, True, 4.0])
def test_invalid_suffix_lengths_fail_safely(length):
    with pytest.raises(PseudonymError):
        derive_token(
            EntityType.SECRET, SecretStr("Synthetic"), KEY, suffix_length=length
        )


@pytest.mark.parametrize("length", [16, 24, 31, 33])
def test_session_key_must_have_exactly_32_bytes(length):
    with pytest.raises(PseudonymError):
        derive_token(
            EntityType.SECRET, SecretStr("Synthetic"), SecretBytes(b"k" * length)
        )


def test_secret_values_and_digests_are_not_in_representation_or_dump(caplog):
    derived = derive_token(EntityType.SECRET, SecretStr("Synthetic private token"), KEY)
    assert "Synthetic private token" not in repr(derived)
    assert derived.entity_digest.hex() not in repr(derived)
    assert "entity_digest" not in derived.model_dump()
    assert "Synthetic private token" not in repr(
        normalize_entity(EntityType.SECRET, SecretStr("Synthetic private token"))
    )
    assert not caplog.text


@pytest.mark.parametrize(
    "entity,value",
    [
        ("PERSON", SecretStr("Synthetic")),
        (EntityType.PERSON, "Synthetic"),
        (EntityType.PERSON, SecretStr("")),
        (EntityType.PERSON, SecretStr("  ")),
    ],
)
def test_invalid_inputs_do_not_echo_values(entity, value):
    with pytest.raises(PseudonymError) as error:
        derive_token(entity, value, KEY)
    assert str(error.value) == "Pseudonym derivation failed."


@pytest.mark.parametrize(
    "entity,value",
    [
        (EntityType.PHONE_NUMBER, "Synthetic 2025550147"),
        (EntityType.CREDIT_CARD, "Synthetic 4111"),
        (EntityType.EMAIL_ADDRESS, "Synthetic <person@example.test>"),
        (EntityType.IP_ADDRESS, "Synthetic 192.0.2.14"),
    ],
)
def test_unsupported_format_fallback_is_idempotent(entity, value):
    canonical = norm(entity, value)
    assert norm(entity, canonical) == canonical


def test_ipv6_zone_with_prefix_is_not_discarded():
    assert norm(EntityType.IP_ADDRESS, "fe80::1%Eth0/64") != norm(
        EntityType.IP_ADDRESS, "fe80::1%eth0/64"
    )
    assert norm(EntityType.IP_ADDRESS, "fe80::1%Eth0/64") != norm(
        EntityType.IP_ADDRESS, "fe80::1/64"
    )


@given(
    st.sampled_from(list(EntityType)),
    st.text(min_size=1, max_size=40).filter(lambda value: bool(value.strip())),
)
def test_normalization_is_idempotent_for_nonblank_values(entity, value):
    canonical = norm(entity, value)
    assert norm(entity, canonical) == canonical


def test_token_format_never_exports_the_full_digest():
    with pytest.raises(PseudonymError):
        derive_token(EntityType.PERSON, SecretStr("Synthetic"), KEY, suffix_length=52)


def test_suffix_can_be_extended_using_only_full_digest():
    from shield.pseudonym import format_token

    derived = derive_token(EntityType.PERSON, SecretStr("Synthetic"), KEY)
    extended = format_token(derived.entity_type, derived.entity_digest, suffix_length=6)
    assert extended.startswith(derived.token[:-1])
    assert len(extended) == len(derived.token) + 2
    with pytest.raises(PseudonymError):
        format_token(EntityType.PERSON, derived.entity_digest[:4])
