"""Startup secrets remain separate from configuration and public serialization."""

import warnings

import pytest

from shield.__main__ import main
from shield.config import SessionsConfig, ShieldConfig, UpstreamConfig
from shield.credentials import (
    CredentialError,
    load_credentials,
    prompt_vault_passphrase,
)


@pytest.fixture
def config():
    return ShieldConfig(
        upstream=UpstreamConfig(api_key_env="SHIELD_SYNTHETIC_TEST_KEY")
    )


def test_ephemeral_startup_does_not_prompt_or_require_provider_key(config, monkeypatch):
    monkeypatch.delenv("SHIELD_SYNTHETIC_TEST_KEY", raising=False)

    def unexpected_prompt(*args):
        pytest.fail("Ephemeral startup must not prompt")

    monkeypatch.setattr("shield.credentials.getpass.getpass", unexpected_prompt)
    credentials = load_credentials(config)
    assert credentials.api_key is None
    assert credentials.vault_passphrase is None


def test_environment_key_and_prompted_passphrase_are_masked_and_not_serialized(
    config, monkeypatch
):
    key = "synthetic-provider-secret"
    passphrase = "  synthetic passphrase 🙂  "
    monkeypatch.setenv("SHIELD_SYNTHETIC_TEST_KEY", key)
    prompts = []
    monkeypatch.setattr(
        "shield.credentials.getpass.getpass",
        lambda prompt: prompts.append(prompt) or passphrase,
    )
    config = config.model_copy(
        update={"sessions": SessionsConfig(persistent_enabled=True)}
    )
    credentials = load_credentials(config)
    assert len(prompts) == 1
    assert credentials.api_key.get_secret_value() == key
    assert credentials.vault_passphrase.get_secret_value() == passphrase
    assert credentials.model_dump() == {}
    assert credentials.model_dump_json() == "{}"
    assert key not in repr(credentials)
    assert passphrase not in repr(credentials)


@pytest.mark.parametrize("value", ["", " ", "synthetic-key\n"])
def test_invalid_environment_key_is_not_echoed(config, monkeypatch, value):
    monkeypatch.setenv("SHIELD_SYNTHETIC_TEST_KEY", value)
    with pytest.raises(CredentialError) as caught:
        load_credentials(config)
    assert "synthetic-key" not in str(caught.value)


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_passphrase_is_rejected(monkeypatch, value):
    monkeypatch.setattr("shield.credentials.getpass.getpass", lambda prompt: value)
    with pytest.raises(CredentialError, match="must not be empty"):
        prompt_vault_passphrase()


def test_prompt_never_falls_back_to_echoed_input(monkeypatch, capsys):
    from getpass import GetPassWarning

    def fallback(prompt):
        warnings.warn("synthetic-sensitive-warning", GetPassWarning, stacklevel=2)
        pytest.fail("Fallback must be interrupted before reading echoed input")

    monkeypatch.setattr("shield.credentials.getpass.getpass", fallback)
    with pytest.raises(CredentialError, match="without echo") as caught:
        prompt_vault_passphrase()
    assert "synthetic-sensitive" not in str(caught.value)
    assert "synthetic-sensitive" not in capsys.readouterr().err


@pytest.mark.parametrize("failure", [EOFError, OSError])
def test_prompt_failures_do_not_expose_exception_text(monkeypatch, failure):
    def fail(prompt):
        raise failure("synthetic-sensitive-exception")

    monkeypatch.setattr("shield.credentials.getpass.getpass", fail)
    with pytest.raises(CredentialError) as caught:
        prompt_vault_passphrase()
    assert "synthetic-sensitive" not in str(caught.value)


def test_cli_wires_opt_in_prompt_and_environment_credentials(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text(
        "sessions: {persistent_enabled: true}\n"
        "upstream: {api_key_env: SHIELD_SYNTHETIC_TEST_KEY}\n"
    )
    monkeypatch.setenv("SHIELD_SYNTHETIC_TEST_KEY", "synthetic-key")
    monkeypatch.setattr("sys.argv", ["pii-shield", "--config", str(path)])
    monkeypatch.setattr(
        "shield.credentials.getpass.getpass", lambda prompt: "synthetic-passphrase"
    )
    calls = []
    monkeypatch.setattr(
        "shield.__main__.uvicorn.run", lambda app, **kw: calls.append(app)
    )
    main()
    assert calls[0].state.credentials.api_key.get_secret_value() == "synthetic-key"
    assert (
        calls[0].state.credentials.vault_passphrase.get_secret_value()
        == "synthetic-passphrase"
    )


def test_cli_aborts_on_passphrase_failure_without_starting_server(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "config.yaml"
    path.write_text("sessions: {persistent_enabled: true}")
    monkeypatch.setattr("sys.argv", ["pii-shield", "--config", str(path)])
    monkeypatch.delenv("UPSTREAM_API_KEY", raising=False)
    monkeypatch.setattr("shield.credentials.getpass.getpass", lambda prompt: "")
    calls = []
    monkeypatch.setattr("shield.__main__.uvicorn.run", lambda *a, **kw: calls.append(a))
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert calls == []
    assert "passphrase must not be empty" in capsys.readouterr().err
