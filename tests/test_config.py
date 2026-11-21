"""Configuration failures must stop startup without disclosing input values."""

from pathlib import Path

import pytest

from shield.__main__ import main
from shield.app import create_app
from shield.config import ConfigurationError, load_config


def write_config(tmp_path, text):
    path = tmp_path / "settings.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_default_file_uses_safe_defaults_without_creating_vault(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    default_vault = Path("~/.shield/vault.db").expanduser().resolve()
    vault_existed = default_vault.exists()
    config = load_config()

    assert config.server.host == "127.0.0.1"
    assert config.server.port == 8000
    assert str(config.upstream.base_url) == "http://127.0.0.1:8001/v1"
    assert config.upstream.timeout_s == 60
    assert config.detection.effective_threshold == 0.5
    assert config.sessions.default == "ephemeral"
    assert config.vault.path == default_vault
    assert config.vault.session_ttl_hours == 24
    assert default_vault.exists() == vault_existed


def test_example_loads_without_credentials_or_model_dependencies():
    config = load_config(Path(__file__).resolve().parents[1] / "shield.example.yaml")
    assert config.detection.mode == "balanced"
    assert config.detection.on_stage2_failure == "fail_closed"
    assert config.detection.stage2_max_output_bytes == 65536
    assert config.vault.argon2.memory_kib == 65536
    assert config.upstream.api_key_env == "UPSTREAM_API_KEY"
    assert create_app(config).state.config is config


def test_request_limits_are_loaded_from_yaml(tmp_path):
    config = load_config(
        write_config(
            tmp_path, "server: {max_request_bytes: 4096, request_timeout_s: 2.5}"
        )
    )
    assert config.server.max_request_bytes == 4096
    assert config.server.request_timeout_s == 2.5


@pytest.mark.parametrize(
    "settings",
    [
        "max_request_bytes: 0",
        "max_request_bytes: -1",
        "max_request_bytes: true",
        "max_request_bytes: 1.5",
        "max_request_bytes: '1024'",
        "request_timeout_s: 0",
        "request_timeout_s: -1",
        "request_timeout_s: .nan",
        "request_timeout_s: .inf",
        "request_timeout_s: true",
    ],
)
def test_invalid_request_limits_fail_configuration(tmp_path, settings):
    with pytest.raises(ConfigurationError):
        load_config(write_config(tmp_path, f"server: {{{settings}}}"))


@pytest.mark.parametrize(
    "mode,expected", [("fast", 0.6), ("balanced", 0.5), ("paranoid", 0.3)]
)
def test_mode_defaults_and_explicit_threshold_precedence(tmp_path, mode, expected):
    path = write_config(tmp_path, f"detection:\n  mode: {mode}\n")
    assert load_config(path).detection.effective_threshold == expected
    for threshold in [0, 0.7, 1]:
        path.write_text(f"detection:\n  mode: {mode}\n  threshold: {threshold}\n")
        assert load_config(path).detection.effective_threshold == threshold


def test_default_file_is_loaded_and_relative_vault_path_uses_its_directory(
    tmp_path, monkeypatch
):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    path = write_config(
        config_dir,
        "vault:\n  path: data/vault.db\n  session_ttl_hours: 0.5\n"
        "server:\n  port: 8123\n"
        "detection:\n  allowlist: ['Synthetic Organization', '李 Example']\n",
    )
    config = load_config(path)
    assert config.vault.path == config_dir / "data" / "vault.db"
    assert not config.vault.path.parent.exists()
    assert config.vault.session_ttl_hours == 0.5
    assert config.detection.allowlist == ["Synthetic Organization", "李 Example"]
    path.rename(config_dir / "shield.yaml")
    monkeypatch.chdir(config_dir)
    assert load_config().server.port == 8123


@pytest.mark.parametrize(
    "yaml_text,field",
    [
        ("upstream: {base_url: 'ftp://example.test/v1'}", "upstream.base_url"),
        (
            "upstream: {base_url: 'https://user:synthetic-secret@example.test/v1'}",
            "upstream",
        ),
        (
            "upstream: {base_url: 'https://example.test/v1?key=synthetic-secret'}",
            "upstream",
        ),
        (
            "upstream: {base_url: 'https://example.test/v1#synthetic-secret'}",
            "upstream",
        ),
        ("upstream: {base_url: ' https://example.test/v1'}", "upstream.base_url"),
        ("upstream: {timeout_s: 0}", "upstream.timeout_s"),
        ("upstream: {timeout_s: .inf}", "upstream.timeout_s"),
        ("upstream: {api_key_env: 'bad-name'}", "upstream.api_key_env"),
        ("detection: {mode: unknown}", "detection.mode"),
        ("detection: {threshold: -0.1}", "detection.threshold"),
        ("detection: {threshold: 1.1}", "detection.threshold"),
        ("detection: {threshold: .nan}", "detection.threshold"),
        ("detection: {threshold: true}", "detection.threshold"),
        ("detection: {allowlist: ['  ']}", "detection.allowlist"),
        ("detection: {allowlist: [42]}", "detection.allowlist"),
        ("detection: {allowlist: 'Synthetic Organization'}", "detection.allowlist"),
        ("detection: {stage2_timeout_s: -1}", "detection.stage2_timeout_s"),
        (
            "detection: {stage2_max_output_bytes: 0}",
            "detection.stage2_max_output_bytes",
        ),
        (
            "detection: {stage2_max_output_bytes: true}",
            "detection.stage2_max_output_bytes",
        ),
        ("detection: {on_stage2_failure: ignore}", "detection.on_stage2_failure"),
        ("vault: {path: ''}", "vault.path"),
        ("vault: {session_ttl_hours: 0}", "vault.session_ttl_hours"),
        ("vault: {argon2: {memory_kib: 8, parallelism: 4}}", "vault.argon2"),
        ("vault: {argon2: {time_cost: 0}}", "vault.argon2.time_cost"),
        ("sessions: {default: persistent}", "sessions.default"),
        ("server: {host: '0.0.0.0'}", "server.host"),
        ("server: {host: '192.0.2.1'}", "server.host"),
        ("server: {port: 0}", "server.port"),
        ("server: {port: 65536}", "server.port"),
        ("server: {port: true}", "server.port"),
        ("server: {port: '8000'}", "server.port"),
        ("upstream: {api_key: synthetic-secret}", "upstream.<unknown>"),
        ("vault: {passphrase: synthetic-secret}", "vault.<unknown>"),
        ("synthetic-secret: unexpected", "<unknown>"),
    ],
)
def test_invalid_settings_rejected_without_echoing_values(tmp_path, yaml_text, field):
    with pytest.raises(ConfigurationError) as caught:
        load_config(write_config(tmp_path, yaml_text))
    assert field in str(caught.value)
    assert "synthetic-secret" not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "null",
        "- synthetic-secret",
        "synthetic-secret: [",
        "server: {port: 8000, port: 8123}",
        "!!python/object/apply:os.system ['synthetic-secret']",
        "? [synthetic-secret]\n: value",
    ],
)
def test_invalid_yaml_and_duplicate_keys_rejected(tmp_path, text):
    with pytest.raises(ConfigurationError) as caught:
        load_config(write_config(tmp_path, text))
    assert "synthetic-secret" not in str(caught.value)


def test_explicit_missing_or_unreadable_files_fail(tmp_path):
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_config(tmp_path / "missing.yaml")
    with pytest.raises(ConfigurationError, match="cannot be read"):
        load_config(tmp_path)
    path = tmp_path / "invalid.yaml"
    path.write_bytes(b"\xff")
    with pytest.raises(ConfigurationError, match="cannot be read"):
        load_config(path)


def test_vault_path_cannot_be_an_existing_directory(tmp_path):
    with pytest.raises(ConfigurationError, match="Vault path must refer to a file"):
        load_config(write_config(tmp_path, "vault: {path: '.'}"))


def test_cli_passes_configured_port_and_settings_to_server(tmp_path, monkeypatch):
    path = write_config(tmp_path, "server: {port: 8123}\ndetection: {mode: fast}")
    monkeypatch.setattr("sys.argv", ["pii-shield", "--config", str(path)])
    calls = []
    monkeypatch.setattr(
        "shield.__main__.uvicorn.run", lambda *a, **kw: calls.append((a, kw))
    )
    main()
    ((args, kwargs),) = calls
    assert kwargs == {
        "host": "127.0.0.1",
        "port": 8123,
        "access_log": False,
        "log_level": "info",
    }
    assert args[0].state.config.detection.effective_threshold == 0.6


def test_invalid_cli_configuration_never_starts_server(tmp_path, monkeypatch, capsys):
    path = write_config(tmp_path, "server: {host: synthetic-secret}")
    monkeypatch.setattr("sys.argv", ["pii-shield", "--config", str(path)])
    calls = []
    monkeypatch.setattr(
        "shield.__main__.uvicorn.run", lambda *a, **kw: calls.append((a, kw))
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert calls == []
    stderr = capsys.readouterr().err
    assert "server.host" in stderr
    assert "synthetic-secret" not in stderr
