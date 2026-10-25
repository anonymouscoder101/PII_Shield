"""Validated YAML settings. Loading never opens a vault or contacts an upstream."""

from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import Field, HttpUrl, ValidationError, field_validator, model_validator

from shield.contracts import Contract

PositiveDuration = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonBlankString = Annotated[str, Field(min_length=1, pattern=r"\S")]


class UpstreamConfig(Contract):
    base_url: HttpUrl = Field(default=HttpUrl("http://127.0.0.1:8001/v1"), repr=False)
    api_key_env: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")] = (
        "UPSTREAM_API_KEY"
    )
    timeout_s: PositiveDuration = 60.0

    @field_validator("base_url", mode="before")
    @classmethod
    def no_url_whitespace(cls, value: object) -> object:
        if isinstance(value, str) and any(char.isspace() for char in value):
            raise ValueError("upstream URL must not contain whitespace")
        return value

    @model_validator(mode="after")
    def no_embedded_credentials(self) -> Self:
        if self.base_url.username is not None or self.base_url.password is not None:
            raise ValueError("upstream URL must not contain credentials")
        if self.base_url.query is not None or self.base_url.fragment is not None:
            raise ValueError("upstream URL must not contain a query or fragment")
        return self


class DetectionConfig(Contract):
    mode: Literal["fast", "balanced", "paranoid"] = "balanced"
    threshold: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None
    allowlist: list[NonBlankString] = Field(default_factory=list)
    stage2_model: NonBlankString = "llama3.1:8b"
    stage2_timeout_s: PositiveDuration = 10.0
    on_stage2_failure: Literal["fail_closed", "fail_open"] = "fail_closed"

    @property
    def effective_threshold(self) -> float:
        """Explicit values, including zero, override the selected mode default."""
        if self.threshold is not None:
            return self.threshold
        return {"fast": 0.6, "balanced": 0.5, "paranoid": 0.3}[self.mode]


class Argon2Config(Contract):
    memory_kib: Annotated[int, Field(ge=8)] = 65536
    time_cost: Annotated[int, Field(ge=1)] = 3
    parallelism: Annotated[int, Field(ge=1)] = 4

    @model_validator(mode="after")
    def sufficient_memory(self) -> Self:
        if self.memory_kib < 8 * self.parallelism:
            raise ValueError("Argon2 memory_kib must be at least 8 times parallelism")
        return self


class VaultConfig(Contract):
    path: Path = Path("~/.shield/vault.db")
    session_ttl_hours: PositiveDuration = 24.0
    argon2: Argon2Config = Field(default_factory=Argon2Config)

    @field_validator("path", mode="before")
    @classmethod
    def parse_path(cls, value: object) -> Path:
        if isinstance(value, Path):
            return value
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError("vault path must be a nonempty filesystem path")
        return Path(value)


class SessionsConfig(Contract):
    default: Literal["ephemeral"] = "ephemeral"
    persistent_enabled: bool = False


class ServerConfig(Contract):
    # The supported deployment is a single-user IPv4 localhost service.
    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65535)] = 8000


class ShieldConfig(Contract):
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    sessions: SessionsConfig = Field(default_factory=SessionsConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)


class ConfigurationError(ValueError):
    """Startup failure whose message does not contain configuration values."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate keys instead of silently replacing an earlier setting."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError:
                raise yaml.constructor.ConstructorError(
                    None, None, "invalid mapping key", key_node.start_mark
                ) from None
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate mapping key", key_node.start_mark
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


_CONFIG_MODELS = (
    ShieldConfig,
    UpstreamConfig,
    DetectionConfig,
    VaultConfig,
    Argon2Config,
    SessionsConfig,
    ServerConfig,
)
_FIELD_NAMES = {name for model in _CONFIG_MODELS for name in model.model_fields}


def load_config(path: str | Path | None = None) -> ShieldConfig:
    """Load an explicit file, optional cwd/shield.yaml, or built-in defaults.

    Relative vault paths resolve beside the YAML file (cwd for built-in defaults).
    Tildes expand without creating directories. Credentials are never read here.
    """
    try:
        config_path = (
            Path(path).expanduser() if path is not None else Path("shield.yaml")
        )
    except OSError, RuntimeError, ValueError:
        raise ConfigurationError(
            "Configuration file path cannot be resolved."
        ) from None
    data = {}
    try:
        with config_path.open(encoding="utf-8") as source:
            data = yaml.load(source, Loader=_UniqueKeyLoader)
    except FileNotFoundError:
        if path is not None:
            raise ConfigurationError("Configuration file does not exist.") from None
    except OSError, UnicodeError, ValueError:
        raise ConfigurationError("Configuration file cannot be read.") from None
    except yaml.YAMLError, RecursionError:
        # YAML exceptions can include source lines, including accidental secrets.
        raise ConfigurationError(
            "Invalid YAML configuration; use a mapping with unique keys."
        ) from None

    if not isinstance(data, dict):
        raise ConfigurationError("Configuration must be a YAML mapping.")
    try:
        config = ShieldConfig.model_validate(data)
    except ValidationError as exc:
        problems = []
        for error in exc.errors(include_input=False, include_context=False):
            # Unknown key names may themselves contain sensitive text.
            location = ".".join(
                str(part) if part in _FIELD_NAMES else "<unknown>"
                for part in error["loc"]
            )
            problems.append(f"{location or 'configuration'}: {error['msg']}")
        raise ConfigurationError(
            "Invalid configuration: " + "; ".join(problems)
        ) from None

    try:
        vault_path = config.vault.path.expanduser()
        if not vault_path.is_absolute():
            vault_path = config_path.absolute().parent / vault_path
        vault_path = vault_path.resolve()
        if vault_path.is_dir():
            raise ConfigurationError("Vault path must refer to a file.")
    except OSError, RuntimeError:
        raise ConfigurationError("Vault path cannot be resolved.") from None
    return config.model_copy(
        update={"vault": config.vault.model_copy(update={"path": vault_path})}
    )
