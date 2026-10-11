"""Configuration models.

Public runtime configuration (network, paths, deployment profile, tuning of the chain client) is kept apart from
secrets. Library code never reads ``os.environ``: an entry point reads its environment once, with
``read_environment``, builds these models and passes them down.

Delay profiles are data files in ``agentvax/profiles/``. A profile holds a complete mandate, with the expiry
written as a duration that is turned into an absolute time when the mandate is set, and the guardian's
attestation lifetime. The profile used is chosen at deployment and recorded with the deployment.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from agentvax import resources
from agentvax.types import (
    ALLOWED_CHAIN_IDS,
    MAX_ATTESTATION_TTL,
    Mandate,
    Uint8,
    Uint32,
    Uint256,
)

PROFILE_NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"


class ConfigModel(BaseModel):
    """Base for configuration: no unknown fields, immutable. Values are coerced from text where sensible."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------------------------------------------------------------------------------------------- profiles


class MandateTemplate(ConfigModel):
    """Every mandate field, with ``expiry_after`` (seconds from the moment the mandate is set) for ``expiry``."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    reserve: Uint256
    c1: Uint256
    d1: Uint256
    c2: Uint256
    delay: Annotated[int, Field(ge=1, le=2**64 - 1)]
    loosening_delay: Annotated[int, Field(ge=1, le=2**64 - 1)]
    pressure_hold: Annotated[int, Field(ge=1, le=2**64 - 1)]
    refill_period: Annotated[int, Field(ge=1, le=2**64 - 1)]
    horizon: Annotated[int, Field(ge=1, le=2**64 - 1)]
    expiry_after: Annotated[int, Field(ge=1, le=2**64 - 1)]
    allowance_max: Uint32
    channel_profile: Annotated[int, Field(ge=0, le=0x1F)]
    charge_external: Uint8
    charge_over_half_d: Uint8
    charge_anomaly: Uint8
    charge_first_payment: Uint8
    charge_partial_capsule: Uint8
    fee_top_up_cap: Uint256
    fee_daily_budget: Uint256
    agent_balance_floor: Uint256
    native_reserve: Uint256

    @model_validator(mode="after")
    def _limits_ordered(self) -> MandateTemplate:
        if self.c1 > self.c2:
            raise ValueError("c1 must not exceed c2")
        return self

    def mandate(self, set_at: int) -> Mandate:
        """The mandate with ``expiry = set_at + expiry_after``. ``set_at`` is a block timestamp."""
        fields = self.model_dump()
        fields["expiry"] = set_at + fields.pop("expiry_after")
        return Mandate(**fields)


class GuardianProfile(ConfigModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    attestation_lifetime: Annotated[int, Field(ge=1, le=MAX_ATTESTATION_TTL)]
    """Seconds an attestation stays valid. At most the contract's ``MAX_ATTESTATION_TTL``."""


class Profile(ConfigModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: Annotated[str, Field(pattern=PROFILE_NAME_PATTERN)]
    mandate: MandateTemplate
    guardian: GuardianProfile


def load_profile(name: str) -> Profile:
    """Loads profile ``name`` from the package data. Raises ``ValueError`` for an unknown or malformed profile."""
    if not re.fullmatch(PROFILE_NAME_PATTERN, name):
        raise ValueError(f"invalid profile name {name!r}")
    path = f"profiles/{name}.json"
    if not resources.exists(path):
        raise ValueError(f"unknown profile {name!r}")
    profile = resources.load_model(Profile, path)
    if profile.name != name:
        raise ValueError(f"profile file {name}.json names itself {profile.name!r}")
    return profile


def available_profiles() -> tuple[str, ...]:
    return tuple(n[: -len(".json")] for n in resources.list_dir("profiles") if n.endswith(".json"))


# ---------------------------------------------------------------------------------------------- runtime


def _check_chain_id(value: int) -> int:
    if value not in ALLOWED_CHAIN_IDS:
        raise ValueError(f"chain id {value} is not an allowed test network {sorted(ALLOWED_CHAIN_IDS)}")
    return value


class NetworkConfig(ConfigModel):
    rpc_url: Annotated[str, Field(min_length=1)]
    chain_id: int
    explorer_url: str | None = None

    @field_validator("chain_id")
    @classmethod
    def _allowed_chain(cls, value: int) -> int:
        return _check_chain_id(value)


class ChainTuning(ConfigModel):
    """How the chain client talks to a node. Values suit both Anvil and a public test network."""

    rpc_timeout_seconds: Annotated[float, Field(gt=0)] = 30.0
    receipt_timeout_seconds: Annotated[float, Field(gt=0)] = 180.0
    receipt_poll_seconds: Annotated[float, Field(gt=0)] = 0.2
    gas_margin_percent: Annotated[int, Field(ge=0, le=200)] = 25
    max_fee_base_multiplier: Annotated[int, Field(ge=1, le=10)] = 2
    """``maxFeePerGas`` is this many times the latest base fee plus the priority fee, so that a transaction still
    lands if the base fee rises for a few blocks."""


class GuardianTiming(ConfigModel):
    """How long the runtime waits for the guardian process."""

    startup_timeout_seconds: Annotated[float, Field(gt=0)] = 60.0
    request_timeout_seconds: Annotated[float, Field(gt=0)] = 30.0
    shutdown_timeout_seconds: Annotated[float, Field(gt=0)] = 10.0


class RuntimeConfig(ConfigModel):
    """Public configuration of one runtime: which network, which profile, where the contracts and artifacts are."""

    network: NetworkConfig
    profile: Annotated[str, Field(pattern=PROFILE_NAME_PATTERN)]
    contracts_dir: Path
    artifacts_dir: Path
    deployment_file: Path | None = None
    forge_executable: Annotated[str, Field(min_length=1)] = "forge"
    tuning: ChainTuning = ChainTuning()
    guardian_timing: GuardianTiming = GuardianTiming()

    @classmethod
    def for_repository(
        cls,
        repo_root: Path,
        network: NetworkConfig,
        profile: str,
        deployment_file: Path | None = None,
        forge_executable: str = "forge",
    ) -> RuntimeConfig:
        """Paths laid out as in this repository: ``contracts/`` with Foundry artifacts in ``contracts/out``."""
        contracts = repo_root / "contracts"
        return cls(
            network=network,
            profile=profile,
            contracts_dir=contracts,
            artifacts_dir=contracts / "out",
            deployment_file=deployment_file,
            forge_executable=forge_executable,
        )


class LlmConfig(ConfigModel):
    """Public part of the hosted model configuration. The API key is a secret, see ``Secrets``."""

    provider: Annotated[str, Field(min_length=1)]
    model: Annotated[str, Field(min_length=1)]
    base_url: str | None = None
    timeout_seconds: Annotated[float, Field(gt=0)] = 60.0
    temperature: Annotated[float, Field(ge=0.0, le=2.0)] = 0.0


class Secrets(ConfigModel):
    """Secret values. ``SecretStr`` keeps them out of ``repr`` and logs. Never passed to the guardian process,
    which holds its own key, and never to a model."""

    owner_private_key: SecretStr | None = None
    llm_api_key: SecretStr | None = None


class EnvironmentSettings(ConfigModel):
    """What an entry point learns from its environment. Every part is optional: a stage that needs a missing
    part reports that it is blocked."""

    testnet: NetworkConfig | None
    llm: LlmConfig | None
    secrets: Secrets


def read_environment(env_file: Path | None, process_env: Mapping[str, str]) -> dict[str, str]:
    """Merges ``env_file`` (if it exists) with ``process_env``; the process environment wins.

    Called only by entry points. Nothing is printed or logged, and ``os.environ`` is not modified.
    """
    merged: dict[str, str] = {}
    if env_file is not None and env_file.is_file():
        merged.update({k: v for k, v in dotenv_values(env_file).items() if v is not None})
    merged.update(process_env)
    return merged


def _nonempty(env: Mapping[str, str], key: str) -> str | None:
    value = env.get(key, "").strip()
    return value or None


def settings_from_environment(env: Mapping[str, str]) -> EnvironmentSettings:
    """Builds the settings from the variable names documented in ``.env.example``."""
    testnet: NetworkConfig | None = None
    rpc = _nonempty(env, "TESTNET_RPC_URL")
    chain = _nonempty(env, "TESTNET_CHAIN_ID")
    if rpc is not None and chain is not None:
        testnet = NetworkConfig(rpc_url=rpc, chain_id=int(chain), explorer_url=_nonempty(env, "EXPLORER_URL"))

    llm: LlmConfig | None = None
    provider = _nonempty(env, "LLM_PROVIDER")
    model = _nonempty(env, "LLM_MODEL")
    if provider is not None and model is not None:
        llm = LlmConfig(provider=provider, model=model, base_url=_nonempty(env, "LLM_BASE_URL"))

    owner_key = _nonempty(env, "OWNER_PRIVATE_KEY")
    api_key = _nonempty(env, "LLM_API_KEY")
    secrets = Secrets(
        owner_private_key=SecretStr(owner_key) if owner_key else None,
        llm_api_key=SecretStr(api_key) if api_key else None,
    )
    return EnvironmentSettings(testnet=testnet, llm=llm, secrets=secrets)


def profile_json(profile: Profile) -> str:
    """Canonical JSON of a profile, for recording next to a deployment."""
    return json.dumps(profile.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
