"""Configuration: profiles are data, networks are limited to test chains, secrets stay out of reprs."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentvax.config import (
    NetworkConfig,
    available_profiles,
    load_profile,
    read_environment,
    settings_from_environment,
)
from agentvax.types import MAX_ATTESTATION_TTL, TOKEN_UNIT


def test_profiles_hold_the_spec_mandates() -> None:
    assert {"default", "demo"} <= set(available_profiles())
    default = load_profile("default")
    demo = load_profile("demo")
    for profile in (default, demo):
        m = profile.mandate
        assert (m.reserve, m.c1, m.d1, m.c2) == (
            600 * TOKEN_UNIT,
            500 * TOKEN_UNIT,
            1000 * TOKEN_UNIT,
            2000 * TOKEN_UNIT,
        )
        assert m.allowance_max == 10 and m.horizon == 30 * 86400 and m.expiry_after == 90 * 86400
        assert (m.charge_external, m.charge_over_half_d, m.charge_anomaly, m.charge_first_payment) == (2, 2, 3, 3)
        assert m.charge_partial_capsule == 5
        assert 0 < profile.guardian.attestation_lifetime <= MAX_ATTESTATION_TTL
    assert (default.mandate.delay, default.mandate.loosening_delay, default.mandate.pressure_hold) == (
        3600,
        86400,
        3600,
    )
    assert default.mandate.refill_period == 86400
    assert (demo.mandate.delay, demo.mandate.loosening_delay, demo.mandate.pressure_hold) == (60, 300, 120)
    assert demo.mandate.refill_period == 600

    mandate = demo.mandate.mandate(1_800_000_000)
    assert mandate.expiry == 1_800_000_000 + 90 * 86400
    assert mandate.delay == 60


def test_unknown_or_malformed_profile_refused() -> None:
    for name in ("mainnet", "../default", "Default", ""):
        with pytest.raises(ValueError):
            load_profile(name)


def test_network_config_accepts_only_test_chains() -> None:
    for chain_id in (31337, 84532, 11155111):
        assert NetworkConfig(rpc_url="http://127.0.0.1:8545", chain_id=chain_id).chain_id == chain_id
    for chain_id in (1, 8453, 10, 137, 0):
        with pytest.raises(ValidationError):
            NetworkConfig(rpc_url="http://127.0.0.1:8545", chain_id=chain_id)


def test_settings_keep_secrets_hidden(tmp_path: Path) -> None:
    secret = "0x" + "5e" * 32
    env_file = tmp_path / "settings.env"
    env_file.write_text(f"OWNER_PRIVATE_KEY={secret}\nTESTNET_CHAIN_ID=84532\nTESTNET_RPC_URL=http://node\n")
    before = dict(os.environ)
    merged = read_environment(env_file, {"LLM_PROVIDER": "openai", "LLM_MODEL": "m"})
    assert dict(os.environ) == before
    settings = settings_from_environment(merged)
    assert settings.testnet is not None and settings.testnet.chain_id == 84532
    assert settings.llm is not None and settings.llm.provider == "openai"
    assert settings.secrets.owner_private_key is not None
    assert settings.secrets.owner_private_key.get_secret_value() == secret
    assert secret not in repr(settings) and secret not in str(settings)
    assert secret not in settings.model_dump_json()

    with pytest.raises(ValidationError):
        settings_from_environment({"TESTNET_CHAIN_ID": "1", "TESTNET_RPC_URL": "http://node"})
