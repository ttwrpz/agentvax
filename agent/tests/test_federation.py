"""Federated detector: FedAvg, clipping, pairwise masks, the canary check, on-chain anchoring and adoption, and
the federation.json output."""

from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
import pytest
from chain_support import REPO_ROOT, AnvilNode, client_for, deploy_test_stack, funded_account
from flwr.server.strategy.aggregate import aggregate

from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import THREAT_BULLETIN, ChainClient
from agentvax.detector.model import (
    Detector,
    DetectorModel,
    ModelFormatError,
    ModelHashMismatch,
    canonical_bytes,
    model_hash,
    parse_model,
    save_model,
)
from agentvax import resources
from agentvax.fed import anchor, canary
from agentvax.fed.client import (
    WalletClient,
    model_from_vector,
    model_to_ndarrays,
    ndarrays_to_vector,
    vector_to_ndarrays,
)
from agentvax.fed.config import FAMILY_NAMES, CanaryTolerance, FedConfig, default_fed_config
from agentvax.fed.data import FederationData, load_federation_data, local_datasets
from agentvax.fed.hostile import HostileWalletClient, poisoned_update
from agentvax.fed.run import FEDERATION_FILE, MODEL_FILE, main
from agentvax.fed.secure import (
    EXACT_INTEGER_LIMIT,
    MaskingError,
    MaskingKey,
    PairwiseMasker,
    Quantiser,
    clip,
    exactness_bound,
    l2_norm,
    require_exact,
)
from agentvax.fed.server import aggregate_masked, run_round

# ---------------------------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def config() -> FedConfig:
    return default_fed_config()


@pytest.fixture(scope="module")
def data() -> FederationData:
    return load_federation_data()


@pytest.fixture(scope="module")
def initial(config: FedConfig) -> DetectorModel:
    return parse_model(resources.read_bytes(config.initial_model))


def _clients(
    data: FederationData, config: FedConfig, initial: DetectorModel, hostile: frozenset[str] = frozenset()
) -> list[WalletClient]:
    datasets = local_datasets(data, config)
    keys = {w.id: MaskingKey(w.id) for w in config.wallets}
    out: list[WalletClient] = []
    for w in config.wallets:
        peers = {o: k.public_key for o, k in keys.items() if o != w.id}
        cls = HostileWalletClient if w.id in hostile else WalletClient
        out.append(
            cls(
                wallet_id=w.id,
                dataset=datasets[w.id],
                canary_set=data.canaries[w.id],
                current=initial,
                config=config,
                masker=PairwiseMasker(keys[w.id], peers, config.mask_bits),
            )
        )
    return out


@pytest.fixture(scope="module")
def run_outputs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Two complete runs of ``python -m agentvax.fed.run`` into separate directories."""
    first = tmp_path_factory.mktemp("fed-first")
    second = tmp_path_factory.mktemp("fed-second")
    assert main(["--out", str(first)]) == 0
    assert main(["--out", str(second)]) == 0
    return first, second


# ---------------------------------------------------------------------------------------------- FedAvg


def test_fedavg_matches_manual_average(data: FederationData, config: FedConfig, initial: DetectorModel) -> None:
    # Flower's aggregate is the example-weighted average, layer by layer.
    rng = np.random.default_rng(7)
    results = [([rng.normal(size=5), rng.normal(size=1)], n) for n in (3, 5, 12)]
    got = aggregate(results)
    total = sum(n for _, n in results)
    for layer in range(2):
        manual = sum(n * params[layer] for params, n in results) / total
        np.testing.assert_allclose(got[layer], manual, rtol=0, atol=1e-12)

    # A full masked round produces global + the plain average of the clipped updates.
    clients = _clients(data, config, initial)
    parameters = model_to_ndarrays(initial)
    plain = [c.prepare_update(parameters, 1) for c in clients]
    manual_mean = np.mean(np.vstack(plain), axis=0)
    fits = [c.fit(parameters, {"round": 1}) for c in clients]
    mean = aggregate_masked([(p, n) for p, n, _ in fits], config)
    quantum = 2.0 ** -config.fraction_bits
    assert np.max(np.abs(mean - manual_mean)) <= quantum
    candidate, record = run_round(clients, initial, 1, config)
    expected = ndarrays_to_vector(parameters) + manual_mean
    np.testing.assert_allclose(ndarrays_to_vector(model_to_ndarrays(candidate)), expected, rtol=0, atol=quantum)
    assert record.candidate_version == initial.version + 1
    assert record.adopted == (candidate.version == initial.version + 1)


def test_fedavg_refuses_unequal_example_counts(config: FedConfig) -> None:
    zeros = vector_to_ndarrays(np.zeros(9))
    with pytest.raises(MaskingError):
        aggregate_masked([(zeros, 60), (zeros, 60), (zeros, 61)], config)
    with pytest.raises(MaskingError):
        aggregate_masked([(zeros, 60)], config)


# ---------------------------------------------------------------------------------------------- clipping


def test_update_clipping(data: FederationData, config: FedConfig, initial: DetectorModel) -> None:
    long = np.array([3.0, 4.0, 12.0])  # norm 13
    clipped = clip(long, 6.5)
    assert l2_norm(clipped) == pytest.approx(6.5, rel=1e-12)
    np.testing.assert_allclose(clipped, long / 2, rtol=1e-12)
    short = np.array([0.1, -0.2])
    np.testing.assert_array_equal(clip(short, 1.0), short)
    at_bound = np.array([0.6, 0.8])
    np.testing.assert_array_equal(clip(at_bound, 1.0), at_bound)
    with pytest.raises(ValueError):
        clip(np.array([np.nan, 1.0]), 1.0)
    with pytest.raises(ValueError):
        clip(long, 0.0)

    # Every honest client's contribution is within C, whatever its raw update was.
    parameters = model_to_ndarrays(initial)
    for client in _clients(data, config, initial):
        raw = client.local_update(parameters, 1)
        sent = client.prepare_update(parameters, 1)
        assert l2_norm(sent) <= config.clip_norm * (1 + 1e-12)
        if l2_norm(raw) > config.clip_norm:
            cosine = float(raw @ sent) / (l2_norm(raw) * l2_norm(sent))
            assert cosine == pytest.approx(1.0, abs=1e-12)


# ---------------------------------------------------------------------------------------------- masks


def test_masks_cancel_in_aggregate(data: FederationData, config: FedConfig, initial: DetectorModel) -> None:
    ids = ["A", "B", "C"]
    keys = {i: MaskingKey(i) for i in ids}
    maskers = {
        i: PairwiseMasker(keys[i], {o: keys[o].public_key for o in ids if o != i}, config.mask_bits) for i in ids
    }
    # Pair seeds are symmetric, and mask_ij = -mask_ji.
    assert keys["A"].pair_seed("B", keys["B"].public_key, 4) == keys["B"].pair_seed("A", keys["A"].public_key, 4)
    assert keys["A"].pair_seed("B", keys["B"].public_key, 4) != keys["A"].pair_seed("B", keys["B"].public_key, 5)
    totals = [maskers[i].total_mask(3, 4097) for i in ids]
    np.testing.assert_array_equal(np.sum(totals, axis=0), np.zeros(4097))
    # Without one wallet the masks do not cancel: a dropped wallet aborts the round.
    assert np.max(np.abs(totals[0] + totals[1])) > 2**30

    clients = _clients(data, config, initial)
    parameters = model_to_ndarrays(initial)
    quantiser = Quantiser(config.fraction_bits)
    plain = [quantiser.encode(c.prepare_update(parameters, 2)) for c in clients]
    fits = [c.fit(parameters, {"round": 2}) for c in clients]
    for (masked, n, _), raw in zip(fits, plain, strict=True):
        assert n == clients[0].num_examples
        # The aggregator cannot read an individual update.
        assert np.median(np.abs(ndarrays_to_vector(masked) - raw)) > 2 ** (config.mask_bits - 2)
    masked_sum = np.sum([ndarrays_to_vector(p) for p, _, _ in fits], axis=0)
    np.testing.assert_array_equal(masked_sum, np.sum(plain, axis=0))

    masked_mean = aggregate_masked([(p, n) for p, n, _ in fits], config)
    float_mean = np.mean(np.vstack([c.prepare_update(parameters, 2) for c in clients]), axis=0)
    assert np.max(np.abs(masked_mean - float_mean)) < 1e-9

    # Fresh keys give different masks but the bit-identical aggregate.
    again = _clients(data, config, initial)
    fits_again = [c.fit(parameters, {"round": 2}) for c in again]
    assert not np.array_equal(ndarrays_to_vector(fits_again[0][0]), ndarrays_to_vector(fits[0][0]))
    np.testing.assert_array_equal(aggregate_masked([(p, n) for p, n, _ in fits_again], config), masked_mean)


def test_masking_parameters_are_exact(config: FedConfig) -> None:
    n = 60
    bound = exactness_bound(len(config.wallets), n, config.clip_norm, config.fraction_bits, config.mask_bits)
    assert bound < EXACT_INTEGER_LIMIT
    require_exact(len(config.wallets), n, config.clip_norm, config.fraction_bits, config.mask_bits)
    with pytest.raises(MaskingError):
        require_exact(3, n, config.clip_norm, config.fraction_bits, 50)
    key = MaskingKey("A")
    masker = PairwiseMasker(key, {"B": MaskingKey("B").public_key}, config.mask_bits)
    with pytest.raises(MaskingError):
        masker.mask(np.array([0.5, 1.0]), 1)
    with pytest.raises(MaskingError):
        PairwiseMasker(key, {"A": key.public_key}, config.mask_bits)
    with pytest.raises(MaskingError):
        key.pair_seed("A", key.public_key, 1)


def test_aggregator_refuses_values_outside_masked_range(config: FedConfig) -> None:
    good = vector_to_ndarrays(np.zeros(9))
    huge = vector_to_ndarrays(np.full(9, 2.0**52))
    fraction = vector_to_ndarrays(np.full(9, 0.5))
    with pytest.raises(MaskingError):
        aggregate_masked([(good, 60), (good, 60), (huge, 60)], config)
    with pytest.raises(MaskingError):
        aggregate_masked([(good, 60), (good, 60), (fraction, 60)], config)


# ---------------------------------------------------------------------------------------------- canary


def test_canary_rejects_degraded_model(data: FederationData, config: FedConfig, initial: DetectorModel) -> None:
    tolerance = config.canary
    canary_a = data.canaries["A"]
    base = canary.score(initial, canary_a)

    # A model that misses attacks (bias pushed far down) loses recall and is rejected.
    blind = initial.model_copy(update={"bias": initial.bias - 50.0})
    verdict = canary.check(initial, blind, canary_a, tolerance)
    assert verdict.candidate.recall == 0.0
    assert not verdict.accepted
    # A model that flags everything (bias pushed far up) raises the false-positive rate and is rejected.
    noisy = initial.model_copy(update={"bias": initial.bias + 50.0})
    verdict = canary.check(initial, noisy, canary_a, tolerance)
    assert verdict.candidate.false_positive_rate == 1.0
    assert not verdict.accepted
    # The current model itself is always acceptable.
    assert canary.check(initial, initial, canary_a, tolerance).accepted
    # Tolerance edges.
    tight = CanaryTolerance(max_recall_drop=0.1, max_fpr_rise=0.1)
    now = canary.CanaryScore(recall=0.9, false_positive_rate=0.1)
    assert canary.judge(now, canary.CanaryScore(recall=0.8, false_positive_rate=0.2), tight)
    assert not canary.judge(now, canary.CanaryScore(recall=0.7, false_positive_rate=0.1), tight)
    assert not canary.judge(now, canary.CanaryScore(recall=0.9, false_positive_rate=0.25), tight)
    assert base.recall > 0.0

    # A poisoned participant: its sign-flipped, unclipped update makes a model that a canary rejects, so no
    # wallet adopts it and every wallet keeps the model it had.
    clients = _clients(data, config, initial, hostile=frozenset({"C"}))
    after, record = run_round(clients, initial, 1, config)
    assert not record.adopted
    assert any(not w.accepted for w in record.wallets)
    assert after == initial
    assert all(c.current == initial for c in clients)


def test_poisoned_update_is_sign_flipped_and_scaled() -> None:
    honest = np.array([1.0, -2.0, 2.0])
    poison = poisoned_update(honest, 30.0)
    assert l2_norm(poison) == pytest.approx(30.0, rel=1e-12)
    assert float(poison @ honest) < 0
    with pytest.raises(ValueError):
        poisoned_update(np.zeros(3), 1.0)


def test_client_adopts_only_same_encoder(data: FederationData, config: FedConfig, initial: DetectorModel) -> None:
    client = _clients(data, config, initial)[0]
    other = initial.model_copy(
        update={"encoder": initial.encoder.model_copy(update={"char_ngram_max": initial.encoder.char_ngram_max - 1})}
    )
    with pytest.raises(ValueError):
        client.adopt(other)
    assert client.current == initial


# ---------------------------------------------------------------------------------------------- anchoring


def _deploy_bulletin(client: ChainClient, node: AnvilNode) -> tuple[str, object, object]:
    deployer = funded_account(node)
    aggregator = funded_account(node)
    artifact = client.artifacts.load(THREAT_BULLETIN)
    receipt = client.deploy(deployer, artifact.abi, artifact.bytecode, (deployer.address, aggregator.address))
    return str(receipt["contractAddress"]), aggregator, deployer


def test_model_adopted_only_if_hash_matches(
    anvil: AnvilNode, artifacts: ArtifactStore, initial: DetectorModel, tmp_path: Path
) -> None:
    client = client_for(anvil, artifacts)
    bulletin, aggregator, outsider = _deploy_bulletin(client, anvil)
    model = initial.model_copy(update={"version": 2})
    path = tmp_path / "model.json"
    save_model(model, path)

    with pytest.raises(anchor.ModelNotAnchored):
        anchor.adopt(path, client, bulletin)
    with pytest.raises(anchor.NotAggregator):
        anchor.anchor_model(client, outsider, bulletin, model)  # type: ignore[arg-type]

    record = anchor.anchor_model(client, aggregator, bulletin, model)  # type: ignore[arg-type]
    assert record.version == 2 and record.model_hash == model_hash(model)
    assert anchor.latest_anchor(client, bulletin) == (2, model_hash(model))

    # The matching file is adopted.
    detector = anchor.adopt(path, client, bulletin)
    assert isinstance(detector, Detector)
    assert canonical_bytes(detector.model) == path.read_bytes()

    # A tampered file is refused: one weight changed, still canonical, different hash.
    weights = list(model.weights)
    weights[0] = weights[0] + 1.0
    tampered = tmp_path / "tampered.json"
    save_model(model.model_copy(update={"weights": tuple(weights)}), tampered)
    with pytest.raises(ModelHashMismatch):
        anchor.adopt(tampered, client, bulletin)
    # Whitespace added to the right model is refused too.
    padded = tmp_path / "padded.json"
    padded.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ModelHashMismatch):
        anchor.adopt(padded, client, bulletin)

    # Once a different model is anchored as the latest version, the old file is refused.
    newer = model.model_copy(update={"version": 3, "bias": model.bias + 0.25})
    anchor.anchor_model(client, aggregator, bulletin, newer)  # type: ignore[arg-type]
    with pytest.raises(ModelHashMismatch):
        anchor.adopt(path, client, bulletin)
    newer_path = tmp_path / "newer.json"
    save_model(newer, newer_path)
    assert anchor.adopt(newer_path, client, bulletin).model == newer

    # A file whose hash is anchored but under another version number is refused.
    renumbered = newer.model_copy(update={"version": 5})
    renumbered_path = tmp_path / "renumbered.json"
    save_model(renumbered, renumbered_path)
    anchor.anchor_model(client, aggregator, bulletin, renumbered.model_copy(update={"version": 4}))  # type: ignore[arg-type]
    with pytest.raises(ModelHashMismatch):
        anchor.adopt(renumbered_path, client, bulletin)
    garbage = tmp_path / "garbage.json"
    garbage.write_bytes(b"{}")
    with pytest.raises((ModelHashMismatch, ModelFormatError)):
        anchor.adopt(garbage, client, bulletin)


# ---------------------------------------------------------------------------------------------- federation.json


EXPECTED_KEYS = ("rounds", "masked", "clipped", "canary_passed", "model_version", "model_hash", "wallets")


def test_federation_json_schema(run_outputs: tuple[Path, Path], config: FedConfig) -> None:
    out, _ = run_outputs
    report = json.loads((out / FEDERATION_FILE).read_text(encoding="utf-8"))
    assert list(report)[: len(EXPECTED_KEYS)] == list(EXPECTED_KEYS)
    assert report["rounds"] == config.rounds >= 3
    assert report["masked"] is True and report["clipped"] is True
    assert isinstance(report["canary_passed"], bool)
    assert isinstance(report["model_version"], int) and report["model_version"] >= 1
    assert isinstance(report["model_hash"], str) and len(report["model_hash"]) == 66
    assert report["model_hash"].startswith("0x")

    wallets = report["wallets"]
    assert [(w["id"], w["seeded_family"]) for w in wallets] == [("A", "direct"), ("B", "indirect"), ("C", "memory")]
    for w in wallets:
        assert set(w["recall_unseen"]) == {"tiers_only", "local", "federated"}
        for value in w["recall_unseen"].values():
            assert isinstance(value, float) and 0.0 <= value <= 1.0
        assert w["seeded_family"] not in w["unseen_families"]
        assert len(w["unseen_families"]) == len(FAMILY_NAMES) - 1

    # The model file is the adopted model and its hash is the reported one.
    model = parse_model((out / MODEL_FILE).read_bytes())
    assert model_hash(model) == report["model_hash"]
    assert model.version == report["model_version"]
    if report["canary_passed"]:
        assert report["model_version"] > report["initial_model"]["version"]
        adopted = [r for r in report["round_log"] if r["adopted"]]
        assert adopted and adopted[-1]["candidate_hash"] == report["model_hash"]
        assert all(w["accepted"] for w in adopted[-1]["wallets"])


def test_federation_run_is_deterministic(run_outputs: tuple[Path, Path]) -> None:
    first, second = run_outputs
    assert (first / FEDERATION_FILE).read_bytes() == (second / FEDERATION_FILE).read_bytes()
    assert (first / MODEL_FILE).read_bytes() == (second / MODEL_FILE).read_bytes()


def test_federation_data_is_separate_and_sized(data: FederationData, config: FedConfig) -> None:
    for name in FAMILY_NAMES:
        split = data.attacks.family(name)
        assert len(split.train) >= 30 and len(split.test) >= 20
    assert len(data.benign.train) >= 150 and len(data.benign.test) >= 100
    assert set(data.canaries) == {w.id for w in config.wallets}
    datasets = local_datasets(data, config)
    assert len({d.size for d in datasets.values()}) == 1
    benign_slices = [set(d.benign) for d in datasets.values()]
    assert not (benign_slices[0] & benign_slices[1] or benign_slices[0] & benign_slices[2])
    held_out = set(config.held_out_families)
    for d in datasets.values():
        for family in held_out:
            assert not set(d.attack) & set(data.attacks.family(family).train)
    source = Path(__file__).resolve().parents[1] / "agentvax" / "fed"
    for module in source.glob("*.py"):
        text = module.read_text(encoding="utf-8")
        assert re.search(r"[\"']eval/suites|eval\.suites", text) is None, module.name


def test_run_anchors_adopted_model_on_chain(
    anvil: AnvilNode, artifacts: ArtifactStore, tmp_path: Path
) -> None:
    client = client_for(anvil, artifacts)
    stack = deploy_test_stack(client, anvil, guardian=funded_account(anvil).address)
    deployment_file = tmp_path / "deployment.json"
    deployment_file.write_text(json.dumps(stack.deployment.to_file_dict()), encoding="utf-8")
    key_file = tmp_path / "aggregator.key"
    key_file.write_text(stack.aggregator.key.hex(), encoding="ascii")
    out = tmp_path / "out"
    args = ["--out", str(out), "--anchor", "--rpc-url", anvil.rpc_url, "--deployment", str(deployment_file)]
    args += ["--aggregator-key-file", str(key_file), "--repo-root", str(REPO_ROOT)]
    assert main(args) == 0

    report = json.loads((out / FEDERATION_FILE).read_text(encoding="utf-8"))
    assert report["canary_passed"] is True
    bulletin = stack.deployment.threat_bulletin.address
    assert report["anchor"]["version"] == report["model_version"]
    assert report["anchor"]["model_hash"] == report["model_hash"]
    assert report["anchor"]["chain_id"] == anvil.chain_id
    assert anchor.latest_anchor(client, bulletin) == (report["model_version"], report["model_hash"])
    assert model_hash(anchor.adopt(out / MODEL_FILE, client, bulletin).model) == report["model_hash"]
    # The key is never written into the report.
    assert stack.aggregator.key.hex()[2:] not in (out / FEDERATION_FILE).read_text(encoding="utf-8")


def test_anchor_flag_needs_chain_arguments(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--out", str(tmp_path), "--anchor"])
