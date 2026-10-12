"""The federation experiment: ``python -m agentvax.fed.run --out results``.

Runs offline. Writes ``<out>/federation.json`` and ``<out>/detector_model.json`` (the adopted model). Reports
``recall_unseen`` per wallet for three models: ``tiers_only`` (deterministic rules alone), ``local`` (own data
only) and ``federated``. The output is reproducible from the configuration. With ``--anchor`` the adopted model is
also anchored in a deployed ThreatBulletin, signed by the key in ``--aggregator-key-file``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from agentvax import pressure, resources
from agentvax.chain.client import ChainClient
from agentvax.chain.deploy import Deployment
from agentvax.config import NetworkConfig, RuntimeConfig
from agentvax.detector.model import MODEL_FILE, Detector, DetectorModel, model_hash, parse_model, save_model
from agentvax.fed.anchor import AnchorRecord, aggregator_from_key_file, anchor_model
from agentvax.fed.canary import detection_rate
from agentvax.fed.client import WalletClient, derived_seed, train_local_model
from agentvax.fed.config import FAMILY_NAMES, FamilyName, FedConfig, default_fed_config
from agentvax.fed.data import FederationData, load_federation_data, local_datasets
from agentvax.fed.hostile import HostileWalletClient
from agentvax.fed.secure import MaskingKey, PairwiseMasker
from agentvax.fed.server import FederationOutcome, RoundRecord, federate, run_round
from agentvax.types import PRESSURE_FLAGS, Flag

FEDERATION_FILE = "federation.json"
TIER_FLAGS = PRESSURE_FLAGS | Flag.ENCODED_CONTENT

Rate = Annotated[float, Field(ge=0.0, le=1.0)]


class _Report(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class RecallUnseen(_Report):
    tiers_only: Rate
    local: Rate
    federated: Rate


class SeededRecall(_Report):
    local: Rate
    federated: Rate


class WalletReport(_Report):
    id: str
    seeded_family: FamilyName
    recall_unseen: RecallUnseen
    unseen_families: tuple[FamilyName, ...]
    unseen_test_texts: int
    recall_seeded_family: SeededRecall
    benign_test_fpr_local: Rate


class BenignFpr(_Report):
    tiers_only: Rate
    initial: Rate
    federated: Rate


class WalletVerdict(_Report):
    id: str
    accepted: bool
    canary_recall: Rate
    canary_fpr: Rate


class RoundSummary(_Report):
    round: int
    candidate_version: int
    candidate_hash: str
    mean_update_norm: float
    updates_clipped: int
    """How many wallets' updates were longer than C and scaled down this round."""
    adopted: bool
    wallets: tuple[WalletVerdict, ...]


class InitialModel(_Report):
    version: int
    model_hash: str
    recall_by_family: dict[str, Rate]


class FederationReport(_Report):
    """``results/federation.json``. The first eight fields are the standard format, the rest are extra."""

    rounds: int
    masked: bool
    clipped: bool
    canary_passed: bool
    model_version: int
    model_hash: str
    wallets: tuple[WalletReport, ...]
    held_out_families: tuple[FamilyName, ...]
    clip_norm: float
    recall_by_family_federated: dict[str, Rate]
    benign_test_fpr: BenignFpr
    initial_model: InitialModel
    round_log: tuple[RoundSummary, ...]
    model_file: str
    anchor: AnchorRecord | None = None


def tier_rate(texts: tuple[str, ...] | list[str]) -> float:
    """Share of ``texts`` for which the deterministic rules alone set a pressure or encoding flag."""
    if not texts:
        return 0.0
    return sum(1 for t in texts if pressure.scan(t) & TIER_FLAGS) / len(texts)


def build_clients(
    data: FederationData, config: FedConfig, initial: DetectorModel, hostile: frozenset[str] = frozenset()
) -> list[WalletClient]:
    """One client per wallet, each with a fresh masking key and its peers' public keys. Wallets named in
    ``hostile`` are poisoning participants (``agentvax.fed.hostile``), for the hostile-wallet suite."""
    unknown = hostile - {w.id for w in config.wallets}
    if unknown:
        raise ValueError(f"no wallet {sorted(unknown)} in the federation")
    datasets = local_datasets(data, config)
    keys = {w.id: MaskingKey(w.id) for w in config.wallets}
    clients = []
    for seeding in config.wallets:
        if seeding.id not in data.canaries:
            raise ValueError(f"no canary set for wallet {seeding.id}")
        peers = {other: key.public_key for other, key in keys.items() if other != seeding.id}
        kind = HostileWalletClient if seeding.id in hostile else WalletClient
        clients.append(
            kind(
                wallet_id=seeding.id,
                dataset=datasets[seeding.id],
                canary_set=data.canaries[seeding.id],
                current=initial,
                config=config,
                masker=PairwiseMasker(keys[seeding.id], peers, config.mask_bits),
            )
        )
    return clients


def local_models(data: FederationData, config: FedConfig, initial: DetectorModel) -> dict[str, DetectorModel]:
    """Each wallet's model trained on its own data alone, for the same number of epochs as the federation."""
    datasets = local_datasets(data, config)
    epochs = config.rounds * config.local_epochs
    return {
        w.id: train_local_model(initial, datasets[w.id], config, epochs, derived_seed(config.seed, "local", w.id))
        for w in config.wallets
    }


def _unseen_texts(data: FederationData, families: tuple[FamilyName, ...]) -> list[str]:
    texts: list[str] = []
    for name in families:
        texts += data.attacks.family(name).test
    return texts


def _recall_by_family(detector: Detector, data: FederationData) -> dict[str, float]:
    return {name: detection_rate(detector, data.attacks.family(name).test) for name in FAMILY_NAMES}


def build_report(
    data: FederationData,
    config: FedConfig,
    outcome: FederationOutcome,
    local: dict[str, DetectorModel],
    raw_norms: dict[str, dict[int, float]],
) -> FederationReport:
    federated = Detector(outcome.model)
    initial = Detector(outcome.initial)
    wallets = []
    for seeding in config.wallets:
        unseen = tuple(f for f in FAMILY_NAMES if f != seeding.seeded_family)
        texts = _unseen_texts(data, unseen)
        own = data.attacks.family(seeding.seeded_family).test
        local_detector = Detector(local[seeding.id])
        wallets.append(
            WalletReport(
                id=seeding.id,
                seeded_family=seeding.seeded_family,
                recall_unseen=RecallUnseen(
                    tiers_only=tier_rate(texts),
                    local=detection_rate(local_detector, texts),
                    federated=detection_rate(federated, texts),
                ),
                unseen_families=unseen,
                unseen_test_texts=len(texts),
                recall_seeded_family=SeededRecall(
                    local=detection_rate(local_detector, own), federated=detection_rate(federated, own)
                ),
                benign_test_fpr_local=detection_rate(local_detector, data.benign.test),
            )
        )
    rounds = tuple(
        RoundSummary(
            round=r.round,
            candidate_version=r.candidate_version,
            candidate_hash=r.candidate_hash,
            mean_update_norm=r.mean_update_norm,
            updates_clipped=sum(1 for norms in raw_norms.values() if norms[r.round] > config.clip_norm),
            adopted=r.adopted,
            wallets=tuple(
                WalletVerdict(
                    id=w.wallet_id,
                    accepted=w.accepted,
                    canary_recall=w.candidate.recall,
                    canary_fpr=w.candidate.false_positive_rate,
                )
                for w in r.wallets
            ),
        )
        for r in outcome.rounds
    )
    return FederationReport(
        rounds=config.rounds,
        masked=outcome.masked,
        clipped=outcome.clipped,
        canary_passed=outcome.canary_passed,
        model_version=outcome.model.version,
        model_hash=model_hash(outcome.model),
        wallets=tuple(wallets),
        held_out_families=config.held_out_families,
        clip_norm=config.clip_norm,
        recall_by_family_federated=_recall_by_family(federated, data),
        benign_test_fpr=BenignFpr(
            tiers_only=tier_rate(data.benign.test),
            initial=detection_rate(initial, data.benign.test),
            federated=detection_rate(federated, data.benign.test),
        ),
        initial_model=InitialModel(
            version=outcome.initial.version,
            model_hash=model_hash(outcome.initial),
            recall_by_family=_recall_by_family(initial, data),
        ),
        round_log=rounds,
        model_file=MODEL_FILE,
    )


def run_federation(config: FedConfig, data: FederationData) -> tuple[FederationReport, FederationOutcome]:
    """Runs the federation and the local baselines and builds the report. Needs no chain and writes nothing."""
    initial = parse_model(resources.read_bytes(config.initial_model))
    clients = build_clients(data, config, initial)
    outcome = federate(clients, initial, config)
    raw_norms = {c.wallet_id: dict(c.raw_update_norms) for c in clients}
    return build_report(data, config, outcome, local_models(data, config, initial), raw_norms), outcome


class FederationFailed(RuntimeError):
    """No federated model passed every wallet's canary, so there is no model to release."""


def build_detector_release(work_dir: Path) -> Path:
    """Runs the federation with the packaged configuration and data and writes the canonical file of the model it
    adopted to ``work_dir``. Returns the file's path. Raises ``FederationFailed`` if no candidate passed every
    canary. This function touches no chain."""
    _, outcome = run_federation(default_fed_config(), load_federation_data())
    if not outcome.canary_passed:
        raise FederationFailed("no federated model passed every canary")
    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / MODEL_FILE
    save_model(outcome.model, path)
    return path


def poisoned_round(current: DetectorModel, hostile: str) -> tuple[DetectorModel, RoundRecord]:
    """One federation round from ``current``, the model every wallet runs, in which wallet ``hostile`` sends a
    poisoned update. Returns the model every wallet runs afterwards and the round's record with every wallet's
    canary verdict. Uses the packaged configuration and data and touches no chain."""
    config = default_fed_config()
    clients = build_clients(load_federation_data(), config, current, hostile=frozenset({hostile}))
    return run_round(clients, current, config.rounds + 1, config)


def write_json(path: Path, report: FederationReport) -> None:
    path.write_text(json.dumps(report.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")


def anchor_on_chain(
    model: DetectorModel, rpc_url: str, deployment_file: Path, key_file: Path, repo_root: Path
) -> AnchorRecord:
    """Anchors ``model`` in the bulletin of the deployment in ``deployment_file``. The chain id must be an allowed
    test network and must match the deployment."""
    deployment = Deployment.from_file_dict(json.loads(deployment_file.read_text(encoding="utf-8")))
    network = NetworkConfig(rpc_url=rpc_url, chain_id=deployment.chain_id)
    config = RuntimeConfig.for_repository(repo_root, network, deployment.profile, deployment_file)
    client = ChainClient.from_config(config)
    return anchor_model(client, aggregator_from_key_file(key_file), deployment.threat_bulletin.address, model)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the federated detector experiment offline.")
    parser.add_argument("--out", type=Path, required=True, help="directory for federation.json and the model file")
    parser.add_argument("--anchor", action="store_true", help="also anchor the adopted model on a test network")
    parser.add_argument("--rpc-url", help="RPC endpoint of the test network (with --anchor)")
    parser.add_argument("--deployment", type=Path, help="deployment file of the stack (with --anchor)")
    parser.add_argument("--aggregator-key-file", type=Path, help="file with the aggregator key (with --anchor)")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd(), help="repository root (with --anchor)")
    args = parser.parse_args(argv)
    if args.anchor and not (args.rpc_url and args.deployment and args.aggregator_key_file):
        parser.error("--anchor needs --rpc-url, --deployment and --aggregator-key-file")

    config = default_fed_config()
    data = load_federation_data()
    report, outcome = run_federation(config, data)
    if args.anchor:
        if not outcome.canary_passed:
            parser.error("no federated model passed every canary, so there is nothing to anchor")
        record = anchor_on_chain(outcome.model, args.rpc_url, args.deployment, args.aggregator_key_file, args.repo_root)
        report = report.model_copy(update={"anchor": record})

    args.out.mkdir(parents=True, exist_ok=True)
    save_model(outcome.model, args.out / MODEL_FILE)
    write_json(args.out / FEDERATION_FILE, report)
    print(
        json.dumps(
            {
                "out": str(args.out / FEDERATION_FILE),
                "model_version": report.model_version,
                "model_hash": report.model_hash,
                "canary_passed": report.canary_passed,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
