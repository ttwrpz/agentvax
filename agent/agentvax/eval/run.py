"""``python -m agentvax.eval.run --mode mock|live --out results``: the evaluation run.

Starts a local chain, deploys the stack, runs the federation and every suite, judges each case from chain state
and writes the ledger and the summary. Exit codes: 0 summary written, 1 harness error or vacuous suite, 2 start-up
failure. Live mode never falls back to the mock.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from importlib.resources import files
from pathlib import Path

from eth_utils import keccak

from agentvax import pressure, resources
from agentvax.config import read_environment, settings_from_environment
from agentvax.detector.model import Detector
from agentvax.eval.environment import RunnerConfig
from agentvax.fed.run import FederationFailed
from agentvax.eval.ledger import (
    DetectorInfo,
    DocumentRecord,
    LedgerWriter,
    RunRecord,
    read_ledger,
    reduce,
    vacuity_problems,
)
from agentvax.eval.observe import Observer
from agentvax.eval.provenance import CodeRevision, code_revision, suites_location
from agentvax.eval.scenarios import WALLET_LABELS, Scenarios
from agentvax.eval.stack import local_stack
from agentvax.eval.suites_schema import (
    AttackCase,
    SuiteFileError,
    SuiteSet,
    fixed_size_problems,
    load_suites,
)
from agentvax.harness.mock_llm import MockLLM
from agentvax.llm import UnsupportedProvider, build
from agentvax.llm.base import LanguageModel
from agentvax.text import Strings
from agentvax.vaxlab.inputs import render
from agentvax.vaxlab.rewording import AttackForm, ModelRewriter

RUNNER_CONFIG = "eval/data/runner.json"


class StartupError(RuntimeError):
    """The run cannot start. The message says what is missing."""


def packaged_suites() -> Path:
    directory = files("agentvax").joinpath("eval", "suites")
    if not isinstance(directory, Path):
        raise StartupError("the packaged suites are not available as plain files")
    return directory


def _model(mode: str, env_file: Path) -> LanguageModel:
    if mode == "mock":
        return MockLLM()
    settings = settings_from_environment(read_environment(env_file, os.environ))
    if settings.llm is None or settings.secrets.llm_api_key is None:
        raise StartupError(
            "live mode needs LLM_PROVIDER, LLM_MODEL and LLM_API_KEY (and LLM_BASE_URL for an "
            "openai-compatible provider) in the environment or in .env"
        )
    try:
        return build(settings.llm, settings.secrets.llm_api_key)
    except UnsupportedProvider as error:
        raise StartupError(str(error)) from error


def _documents(suites: SuiteSet, detector: Detector) -> list[DocumentRecord]:
    """One prediction of the adopted detector per distinct benign document."""
    records: dict[tuple[str, str], DocumentRecord] = {}
    for document in suites.documents():
        if not document.benign:
            continue
        text = render(document.text)
        key = (document.channel, text)
        if key in records:
            continue
        score = detector.score(text)
        records[key] = DocumentRecord(
            text_keccak="0x" + keccak(text.encode("utf-8")).hex(),
            channel=document.channel,
            score=score,
            band=int(detector.band_of_score(score)),
            pressure_flags=int(pressure.scan(text)),
        )
    return list(records.values())


def evaluate(
    *,
    mode: str,
    out: Path,
    suites: SuiteSet,
    suites_dir: Path,
    fixed_sizes_checked: bool,
    repo_root: Path,
    code: CodeRevision,
    llm: LanguageModel,
    config: RunnerConfig,
) -> Path:
    """Runs every suite and writes the ledger. Returns its path. Anvil and every guardian process are stopped
    before this returns, whatever happens."""
    ledger_path = out / f"eval_ledger.{mode}.jsonl"
    with local_stack(config=config, profile=config.profile, labels=WALLET_LABELS, repo_root=repo_root) as stack:
        chain, client, deployment, detector = stack.chain, stack.client, stack.deployment, stack.detector
        ledger = LedgerWriter(ledger_path)
        ledger.append(
            RunRecord(
                mode=mode,  # type: ignore[arg-type]
                chain_id=client.chain_id,
                profile=stack.profile.name,
                suites_dir=suites_location(suites_dir, repo_root),
                code=code,
                fixed_sizes_checked=fixed_sizes_checked,
                suite_files=suites.file_hashes,
                rewording="fixed" if mode == "mock" else "generated",
                detector=DetectorInfo(
                    version=detector.model.version, model_hash=stack.detector_hash, anchor_tx=stack.anchor.tx_hash
                ),
                wallets={w.label: w.address for w in deployment.wallets},  # type: ignore[misc]
                token=deployment.mock_usd.address,
                vault=deployment.savings_vault.address,
                bulletin=deployment.threat_bulletin.address,
            )
        )
        for document in _documents(suites, detector):
            ledger.append(document)

        if mode == "live":
            rewriter = ModelRewriter(llm)

            def reworded(case: AttackCase) -> tuple[AttackForm, ...]:
                forms, records = rewriter.forms(case, config.rewordings_per_attack)
                for record in records:
                    ledger.append(record)
                return forms

        else:

            def reworded(case: AttackCase) -> tuple[AttackForm, ...]:
                return ()

        executor = stack.executor(config, llm, Strings.load())
        scenarios = Scenarios(
            chain=chain,
            executor=executor,
            observer=Observer(client, deployment, stack.signers.roles()),
            ledger=ledger,
            base_snapshot=chain.snapshot(),
            reworded=reworded,
            headline="fixed" if mode == "mock" else "generated",
            detector_model=detector.model,
        )
        scenarios.tasks(suites)
        scenarios.ambiguous(suites)
        scenarios.affordability(suites)
        scenarios.attacks(suites)
        scenarios.sequences(suites)
    return ledger_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the AgentVax evaluation suites on a local Anvil.")
    parser.add_argument("--mode", choices=("mock", "live"), required=True)
    parser.add_argument("--out", type=Path, required=True, help="directory for the summary and the ledger")
    parser.add_argument(
        "--suites", type=Path, help="suite directory (default: the packaged suites, checked for their fixed sizes)"
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd(), help="repository root with contracts/")
    parser.add_argument("--env-file", type=Path, help="environment file for live mode (default: <repo-root>/.env)")
    args = parser.parse_args(argv)

    out: Path = args.out
    code = code_revision(args.repo_root, out)
    out.mkdir(parents=True, exist_ok=True)
    summary_path = out / f"summary.{args.mode}.json"
    summary_path.unlink(missing_ok=True)
    try:
        config = resources.load_model(RunnerConfig, RUNNER_CONFIG)
        if not (args.repo_root / "contracts" / "foundry.toml").is_file():
            raise StartupError(f"{args.repo_root} has no contracts/foundry.toml; pass --repo-root")
        suites_dir = args.suites if args.suites is not None else packaged_suites()
        suites = load_suites(suites_dir, Strings.load())
        fixed_sizes_checked = args.suites is None
        if fixed_sizes_checked:
            problems = fixed_size_problems(suites)
            if problems:
                raise StartupError("the suites do not have their fixed sizes: " + "; ".join(problems))
        llm = _model(args.mode, args.env_file or args.repo_root / ".env")
    except (StartupError, SuiteFileError) as error:
        print(f"evaluation not started: {error}", file=sys.stderr)
        return 2

    try:
        ledger_path = evaluate(
            mode=args.mode,
            out=out,
            suites=suites,
            suites_dir=suites_dir,
            fixed_sizes_checked=fixed_sizes_checked,
            repo_root=args.repo_root,
            code=code,
            llm=llm,
            config=config,
        )
    except FederationFailed as error:
        print(f"evaluation not started: {error}", file=sys.stderr)
        return 2
    finally:
        close = getattr(llm, "close", None)
        if callable(close):
            close()

    records = read_ledger(ledger_path)
    problems = vacuity_problems(records)
    if problems:
        print(f"evaluation failed with {len(problems)} harness errors; no summary written:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    summary = reduce(records)
    summary_path.write_text(summary.to_json(), encoding="utf-8")
    print(f"mode {summary.mode}: wrote {summary_path} and {ledger_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
