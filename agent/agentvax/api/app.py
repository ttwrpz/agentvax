"""The interface: a FastAPI app and one static page.

``python -m agentvax.api.app`` serves a real deployment with the hosted model. It has no import path to the mock
model: the demonstration entry point ``python -m agentvax.api.demo`` is the only one that builds it. It finds the
deployment, the agent key, the guardian key file and the detector model where the evidence run left them, and its
guardian runs only the model whose hash is anchored in the deployment's ThreatBulletin. Without an
anchored model it does not start.

One page serves every wallet the app is given. Each request names its wallet in the ``wallet`` query parameter, and
an unknown name is refused, so the owner of one wallet acts only on that wallet.

Security: Every request must carry a ``Host`` the page is served from. Every POST must also carry the
session token that the served page embeds (header ``X-AgentVax-Session``) and an ``Origin`` the page is served
from. The server assigns the source of everything: the client sends an instruction and, separately, documents, and
the documents go through the quarantined reader. The page renders every dynamic value with ``textContent``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import ExitStack
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from agentvax import resources
from agentvax.api import reads
from agentvax.api.models import (
    ActionResult,
    ApproveRequest,
    ChangeRequest,
    ChatRequest,
    ChatResponse,
    ConfirmAttackRequest,
    ExpectedIncomeRequest,
    ExtendHoldRequest,
    ItemRequest,
    ProposePayeeRequest,
    StateResponse,
    WalletRow,
)
from agentvax.api.services import ExpectedIncomeBook, OwnerActions, PayeeNames, Services
from agentvax.capsules import ConfirmedAttack
from agentvax.chain.artifacts import ArtifactStore
from agentvax.chain.client import ChainClient, TransactionFailed, TransactionReverted, UnsupportedChain
from agentvax.chain.deploy import Deployment, WalletRecord
from agentvax.config import ChainTuning, GuardianTiming, NetworkConfig, read_environment, settings_from_environment
from agentvax.confirmation import ConfirmationAnswers, Requester, Verdict, evaluate, outcome_text
from agentvax.detector.model import Detector, ModelFormatError, ModelHashMismatch, model_hash
from agentvax.evidence.keys import KeyStore
from agentvax.evidence.layout import WorkLayout, testnet_deployment_file, testnet_work_directory
from agentvax.explain import ExpectedIncomeItem
from agentvax.fed.anchor import ModelNotAnchored, adopt, latest_anchor
from agentvax.guardian.client import GuardianClient, child_environment
from agentvax.llm import UnsupportedProvider, build
from agentvax.memory import MemoryStore
from agentvax.planner import OwnerInstruction
from agentvax.reader import UntrustedContent
from agentvax.runtime import Agent
from agentvax.text import Strings, describe_duration
from agentvax.types import TOKEN_UNIT, Channel, Task

LOOPBACK = "127.0.0.1"
SESSION_HEADER = "X-AgentVax-Session"
PAGE_PATH = "api/static/index.html"
TOKEN_PLACEHOLDER = "__SESSION_TOKEN__"
MODE_PLACEHOLDER = "__MODE__"
STATIC_FILES = {"app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def create_app(wallets: Mapping[str, Services]) -> FastAPI:
    """The app for ``wallets``, by label. Its session token is random and is known only to the pages it serves. All
    wallets share one wording table, one mode and one set of served addresses."""
    if not wallets:
        raise ValueError("at least one wallet is needed")
    first = next(iter(wallets.values()))
    strings = first.strings
    mode = first.mode
    if any(w.mode != mode for w in wallets.values()):
        raise ValueError("every wallet of one app has the same mode")
    allowed_hosts = frozenset().union(*(w.allowed_hosts for w in wallets.values()))
    allowed_origins = frozenset().union(*(w.allowed_origins for w in wallets.values()))
    token = secrets.token_urlsafe(32)
    app = FastAPI(title="AgentVax", docs_url=None, redoc_url=None, openapi_url=None)

    def refuse(key: str) -> HTTPException:
        return HTTPException(status_code=403, detail=strings.render(key))

    @app.middleware("http")
    async def check_host(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"detail": strings.render("api.refused_host")}, status_code=403, headers=SECURITY_HEADERS)
        response: Response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def guard(request: Request, session: Annotated[str | None, Header(alias=SESSION_HEADER)] = None) -> None:
        if request.headers.get("origin") not in allowed_origins:
            raise refuse("api.refused_origin")
        if session is None or not secrets.compare_digest(session.encode("utf-8"), token.encode("utf-8")):
            raise refuse("api.refused_session")

    def wallet_services(wallet: Annotated[str, Query(min_length=1, max_length=16)]) -> Services:
        found = wallets.get(wallet)
        if found is None:
            raise HTTPException(status_code=404, detail=strings.render("api.unknown_wallet"))
        return found

    def result(
        ok: bool, key: str, status: int = 200, params: dict[str, object] | None = None, **fields: Any
    ) -> JSONResponse:
        body = ActionResult(mode=mode, ok=ok, text=strings.render(key, **(params or {})), **fields)
        return JSONResponse(body.model_dump(mode="json"), status_code=status)

    def failed(error: Exception) -> JSONResponse:
        if isinstance(error, TransactionReverted):
            key = f"revert.{_snake(error.error_name)}"
            return result(False, key if strings.has(key) else "revert.other", 409)
        return result(False, "agent.chain_failed", 502)

    # ------------------------------------------------------------------------------------ the page

    @app.get("/", include_in_schema=False)
    def page() -> Response:
        html = resources.read_text(PAGE_PATH).replace(TOKEN_PLACEHOLDER, token).replace(MODE_PLACEHOLDER, mode)
        return Response(html, media_type="text/html; charset=utf-8")

    @app.get("/static/{name}", include_in_schema=False)
    def static(name: str) -> Response:
        media_type = STATIC_FILES.get(name)
        if media_type is None:
            raise HTTPException(status_code=404)
        return Response(resources.read_text(f"api/static/{name}"), media_type=media_type)

    @app.get("/strings")
    def all_strings() -> dict[str, str]:
        return strings.table()

    @app.get("/api/wallets", response_model=list[WalletRow])
    def wallet_list() -> list[WalletRow]:
        return [
            WalletRow(
                label=label,
                about=strings.render(f"ui.wallet.about.{label}") if strings.has(f"ui.wallet.about.{label}") else None,
            )
            for label in wallets
        ]

    @app.get("/api/state", response_model=StateResponse)
    def state(services: Services = Depends(wallet_services)) -> StateResponse:
        return reads.build_state(services)

    # ------------------------------------------------------------------------------------ actions

    api = APIRouter(prefix="/api", dependencies=[Depends(guard)])

    @api.post("/chat", response_model=ChatResponse)
    def chat(body: ChatRequest, services: Services = Depends(wallet_services)) -> ChatResponse:
        documents = [UntrustedContent(channel=Channel[d.channel.upper()], text=d.text) for d in body.documents]
        with services.chain_lock:
            reply = services.agent.handle(OwnerInstruction(text=body.instruction), documents)
        return ChatResponse(mode=services.mode, reply=reply, link=services.transaction_link(reply.tx_hash))

    @api.post("/owner/cancel")
    def cancel(body: ItemRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                tx = services.owner.cancel(body.item_id)
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        return result(True, "action.cancelled", tx_hash=tx, link=services.transaction_link(tx))

    @api.post("/owner/execute")
    def execute(body: ItemRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                tx = services.owner.execute(body.item_id)
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        return result(True, "action.executed", tx_hash=tx, link=services.transaction_link(tx))

    @api.post("/owner/extend-hold")
    def extend_hold(body: ExtendHoldRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                tx = services.owner.extend_hold(body.item_id, body.extra_seconds)
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        return result(
            True,
            "action.hold_extended",
            tx_hash=tx,
            link=services.transaction_link(tx),
            params={"extra": describe_duration(strings, body.extra_seconds)},
        )

    @api.post("/owner/freeze")
    def freeze(services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                tx = services.owner.freeze()
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        return result(True, "action.frozen", tx_hash=tx, link=services.transaction_link(tx))

    @api.post("/owner/approve")
    def approve(body: ApproveRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        """Approves a proposed item. An item that carries a flag, a pressure hold or a matching alert is approved
        only through the considered confirmation. The name must be typed exactly. If anyone but the owner asked, the
        hold is lengthened first. Nothing here can shorten a hold."""
        with services.chain_lock:
            if body.item_id > reads.item_count(services):
                return result(False, "revert.unknown_item", 404)
            item = reads.stored_item(services, body.item_id)
            view = services.chain.wallet_view(services.wallet)
            context = None
            if item.status == 2:
                context = reads.confirmation_context(services, view, item, reads.matching_capsules(services, item))
            outcome = None
            if context is not None:
                if body.confirmation is None:
                    return result(False, "api.confirmation_required", 422, verdict="confirmation_required")
                outcome = evaluate(
                    context,
                    ConfirmationAnswers(
                        typed_payee_name=body.confirmation.typed_payee_name,
                        requester=Requester[body.confirmation.requester.upper()],
                    ),
                )
                if outcome.verdict is Verdict.NAME_MISMATCH:
                    body_ = ActionResult(
                        mode=services.mode,
                        ok=False,
                        text=outcome_text(strings, outcome),
                        verdict=outcome.verdict.name.lower(),
                    )
                    return JSONResponse(body_.model_dump(mode="json"), status_code=422)
            try:
                if outcome is not None and outcome.extend_hold_seconds:
                    services.owner.extend_hold(body.item_id, outcome.extend_hold_seconds)
                tx = services.owner.approve(body.item_id)
            except (TransactionReverted, TransactionFailed) as error:
                return failed(error)
        approved = strings.render("action.approved")
        text = approved if outcome is None else f"{outcome_text(strings, outcome)} {approved}"
        done = ActionResult(
            mode=services.mode,
            ok=True,
            text=text,
            verdict=None if outcome is None else outcome.verdict.name.lower(),
            tx_hash=tx,
            link=services.transaction_link(tx),
        )
        return JSONResponse(done.model_dump(mode="json"))

    @api.post("/owner/payees/propose")
    def propose_payee(body: ProposePayeeRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                proposed = services.owner.propose_payee(body.name, body.account)
                delay = services.chain.wallet_view(services.wallet).mandate.loosening_delay
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        return result(
            True,
            "action.payee_proposed",
            tx_hash=proposed.tx_hash,
            link=services.transaction_link(proposed.tx_hash),
            change_id=proposed.change_id,
            ready_at=proposed.ready_at,
            params={"payee": body.name, "delay": describe_duration(strings, delay)},
        )

    @api.post("/owner/payees/apply")
    def apply_payee(body: ChangeRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                added = services.owner.apply_payee(body.change_id)
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        except ValueError:
            return result(False, "action.not_a_payee_change", 409)
        name = services.agent.payee_name(added.payee_id) or strings.render("payee.unnamed", id=added.payee_id)
        return result(
            True,
            "action.payee_added",
            tx_hash=added.tx_hash,
            link=services.transaction_link(added.tx_hash),
            params={"payee": name},
        )

    @api.post("/owner/changes/cancel")
    def cancel_change(body: ChangeRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        try:
            with services.chain_lock:
                tx = services.owner.cancel_change(body.change_id)
        except (TransactionReverted, TransactionFailed) as error:
            return failed(error)
        return result(True, "action.change_cancelled", tx_hash=tx, link=services.transaction_link(tx))

    @api.post("/owner/confirm-attack")
    def confirm_attack(body: ConfirmAttackRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        """The allowance goes to zero at once. If asked, the capsule drafted by rule is published."""
        with services.chain_lock:
            if body.item_id > reads.item_count(services):
                return result(False, "revert.unknown_item", 404)
            item = reads.stored_item(services, body.item_id)
            attack = ConfirmedAttack(flags=item.flags, channel=Channel[body.channel.upper()], task=Task(item.task))
            try:
                confirmed = services.owner.confirm_attack(attack, body.publish)
            except (TransactionReverted, TransactionFailed) as error:
                return failed(error)
        link = services.transaction_link(confirmed.publish_tx_hash or confirmed.confirm_tx_hash)
        if confirmed.capsule_id is not None:
            return result(
                True,
                "action.attack_published",
                tx_hash=confirmed.publish_tx_hash,
                link=link,
                capsule_id=confirmed.capsule_id,
                params={"capsule": confirmed.capsule_id},
            )
        key = "action.attack_confirmed" if confirmed.draft is not None else "action.attack_no_capsule"
        return result(True, key, tx_hash=confirmed.confirm_tx_hash, link=link)

    @api.post("/owner/expected-income")
    def expected_income(body: ExpectedIncomeRequest, services: Services = Depends(wallet_services)) -> JSONResponse:
        """Notes income the owner expects. It is shown beside the wallet's numbers and never counted."""
        services.income.add(
            ExpectedIncomeItem(amount=int(Decimal(body.amount) * TOKEN_UNIT), expected_at=body.expected_at)
        )
        return result(True, "action.income_noted")

    app.include_router(api)
    return app


# ---------------------------------------------------------------------------------------------- entry point


class StartupError(RuntimeError):
    """The app cannot start. The message says what is missing."""


RUN_EVIDENCE_FIRST = "Run make evidence first."


def _key_from_file(path: Path) -> LocalAccount:
    return Account.from_key(path.read_text(encoding="ascii").strip())


def _read_deployment(path: Path, label: str) -> tuple[Deployment, WalletRecord]:
    if not path.is_file():
        raise StartupError(f"there is no deployment at {path}. {RUN_EVIDENCE_FIRST}")
    try:
        deployment = Deployment.from_file_dict(json.loads(path.read_text(encoding="utf-8")))
        return deployment, deployment.wallet(label)
    except (OSError, ValueError, KeyError, ValidationError) as error:
        raise StartupError(f"cannot read wallet {label} from {path}: {error}") from error


def adopt_anchored_model(client: ChainClient, deployment: Deployment, model_path: Path) -> Detector:
    """The detector in ``model_path``, only if it is the latest model anchored in the deployment's ThreatBulletin.
    There is no fallback: with no anchored model, no file, or a file whose hash or version differs from
    the anchor, the app does not start."""
    bulletin = deployment.threat_bulletin.address
    try:
        version, _ = latest_anchor(client, bulletin)
    except ModelNotAnchored:
        raise StartupError(
            f"the ThreatBulletin at {bulletin} holds no anchored detector model. {RUN_EVIDENCE_FIRST}"
        ) from None
    if not model_path.is_file():
        raise StartupError(
            f"the anchored detector model, version {version}, is not at {model_path}. "
            f"Pass --model with the anchored file, or run make evidence first."
        )
    try:
        return adopt(model_path, client, bulletin)
    except (ModelHashMismatch, ModelFormatError, ModelNotAnchored) as error:
        raise StartupError(f"the detector model at {model_path} is not the anchored one: {error}") from None


def build_services(args: argparse.Namespace, stack: ExitStack, process_env: Mapping[str, str]) -> Services:
    """Everything the app serves, checked before it starts. The deployment and the key files of the evidence run
    are found first, so that nothing is read from the environment or from a key file when one of them is missing."""
    root: Path = args.repo_root
    deployment_path: Path = args.deployment or testnet_deployment_file(root)
    deployment, record = _read_deployment(deployment_path, args.wallet_label)
    work = WorkLayout(args.evidence_dir or testnet_work_directory(root, deployment.chain_id))
    keys = KeyStore(work.keys)
    try:
        agent_key_file: Path = args.agent_key_file or keys.agent_key_file(args.wallet_label)
        guardian_key_file: Path = args.guardian_key_file or keys.guardian_key_file(args.wallet_label)
    except ValueError as error:
        raise StartupError(str(error)) from None
    for role, path in (("agent", agent_key_file), ("guardian", guardian_key_file)):
        if not path.is_file():
            raise StartupError(f"the {role} key file {path} does not exist. {RUN_EVIDENCE_FIRST}")
    model_path: Path = args.model or work.model

    env = read_environment(args.env_file or root / ".env", process_env)
    try:
        settings = settings_from_environment(env)
    except ValueError as error:
        raise StartupError(f"the network settings are refused: {error}") from None
    network: NetworkConfig | None = settings.testnet
    if network is None:
        raise StartupError("TESTNET_RPC_URL and TESTNET_CHAIN_ID are needed in the environment or in .env")
    if deployment.chain_id != network.chain_id:
        raise StartupError(f"the deployment is for chain {deployment.chain_id}, the network is {network.chain_id}")
    owner_key = settings.secrets.owner_private_key
    if owner_key is None:
        raise StartupError("OWNER_PRIVATE_KEY is needed in the environment or in .env")
    if settings.llm is None or settings.secrets.llm_api_key is None:
        raise StartupError("LLM_PROVIDER, LLM_MODEL and LLM_API_KEY are needed in the environment or in .env")
    try:
        llm = build(settings.llm, settings.secrets.llm_api_key)
    except UnsupportedProvider as error:
        raise StartupError(str(error)) from error
    close = getattr(llm, "close", None)
    if callable(close):
        stack.callback(close)

    store = ArtifactStore(root / "contracts", root / "contracts" / "out", "forge")
    try:
        client = ChainClient(network.rpc_url, store, ChainTuning(), expected_chain_id=network.chain_id)
    except UnsupportedChain as error:
        raise StartupError(f"the node at TESTNET_RPC_URL is refused: {error}") from None
    owner = Account.from_key(owner_key.get_secret_value())
    agent_account = _key_from_file(agent_key_file)
    if owner.address != record.owner or agent_account.address != record.agent:
        raise StartupError("the owner key or the agent key does not match the wallet in the deployment")

    detector = adopt_anchored_model(client, deployment, model_path)
    adopted_hash = model_hash(detector.model)
    guardian = GuardianClient.start(
        wallet=record.address,
        chain_id=client.chain_id,
        rpc_url=network.rpc_url,
        model_path=model_path,
        profile=deployment.profile,
        env=child_environment(process_env),
        timing=GuardianTiming(),
        key_file=guardian_key_file,
        model_hash=adopted_hash,
    )
    stack.callback(guardian.close)
    if guardian.address != record.guardian:
        raise StartupError("the guardian key does not match the wallet in the deployment")
    if guardian.ready.model_hash != adopted_hash or guardian.ready.model_version != detector.model.version:
        raise StartupError("the guardian reported a detector model other than the anchored one")

    memory = MemoryStore(args.memory)
    stack.callback(memory.close)
    names = PayeeNames(args.payees)
    strings = Strings.load()
    agent = Agent(
        llm=llm,
        chain=client,
        wallet=record.address,
        agent_signer=agent_account,
        guardian=guardian,
        memory=memory,
        strings=strings,
        payee_names=names.names,
    )
    origins = (f"http://{LOOPBACK}:{args.port}", f"http://localhost:{args.port}")
    return Services(
        agent=agent,
        chain=client,
        wallet=record.address,
        owner=OwnerActions(
            client=client,
            signer=owner,
            wallet=record.address,
            agent=agent,
            memory=memory,
            names=names,
            guard_version=detector.model.version,
        ),
        strings=strings,
        explorer_url=network.explorer_url,
        allowed_origins=origins,
        mode="live",
        names=names,
        income=ExpectedIncomeBook(),
        log_from_block=record.block_number,
    )


def parser() -> argparse.ArgumentParser:
    """The command line. Every path defaults to where ``make evidence`` leaves the deployment, the keys and the
    anchored model, so ``make ui`` needs no arguments once the evidence run has deployed and anchored."""
    built = argparse.ArgumentParser(description="Serve the AgentVax interface for a deployed wallet.")
    built.add_argument("--repo-root", type=Path, default=Path.cwd(), help="repository root with contracts/")
    built.add_argument("--deployment", type=Path, help="deployment file (default: deployments/testnet.json)")
    built.add_argument("--wallet-label", default="A")
    built.add_argument(
        "--evidence-dir",
        type=Path,
        help="work directory of the evidence run with its keys and model (default: secrets/evidence/<chain id>)",
    )
    built.add_argument("--agent-key-file", type=Path, help="agent session key (default: from the evidence run)")
    built.add_argument("--guardian-key-file", type=Path, help="guardian key file (default: from the evidence run)")
    built.add_argument(
        "--model", type=Path, help="detector model, adopted only if it is the anchored one (default: evidence run)"
    )
    built.add_argument("--memory", type=Path, default=Path("agent_memory.sqlite"))
    built.add_argument("--payees", type=Path, default=Path("payee_names.json"), help="file for payee names")
    built.add_argument("--env-file", type=Path, help="environment file (default: <repo-root>/.env)")
    built.add_argument("--port", type=int, default=8765)
    return built


def main(argv: Sequence[str] | None = None, process_env: Mapping[str, str] | None = None) -> int:
    args = parser().parse_args(argv)
    with ExitStack() as stack:
        try:
            services = build_services(args, stack, os.environ if process_env is None else process_env)
        except StartupError as error:
            print(f"interface not started: {error}", file=sys.stderr)
            return 2
        uvicorn.run(create_app({args.wallet_label: services}), host=LOOPBACK, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
