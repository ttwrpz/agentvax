"""Client side of the guardian process. Never sees the guardian key.

Launches ``python -m agentvax.guardian.service`` with a minimal environment. The RPC URL goes only in the child's
environment, never on its command line. ``attest`` checks the reply independently of the guardian.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from collections import deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO
from urllib.parse import parse_qsl, urlsplit

from eth_utils import to_checksum_address
from pydantic import ValidationError

from agentvax.config import GuardianTiming
from agentvax.eip712 import attestation_digest, intent_hash, recover_signer
from agentvax.guardian.protocol import (
    PROTOCOL_VERSION,
    AttestationReply,
    AttestationRequest,
    ContentItem,
    ErrorCode,
    ErrorReply,
    FatalLine,
    KeyCreatedLine,
    RPC_URL_VARIABLE,
    ReadyLine,
    SignedAttestation,
)
from agentvax.types import ALLOWED_CHAIN_IDS, Flag, Intent, Source

SERVICE_MODULE = "agentvax.guardian.service"

_CHILD_ENVIRONMENT_NAMES = (
    "PATH",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "VIRTUAL_ENV",
)
"""Variables the child needs to run Python and reach the network. Nothing else is passed, so no secret held in
the parent's environment (owner key, model API key) reaches the guardian process. ``GuardianClient.start`` adds
the RPC URL under ``RPC_URL_VARIABLE`` itself, so a value of that name in the parent's environment never does."""


def child_environment(process_env: Mapping[str, str]) -> dict[str, str]:
    """The environment for the guardian process: only the variables in ``_CHILD_ENVIRONMENT_NAMES``."""
    env = {name: process_env[name] for name in _CHILD_ENVIRONMENT_NAMES if name in process_env}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def redact_rpc_url(text: str, rpc_url: str) -> str:
    """``text`` with the RPC URL and each of its parts removed. Network errors quote a URL in pieces (host, path,
    query), and a provider key can sit in any of them, so every part longer than one character is replaced."""
    parts = urlsplit(rpc_url)
    pieces = {rpc_url, parts.netloc, parts.path, parts.query, parts.fragment}
    pieces.update(part for part in (parts.username, parts.password) if part)
    pieces.update(parts.path.split("/"))
    for pair in parse_qsl(parts.query, keep_blank_values=True):
        pieces.update(pair)
    for piece in sorted((p for p in pieces if len(p) > 1), key=len, reverse=True):
        text = text.replace(piece, "<rpc url>")
    return text


class GuardianUnavailable(RuntimeError):
    """The guardian process could not start, stopped, or did not answer in time."""

    def __init__(self, message: str, code: ErrorCode | None = None) -> None:
        self.code = code
        super().__init__(message)


class GuardianRefused(RuntimeError):
    """The guardian answered with an error code."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(f"guardian refused the request: {code.value}")


class AttestationInvalid(RuntimeError):
    """The guardian's reply does not check out on this side. It is not used."""


class _LineReader:
    """Reads lines from a pipe on a thread so that reads can time out."""

    def __init__(self, stream: IO[bytes], keep: int | None) -> None:
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        self.tail: deque[str] = deque(maxlen=keep or 1)
        self._keep = keep
        self._thread = threading.Thread(target=self._run, args=(stream,), daemon=True)
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    def _run(self, stream: IO[bytes]) -> None:
        for line in iter(stream.readline, b""):
            if self._keep is None:
                self.lines.put(line)
            else:
                self.tail.append(line.decode("utf-8", errors="replace").rstrip())
        self.lines.put(None)

    def next(self, timeout: float) -> bytes | None:
        return self.lines.get(timeout=timeout)


def _run_once(argv: list[str], env: Mapping[str, str], timeout: float) -> bytes:
    result = subprocess.run(argv, env=dict(env), capture_output=True, timeout=timeout, check=False)
    return result.stdout


class GuardianClient:
    """A running guardian process bound to one wallet and chain."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        ready: ReadyLine,
        argv: tuple[str, ...],
        timing: GuardianTiming,
        stdout: _LineReader,
        stderr: _LineReader,
    ) -> None:
        self._process = process
        self.ready = ready
        self.argv = argv
        self._timing = timing
        self._stdout = stdout
        self._stderr = stderr
        self._next_id = 0
        self._lock = threading.Lock()

    @property
    def address(self) -> str:
        return self.ready.guardian

    @property
    def wallet(self) -> str:
        return self.ready.wallet

    @property
    def chain_id(self) -> int:
        return self.ready.chain_id

    # ------------------------------------------------------------------------------------ lifecycle

    @staticmethod
    def create_key_file(key_file: Path, env: Mapping[str, str], timing: GuardianTiming) -> str:
        """Has a guardian process create a new key file at ``key_file`` and returns the guardian address.
        The child generates and writes the key, so this process only learns the address."""
        argv = [sys.executable, "-m", SERVICE_MODULE, "init-key", "--key-file", str(key_file)]
        out = _run_once(argv, env, timing.startup_timeout_seconds)
        try:
            return KeyCreatedLine.model_validate_json(out.strip()).guardian
        except ValidationError as exc:
            raise GuardianUnavailable("guardian could not create the key file", _fatal_code(out)) from exc

    @classmethod
    def start(
        cls,
        *,
        wallet: str,
        chain_id: int,
        rpc_url: str,
        model_path: Path,
        profile: str,
        env: Mapping[str, str],
        timing: GuardianTiming,
        key_file: Path | None = None,
        generate_key: bool = False,
        model_hash: str | None = None,
    ) -> GuardianClient:
        """Starts the guardian process and waits for its ready line. ``rpc_url`` is passed to the child in its
        environment under ``RPC_URL_VARIABLE``, added to ``env``, and never appears in its arguments."""
        if chain_id not in ALLOWED_CHAIN_IDS:
            raise GuardianUnavailable(
                f"chain id {chain_id} is not an allowed test network", ErrorCode.UNSUPPORTED_CHAIN
            )
        if (key_file is None) == (not generate_key):
            raise ValueError("pass exactly one of key_file and generate_key")
        if not rpc_url.strip():
            raise ValueError("rpc_url is empty")
        argv = [
            sys.executable,
            "-m",
            SERVICE_MODULE,
            "--wallet",
            to_checksum_address(wallet),
            "--chain-id",
            str(chain_id),
            "--model",
            str(model_path),
            "--profile",
            profile,
        ]
        if model_hash is not None:
            argv += ["--model-hash", model_hash]
        argv += ["--key-file", str(key_file)] if key_file is not None else ["--generate-key"]

        child_env = {**env, RPC_URL_VARIABLE: rpc_url}
        process = subprocess.Popen(
            argv, env=child_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if process.stdout is None or process.stderr is None:
            _stop(process, timing)
            raise GuardianUnavailable("guardian process has no output pipes")
        stdout = _LineReader(process.stdout, keep=None)
        stderr = _LineReader(process.stderr, keep=50)
        try:
            first = stdout.next(timing.startup_timeout_seconds)
        except queue.Empty:
            _stop(process, timing, (stdout, stderr))
            raise GuardianUnavailable("guardian did not report ready in time") from None
        if first is None:
            _stop(process, timing, (stdout, stderr))
            output = redact_rpc_url(" | ".join(stderr.tail), rpc_url)
            raise GuardianUnavailable("guardian exited before it was ready: " + output)
        try:
            ready = ReadyLine.model_validate_json(first.strip())
        except ValidationError:
            _stop(process, timing, (stdout, stderr))
            raise GuardianUnavailable("guardian could not start", _fatal_code(first)) from None
        if ready.chain_id != chain_id or to_checksum_address(ready.wallet) != to_checksum_address(wallet):
            _stop(process, timing, (stdout, stderr))
            raise GuardianUnavailable("guardian reported a different binding")
        return cls(process, ready, tuple(argv), timing, stdout, stderr)

    def close(self) -> None:
        """Closes the guardian's input so that it exits, and kills it if it does not."""
        _stop(self._process, self._timing, (self._stdout, self._stderr))

    @property
    def pid(self) -> int:
        """Process id of the guardian process."""
        return self._process.pid

    @property
    def running(self) -> bool:
        return self._process.poll() is None

    def __enter__(self) -> GuardianClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------------------------ requests

    def attest(
        self, intent: Intent, content: Sequence[ContentItem], caller_flags: Flag = Flag.NONE
    ) -> SignedAttestation:
        """Asks the guardian to attest ``intent`` for its wallet. ``content`` is the raw untrusted material behind
        the intent. ``caller_flags`` are flags this side found by rule, and the guardian can only add to them."""
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
        request = AttestationRequest(
            protocol_version=PROTOCOL_VERSION,
            request_id=request_id,
            wallet=self.wallet,
            chain_id=self.chain_id,
            intent=intent,
            content=tuple(content),
            caller_flags=int(caller_flags),
        )
        return self.request(request)

    def request(self, request: AttestationRequest) -> SignedAttestation:
        """Sends a prepared request and checks the reply. Raises ``GuardianRefused`` with the guardian's error
        code, or ``AttestationInvalid`` if the reply does not check out here."""
        with self._lock:
            raw = self._roundtrip(request.model_dump_json())
        try:
            reply = json.loads(raw)
        except ValueError as exc:
            raise AttestationInvalid("reply is not JSON") from exc
        if not isinstance(reply, dict) or reply.get("request_id") != request.request_id:
            raise AttestationInvalid("reply does not answer this request")
        if reply.get("ok") is False:
            raise GuardianRefused(ErrorReply.model_validate_json(raw).error)
        result = AttestationReply.model_validate_json(raw).result
        self._check(result, request)
        return result

    def _roundtrip(self, line: str) -> bytes:
        if self._process.poll() is not None or self._process.stdin is None:
            raise GuardianUnavailable("guardian process is not running")
        try:
            self._process.stdin.write(line.encode("utf-8") + b"\n")
            self._process.stdin.flush()
        except OSError as exc:
            raise GuardianUnavailable("guardian process closed its input") from exc
        try:
            reply = self._stdout.next(self._timing.request_timeout_seconds)
        except queue.Empty:
            raise GuardianUnavailable("guardian did not answer in time") from None
        if reply is None:
            raise GuardianUnavailable("guardian process stopped")
        return reply.strip()

    def _check(self, result: SignedAttestation, request: AttestationRequest) -> None:
        expected_intent = intent_hash(request.intent, self.chain_id, self.wallet)
        if result.attestation.intent_hash != expected_intent:
            raise AttestationInvalid("attestation names a different intent")
        if result.digest != attestation_digest(result.attestation, self.chain_id, self.wallet):
            raise AttestationInvalid("attestation digest does not match")
        if request.content and result.attestation.source != Source.EXTERNAL_CONTENT:
            raise AttestationInvalid("attestation hides that untrusted content was present")
        if result.attestation.flags & request.caller_flags != request.caller_flags:
            raise AttestationInvalid("attestation dropped a flag the caller set")
        if to_checksum_address(result.guardian) != to_checksum_address(self.address):
            raise AttestationInvalid("attestation names another guardian")
        if recover_signer(result.digest, result.signature) != to_checksum_address(self.address):
            raise AttestationInvalid("signature does not recover to the guardian")


def _fatal_code(raw: bytes) -> ErrorCode | None:
    try:
        return FatalLine.model_validate_json(raw.strip().splitlines()[0]).error
    except (ValidationError, IndexError):
        return None


def _stop(process: subprocess.Popen[bytes], timing: GuardianTiming, readers: Sequence[_LineReader] = ()) -> None:
    """Closes the child's input, waits for it to exit (killing it after the timeout), lets the reader threads
    reach the end of the pipes, then closes the pipes."""
    if process.poll() is None:
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=timing.shutdown_timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timing.shutdown_timeout_seconds)
    for reader in readers:
        reader.join(timing.shutdown_timeout_seconds)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except OSError:
                pass
