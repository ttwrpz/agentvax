"""The guardian process. The only process that ever holds the guardian key.

Serves one wallet and chain id. Per request it checks the binding and the on-chain guardian address, recomputes
the intent hash, scores the untrusted content, sets flags and source, and signs the attestation.
The RPC URL comes from ``AGENTVAX_GUARDIAN_RPC_URL`` and the key is never printed, logged or sent.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO

from eth_abi import decode as abi_decode
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import keccak, to_checksum_address
from pydantic import ValidationError
from web3 import Web3

from agentvax import pressure
from agentvax.config import ChainTuning, load_profile
from agentvax.detector.model import Detector, DetectorModel, load_if_hash_matches, load_model, model_hash
from agentvax.eip712 import attestation_digest, attestation_typed_data, intent_hash
from agentvax.guardian.protocol import (
    MAX_LINE_BYTES,
    PROTOCOL_VERSION,
    RPC_URL_VARIABLE,
    AttestationReply,
    AttestationRequest,
    ErrorCode,
    ErrorReply,
    FatalLine,
    KeyCreatedLine,
    ReadyLine,
    SignedAttestation,
)
from agentvax.types import (
    ALLOWED_CHAIN_IDS,
    EIP712_NAME,
    EIP712_VERSION,
    Attestation,
    Band,
    Flag,
    Source,
)

_GUARDIAN_SELECTOR = keccak(text="guardian()")[:4]
_EIP712_DOMAIN_SELECTOR = keccak(text="eip712Domain()")[:4]
_EIP712_DOMAIN_TYPES = ["bytes1", "string", "string", "uint256", "address", "bytes32", "uint256[]"]


class GuardianError(Exception):
    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class Guardian:
    """Attests intents for one wallet. Holds the key and is constructed only by ``main`` in this process."""

    def __init__(
        self,
        account: LocalAccount,
        wallet: str,
        chain_id: int,
        web3: Web3,
        detector: Detector,
        lifetime: int,
    ) -> None:
        self.__account = account
        self.wallet = to_checksum_address(wallet)
        self.chain_id = chain_id
        self._w3 = web3
        self._detector = detector
        self._lifetime = lifetime
        self._domain_checked = False

    @property
    def address(self) -> str:
        return self.__account.address

    # ------------------------------------------------------------------------------------ chain checks

    def _call(self, selector: bytes) -> bytes:
        try:
            return bytes(self._w3.eth.call({"to": self.wallet, "data": "0x" + selector.hex()}))
        except Exception as exc:
            raise GuardianError(ErrorCode.CHAIN_UNAVAILABLE) from exc

    def _check_wallet(self) -> None:
        try:
            node_chain = int(self._w3.eth.chain_id)
        except Exception as exc:
            raise GuardianError(ErrorCode.CHAIN_UNAVAILABLE) from exc
        if node_chain != self.chain_id:
            raise GuardianError(ErrorCode.WRONG_CHAIN)
        raw = self._call(_GUARDIAN_SELECTOR)
        if len(raw) != 32 or to_checksum_address(raw[12:]) != self.address:
            raise GuardianError(ErrorCode.NOT_WALLET_GUARDIAN)
        if not self._domain_checked:
            try:
                _, name, version, chain, contract, _, _ = abi_decode(
                    _EIP712_DOMAIN_TYPES, self._call(_EIP712_DOMAIN_SELECTOR)
                )
            except GuardianError:
                raise
            except Exception as exc:
                raise GuardianError(ErrorCode.DOMAIN_MISMATCH) from exc
            if (name, version, int(chain), to_checksum_address(contract)) != (
                EIP712_NAME,
                EIP712_VERSION,
                self.chain_id,
                self.wallet,
            ):
                raise GuardianError(ErrorCode.DOMAIN_MISMATCH)
            self._domain_checked = True

    def _valid_until(self) -> int:
        """The later of the latest block time and this host's clock, plus the lifetime.

        The latest block alone can be old on a local chain that mines only on demand, which would make a fresh
        attestation expire at once. The host clock alone can lag a chain whose time was moved forward. The
        contract still refuses any ``validUntil`` more than ``MAX_ATTESTATION_TTL`` after the block it lands in,
        so a host clock running fast can only make an attestation fail, never last longer.
        """
        try:
            block_time = int(self._w3.eth.get_block("latest")["timestamp"])
        except Exception as exc:
            raise GuardianError(ErrorCode.CHAIN_UNAVAILABLE) from exc
        return max(block_time, int(time.time())) + self._lifetime

    # ------------------------------------------------------------------------------------ attesting

    def attest(self, request: AttestationRequest) -> SignedAttestation:
        if to_checksum_address(request.wallet) != self.wallet:
            raise GuardianError(ErrorCode.WRONG_WALLET)
        if request.chain_id != self.chain_id:
            raise GuardianError(ErrorCode.WRONG_CHAIN)
        self._check_wallet()

        band = Band.LOW
        flags = Flag(request.caller_flags)
        for item in request.content:
            band = max(band, self._detector.band(item.text))
            flags |= pressure.scan(item.text)
        source = Source.EXTERNAL_CONTENT if request.content else Source.OWNER_INSTRUCTION

        attestation = Attestation(
            intent_hash=intent_hash(request.intent, self.chain_id, self.wallet),
            band=Band(band),
            source=source,
            flags=int(flags),
            valid_until=self._valid_until(),
        )
        digest = attestation_digest(attestation, self.chain_id, self.wallet)
        signed = self.__account.sign_typed_data(
            full_message=attestation_typed_data(attestation, self.chain_id, self.wallet)
        )
        if "0x" + bytes(signed.message_hash).hex() != digest:
            raise GuardianError(ErrorCode.DOMAIN_MISMATCH)
        return SignedAttestation(
            attestation=attestation,
            signature="0x" + bytes(signed.signature).hex(),
            guardian=self.address,
            digest=digest,
        )

    def handle(self, line: bytes) -> str:
        """One request line in, one reply line out. Error replies carry only a fixed code."""
        request_id: int | None = None
        try:
            envelope = json.loads(line)
            if isinstance(envelope, dict) and isinstance(envelope.get("request_id"), int):
                request_id = envelope["request_id"]
            if not isinstance(envelope, dict) or envelope.get("protocol_version") != PROTOCOL_VERSION:
                raise GuardianError(ErrorCode.UNSUPPORTED_PROTOCOL)
            request = AttestationRequest.model_validate_json(line)
            result = self.attest(request)
            return AttestationReply(
                protocol_version=PROTOCOL_VERSION, request_id=request.request_id, ok=True, result=result
            ).model_dump_json()
        except GuardianError as exc:
            code = exc.code
        except (ValueError, ValidationError):
            code = ErrorCode.BAD_REQUEST
        return ErrorReply(
            protocol_version=PROTOCOL_VERSION, request_id=request_id, ok=False, error=code
        ).model_dump_json()


# ---------------------------------------------------------------------------------------------- keys


def create_key_file(path: Path) -> str:
    """Creates a new key in a new file readable only by this user and returns its address. Never overwrites."""
    account = Account.create()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write("0x" + bytes(account.key).hex() + "\n")
    return account.address


def _load_key_file(path: Path) -> LocalAccount:
    return Account.from_key(path.read_text(encoding="ascii").strip())


# ---------------------------------------------------------------------------------------------- process


def _emit(out: BinaryIO, line: str) -> None:
    out.write(line.encode("utf-8") + b"\n")
    out.flush()


def _fatal(out: BinaryIO, code: ErrorCode) -> int:
    _emit(out, FatalLine(protocol_version=PROTOCOL_VERSION, event="fatal", error=code).model_dump_json())
    return 2


def _read_line(stream: BinaryIO) -> bytes | None:
    """Next line, ``b""`` for a line over the limit (consumed and discarded), ``None`` at end of input."""
    line = stream.readline(MAX_LINE_BYTES + 1)
    if not line:
        return None
    if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
        while True:
            rest = stream.readline(MAX_LINE_BYTES)
            if not rest or rest.endswith(b"\n"):
                break
        return b""
    return line


def serve(guardian: Guardian, stdin: BinaryIO, stdout: BinaryIO) -> None:
    while True:
        line = _read_line(stdin)
        if line is None:
            return
        if line == b"":
            reply = ErrorReply(
                protocol_version=PROTOCOL_VERSION, request_id=None, ok=False, error=ErrorCode.REQUEST_TOO_LARGE
            ).model_dump_json()
        elif not line.strip():
            continue
        else:
            reply = guardian.handle(line)
        _emit(stdout, reply)


def _init_key(argv: list[str], stdout: BinaryIO) -> int:
    parser = argparse.ArgumentParser(prog="agentvax.guardian.service init-key")
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        address = create_key_file(args.key_file)
    except OSError:
        return _fatal(stdout, ErrorCode.KEY_UNAVAILABLE)
    _emit(
        stdout,
        KeyCreatedLine(protocol_version=PROTOCOL_VERSION, event="key_created", guardian=address).model_dump_json(),
    )
    return 0


def _serve(argv: list[str], env: Mapping[str, str], stdin: BinaryIO, stdout: BinaryIO) -> int:
    parser = argparse.ArgumentParser(
        prog="agentvax.guardian.service", epilog=f"The RPC endpoint is read from {RPC_URL_VARIABLE}."
    )
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--chain-id", type=int, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--model-hash", help="adopt the model only if its keccak256 equals this anchored hash")
    parser.add_argument("--profile", required=True, help="deployment profile giving the attestation lifetime")
    parser.add_argument("--rpc-timeout", type=float, default=ChainTuning().rpc_timeout_seconds)
    keys = parser.add_mutually_exclusive_group(required=True)
    keys.add_argument("--key-file", type=Path)
    keys.add_argument("--generate-key", action="store_true")
    args = parser.parse_args(argv)

    if args.chain_id not in ALLOWED_CHAIN_IDS:
        return _fatal(stdout, ErrorCode.UNSUPPORTED_CHAIN)
    try:
        wallet = to_checksum_address(args.wallet)
    except ValueError:
        return _fatal(stdout, ErrorCode.BAD_REQUEST)
    try:
        lifetime = load_profile(args.profile).guardian.attestation_lifetime
    except (ValueError, ValidationError):
        return _fatal(stdout, ErrorCode.BAD_REQUEST)
    try:
        model: DetectorModel = (
            load_if_hash_matches(args.model, args.model_hash) if args.model_hash else load_model(args.model)
        )
    except (OSError, ValueError):
        return _fatal(stdout, ErrorCode.MODEL_REJECTED)

    rpc_url = env.get(RPC_URL_VARIABLE, "").strip()
    if not rpc_url:
        return _fatal(stdout, ErrorCode.CHAIN_UNAVAILABLE)
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": args.rpc_timeout}))
    try:
        node_chain = int(w3.eth.chain_id)
    except Exception:
        return _fatal(stdout, ErrorCode.CHAIN_UNAVAILABLE)
    if node_chain not in ALLOWED_CHAIN_IDS:
        return _fatal(stdout, ErrorCode.UNSUPPORTED_CHAIN)
    if node_chain != args.chain_id:
        return _fatal(stdout, ErrorCode.WRONG_CHAIN)

    try:
        account = Account.create() if args.generate_key else _load_key_file(args.key_file)
    except (OSError, ValueError):
        return _fatal(stdout, ErrorCode.KEY_UNAVAILABLE)

    guardian = Guardian(account, wallet, args.chain_id, w3, Detector(model), lifetime)
    ready = ReadyLine(
        protocol_version=PROTOCOL_VERSION,
        event="ready",
        guardian=guardian.address,
        wallet=wallet,
        chain_id=args.chain_id,
        model_version=model.version,
        model_hash=model_hash(model),
        attestation_lifetime=lifetime,
    )
    _emit(stdout, ready.model_dump_json())
    serve(guardian, stdin, stdout)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == "init-key":
        return _init_key(args[1:], sys.stdout.buffer)
    return _serve(args, os.environ, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
