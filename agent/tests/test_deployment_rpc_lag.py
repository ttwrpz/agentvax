"""A mined receipt can become visible before deployed code on a public RPC."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentvax.chain.deploy import DeploymentError, _check_runtime_code
from agentvax.chain.client import ChainClient, TransactionFailed
from agentvax.config import ChainTuning


def artifact():
    return SimpleNamespace(
        deployed_bytecode="0x60006000", deployed_link_references={},
        immutable_references=(), fqn="src/Example.sol:Example",
    )


def test_runtime_verification_waits_for_absent_code(monkeypatch):
    monkeypatch.setattr("agentvax.chain.deploy.time.sleep", lambda _: None)
    client = SimpleNamespace(code_at=Mock(side_effect=[b"", b"", bytes.fromhex("60006000")]))
    _check_runtime_code(client, "address", artifact(), {}, False)
    assert client.code_at.call_count == 3


def test_runtime_verification_rejects_nonempty_mismatch_without_retry(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("agentvax.chain.deploy.time.sleep", sleep)
    client = SimpleNamespace(code_at=Mock(return_value=bytes.fromhex("60006001")))
    with pytest.raises(DeploymentError, match="does not match"):
        _check_runtime_code(client, "address", artifact(), {}, False)
    sleep.assert_not_called()


def test_runtime_verification_does_not_accept_permanently_absent_code(monkeypatch):
    monkeypatch.setattr("agentvax.chain.deploy.time.sleep", lambda _: None)
    client = SimpleNamespace(code_at=Mock(return_value=b""))
    with pytest.raises(DeploymentError, match="received 0 bytes"):
        _check_runtime_code(client, "address", artifact(), {}, False)


def test_base_preconfirmation_waits_for_canonical_block_inclusion(monkeypatch):
    monkeypatch.setattr("agentvax.chain.client.time.sleep", lambda _: None)
    receipt = {"blockNumber": 10, "blockHash": b"canonical", "status": 1}
    blocks = iter([10, 11, 11])
    class Eth:
        get_transaction_receipt = Mock(return_value=receipt)
        get_block = Mock(side_effect=[
            {"hash": b"preconfirmed", "transactions": [b"tx"]},
            {"hash": b"canonical", "transactions": [b"tx"]},
        ])
        @property
        def block_number(self):
            return next(blocks)
    client = object.__new__(ChainClient)
    client._chain_id = 84532
    client._tuning = ChainTuning()
    client._w3 = SimpleNamespace(eth=Eth())
    assert client._canonical_receipt(b"tx", "0x00", receipt) is receipt
    assert client._w3.eth.get_transaction_receipt.call_count == 3


def test_base_preconfirmation_never_becomes_evidence_on_timeout(monkeypatch):
    monkeypatch.setattr("agentvax.chain.client.time.monotonic", Mock(side_effect=[0, 181]))
    client = object.__new__(ChainClient)
    client._chain_id = 84532
    client._tuning = ChainTuning()
    with pytest.raises(TransactionFailed, match="did not become canonical"):
        client._canonical_receipt(b"tx", "0x00", {})


def test_local_receipt_does_not_wait_for_another_block():
    client = object.__new__(ChainClient)
    client._chain_id = 31337
    receipt = {"status": 1}
    assert client._canonical_receipt(b"tx", "0x00", receipt) is receipt
