"""Owner workflows that combine an owner action on chain with a deterministic memory update.

Every function takes the owner signer explicitly. Memory is written only from values read back from the
chain, never from text.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from agentvax.chain import owner as owner_actions
from agentvax.chain.client import ChainClient, Signer
from agentvax.memory import MemoryStore, account_hash
from agentvax.types import Address, Bytes32, Strict


class PayeeAddition(Strict):
    payee_id: Annotated[int, Field(ge=1)]
    account: Address
    identity_hash: Bytes32
    tx_hash: Bytes32


def apply_payee_addition(
    client: ChainClient, owner: Signer, wallet: str, change_id: int, memory: MemoryStore
) -> PayeeAddition:
    """Applies an ADD_PAYEE change after Λ and records, in memory, that the owner verified the payee's account.

    The payee id, account and identity come from the ``PayeeAdded`` event of the receipt, and the verification
    time is the block time of that receipt.
    """
    receipt = owner_actions.apply_change(client, owner, wallet, change_id)
    added = client.events(receipt, client.wallet(wallet), "PayeeAdded")
    if len(added) != 1:
        raise ValueError(f"change {change_id} did not add a payee")
    args = added[0]["args"]
    verified_at = int(client.web3.eth.get_block(receipt["blockNumber"])["timestamp"])
    payee_id = int(args["payeeId"])
    memory.record_verification(payee_id, account_hash(args["account"]), verified_at)
    return PayeeAddition(
        payee_id=payee_id,
        account=args["account"],
        identity_hash="0x" + bytes(args["identityHash"]).hex(),
        tx_hash="0x" + bytes(receipt["transactionHash"]).hex(),
    )
