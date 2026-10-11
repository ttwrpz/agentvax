// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Attestation, Flags, Intent, Task} from "./AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";

/// @title Intent logic: EIP-712 hashing and the guardian check
/// @notice Linked library. The wallet passes its own EIP-712 domain separator, with name
///         "AgentVax PolicyWallet" and the wallet `VERSION`.
/// @dev Intent hash = EIP-712 digest of `Intent` under the wallet's domain. The guardian signs the EIP-712
///      digest of an `Attestation` whose `intentHash` is that digest.
library IntentLogic {
    /// @notice EIP-712 type hash of `Intent`.
    bytes32 internal constant INTENT_TYPEHASH = keccak256(
        "Intent(uint8 task,uint32 payeeId,uint256 amount,uint64 scheduleId,bytes32 purposeHash,uint256 nonce)"
    );
    /// @notice EIP-712 type hash of `Attestation`.
    bytes32 internal constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes32 intentHash,uint8 band,uint8 source,uint16 flags,uint64 validUntil)");

    /// @notice Furthest `validUntil` may lie beyond the time of submission. An attestation is accepted only if
    ///         `block.timestamp <= validUntil <= block.timestamp + MAX_ATTESTATION_TTL`.
    /// @dev This bounds how long a submitted attestation claims to stay valid, not when it was signed. The
    ///      contract has no trusted signing time, so the guardian must sign with a short `validUntil`.
    uint64 internal constant MAX_ATTESTATION_TTL = 15 minutes;

    uint8 private constant BAND_HIGH = 2;
    uint8 private constant SOURCE_EXTERNAL = 1;

    /// @notice Checks the guardian attestation for `intent` and the intent's shape.
    /// @dev Reverts unless the attestation names this intent, is unexpired, is valid for at most
    ///      MAX_ATTESTATION_TTL from now, has band, source and flags in range, and carries a valid signature
    ///      by `guardian`. A signature is needed at every tier.
    /// @return intentHash The intent hash.
    function verify(
        bytes32 domainSeparator,
        address guardian,
        Intent calldata intent,
        Attestation calldata att,
        bytes calldata sig
    ) external view returns (bytes32 intentHash) {
        intentHash = hashIntent(domainSeparator, intent);
        if (att.intentHash != intentHash) revert IPolicyWalletErrors.AttestationMismatch();
        if (att.validUntil < block.timestamp) revert IPolicyWalletErrors.AttestationExpired(att.validUntil);
        if (att.validUntil > block.timestamp + MAX_ATTESTATION_TTL) {
            revert IPolicyWalletErrors.AttestationValidityTooLong(att.validUntil);
        }
        if (att.band > BAND_HIGH || att.source > SOURCE_EXTERNAL || (att.flags & ~Flags.ALL) != 0) {
            revert IPolicyWalletErrors.InvalidAttestation();
        }
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hashAttestation(domainSeparator, att), sig);
        if (err != ECDSA.RecoverError.NoError || signer != guardian) {
            revert IPolicyWalletErrors.InvalidGuardianSignature();
        }
        _checkShape(intent);
    }

    /// @notice EIP-712 digest of `intent` under `domainSeparator`.
    function hashIntent(bytes32 domainSeparator, Intent calldata intent) public pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                INTENT_TYPEHASH,
                intent.task,
                intent.payeeId,
                intent.amount,
                intent.scheduleId,
                intent.purposeHash,
                intent.nonce
            )
        );
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    /// @notice EIP-712 digest of `att` under `domainSeparator`.
    function hashAttestation(bytes32 domainSeparator, Attestation calldata att) public pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, att.intentHash, att.band, att.source, att.flags, att.validUntil)
        );
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    /// @dev Field rules per task. PAYMENT and SCHEDULE_CREATE name a payee, SWEEP and FEE_TOPUP do not.
    ///      Only PAYMENT may carry an obligation reference in `scheduleId`.
    function _checkShape(Intent calldata intent) private pure {
        uint8 task = intent.task;
        bool paysPayee = task == uint8(Task.PAYMENT) || task == uint8(Task.SCHEDULE_CREATE);
        bool internalTask = task == uint8(Task.SWEEP) || task == uint8(Task.FEE_TOPUP);
        if (intent.amount == 0 || (!paysPayee && !internalTask)) revert IPolicyWalletErrors.InvalidIntent();
        if (paysPayee == (intent.payeeId == 0)) revert IPolicyWalletErrors.InvalidIntent();
        if (task != uint8(Task.PAYMENT) && intent.scheduleId != 0) revert IPolicyWalletErrors.InvalidIntent();
    }
}
