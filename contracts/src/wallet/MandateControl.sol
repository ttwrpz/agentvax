// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Mandate} from "../lib/AgentVaxTypes.sol";
import {AuthorityLogic} from "../lib/AuthorityLogic.sol";
import {LedgerLogic} from "../lib/LedgerLogic.sol";
import {Change, ChangeKind} from "./WalletTypes.sol";
import {CapsuleLogic} from "../lib/CapsuleLogic.sol";
import {CapsuleWatch} from "./CapsuleWatch.sol";

/// @title Mandate control: owner authority and the loosening time-lock Λ
/// @notice Tightening, cancelling and freezing take effect at once. Anything that loosens authority is
///         proposed, waits Λ, and is then applied by the owner. There is no owner shortcut around the wait.
///         The agent cannot change any of this state.
abstract contract MandateControl is CapsuleWatch {
    // ------------------------------------------------------------------ immediate owner actions

    /// @notice Sets the mandate. The first call is immediate. A later call is accepted only if every field
    ///         is equal or tighter, otherwise it reverts with `LooseningNeedsTimelock`.
    /// @dev `mandateHash = keccak256(abi.encode(keccak256(bytes(mission)), mandate))`, with `mandate` encoded
    ///      as a tuple of its static fields in declaration order. Any pending MANDATE proposal becomes stale.
    /// @param mission Plain-language mission the mandate was derived from.
    /// @param m The mandate.
    function setMandate(string calldata mission, Mandate calldata m) external onlyOwner {
        uint256 before = allowance();
        uint8 oldProfile = _auth.mandate.channelProfile;
        bool wasSet = AuthorityLogic.setMandate(_auth, mission, m);
        _afterMandateInstalled(wasSet, before, oldProfile);
    }

    /// @notice Freezes the wallet. Every value-moving function is blocked. Owner only, immediate.
    /// @dev Every pending loosening change becomes stale, including an unfreeze proposed before this call.
    function freeze() external onlyOwner {
        _auth.frozen = true;
        _auth.freezeEpoch += 1;
        emit WalletFrozen();
    }

    /// @notice Removes a payee. Owner only, immediate. Pending items to it can no longer execute, and every
    ///         pending ADD_PAYEE change becomes stale.
    function removePayee(uint32 payeeId) external onlyOwner {
        AuthorityLogic.removePayee(_auth, payeeId);
    }

    /// @notice Revokes the agent key. Owner only, immediate. A new key is set through `proposeAgent`. Every
    ///         pending AGENT change becomes stale.
    function revokeAgent() external onlyOwner {
        _auth.agent = address(0);
        _auth.agentRevokeEpoch += 1;
        emit AgentChanged(address(0));
    }

    /// @notice Records that something asked to pay `account` as `identityHash`. Agent only.
    /// @dev Emits an event and nothing else. The owner decides through `proposeAddPayee`.
    function recordPayeeChangeRequest(bytes32 identityHash, address account, uint16 flags) external onlyAgent {
        emit PayeeChangeRequested(identityHash, account, flags);
    }

    // ------------------------------------------------------------------ loosening proposals

    /// @notice Proposes adding the payee (`identityHash`, `account`). A known identity at a new address is a
    ///         new payee with a new id. Owner only, applied after Λ.
    function proposeAddPayee(bytes32 identityHash, address account) external onlyOwner returns (uint256) {
        return AuthorityLogic.propose(_auth, ChangeKind.ADD_PAYEE, identityHash, account, 0);
    }

    /// @notice Proposes a mandate with any field looser than the current one. Owner only, applied after Λ.
    function proposeMandate(string calldata mission, Mandate calldata m) external onlyOwner returns (uint256) {
        return AuthorityLogic.proposeMandate(_auth, mission, m);
    }

    /// @notice Proposes removing an open obligation, which raises D. Owner only, applied after Λ. The current
    ///         occurrence of an active schedule can be removed only after the schedule is cancelled.
    function proposeRemoveObligation(uint64 obligationId) external onlyOwner returns (uint256) {
        LedgerLogic.requireRemovable(_ledger, obligationId);
        return AuthorityLogic.propose(_auth, ChangeKind.REMOVE_OBLIGATION, bytes32(0), address(0), obligationId);
    }

    /// @notice Proposes a new agent session key. Owner only, applied after Λ. It must differ from the owner
    ///         and the guardian.
    function proposeAgent(address newAgent) external onlyOwner returns (uint256) {
        _requireDistinctKeys(owner, newAgent, _auth.guardian);
        return AuthorityLogic.propose(_auth, ChangeKind.AGENT, bytes32(0), newAgent, 0);
    }

    /// @notice Proposes a new guardian signer. Owner only, applied after Λ. It must differ from the owner and
    ///         the agent.
    function proposeGuardian(address newGuardian) external onlyOwner returns (uint256) {
        _requireDistinctKeys(owner, _auth.agent, newGuardian);
        return AuthorityLogic.propose(_auth, ChangeKind.GUARDIAN, bytes32(0), newGuardian, 0);
    }

    /// @notice Proposes unfreezing the wallet. Owner only, applied after Λ.
    function proposeUnfreeze() external onlyOwner returns (uint256) {
        return AuthorityLogic.propose(_auth, ChangeKind.UNFREEZE, bytes32(0), address(0), 0);
    }

    /// @notice Applies a pending change once its wait has passed and only if it is not stale. Owner only.
    /// @dev Keys are checked again after a key change because two proposals that are each valid alone could
    ///      give one address two roles.
    function applyChange(uint256 changeId) external onlyOwner {
        uint256 before = allowance();
        uint8 oldProfile = _auth.mandate.channelProfile;
        (ChangeKind kind, uint64 obligationId) = AuthorityLogic.applyChange(_auth, changeId);
        if (kind == ChangeKind.MANDATE) {
            _afterMandateInstalled(true, before, oldProfile);
        } else if (kind == ChangeKind.REMOVE_OBLIGATION) {
            LedgerLogic.removeObligation(_ledger, obligationId);
        } else if (kind == ChangeKind.AGENT || kind == ChangeKind.GUARDIAN) {
            _requireDistinctKeys(owner, _auth.agent, _auth.guardian);
        }
    }

    /// @notice Cancels a pending change. Owner only, immediate.
    function cancelChange(uint256 changeId) external onlyOwner {
        AuthorityLogic.cancelChange(_auth, changeId);
    }

    // ------------------------------------------------------------------ views

    /// @notice The current mandate.
    function mandate() external view returns (Mandate memory) {
        return _auth.mandate;
    }

    /// @notice Session key of the agent. May submit intents and add obligations, nothing else.
    function agent() external view returns (address) {
        return _auth.agent;
    }

    /// @notice Address whose EIP-712 signature attests every intent.
    function guardian() external view returns (address) {
        return _auth.guardian;
    }

    /// @notice True while every value-moving function is blocked.
    function frozen() external view returns (bool) {
        return _auth.frozen;
    }

    /// @notice True once the first mandate has been set.
    function mandateSet() external view returns (bool) {
        return _auth.mandateSet;
    }

    /// @notice keccak256 of the current mission text, and the current mandate hash.
    function mandateHashes() external view returns (bytes32 missionHash, bytes32 mandateHash) {
        return (_auth.missionHash, _auth.mandateHash);
    }

    /// @notice Change `changeId`, and the proposed mandate if it is a MANDATE change.
    function getChange(uint256 changeId) external view returns (Change memory change, Mandate memory proposed) {
        return (_auth.changes[changeId], _auth.proposedMandates[changeId]);
    }

    /// @notice Number of changes ever proposed. Change ids run from 1 to this value.
    function changeCount() external view returns (uint256) {
        return _auth.changeCount;
    }

    /// @notice Earliest time change `changeId` can be applied under the current Λ.
    function changeReadyAt(uint256 changeId) external view returns (uint64) {
        return AuthorityLogic.readyAt(_auth, changeId);
    }

    // ------------------------------------------------------------------ internal

    /// @dev Sets the allowance to full the first time, otherwise carries the previous value over capped at
    ///      the new A. If the mandate added a channel to the profile, capsules already published on it are
    ///      rescanned.
    function _afterMandateInstalled(bool wasSet, uint256 before, uint8 oldProfile) private {
        uint256 cap = uint256(_auth.mandate.allowanceMax) * ALLOWANCE_UNIT;
        _setAllowance(wasSet && before < cap ? before : cap);
        if (_auth.mandate.channelProfile & ~oldProfile != 0) CapsuleLogic.rewind(_capsules, bulletin);
    }
}
