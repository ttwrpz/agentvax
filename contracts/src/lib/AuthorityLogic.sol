// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Mandate} from "./AgentVaxTypes.sol";
import {MandateRules} from "./MandateRules.sol";
import {AuthorityBook, Change, ChangeKind, ChangeStatus, Payee} from "../wallet/WalletTypes.sol";
import {IPolicyWalletEvents} from "../interfaces/IPolicyWalletEvents.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";

/// @title Authority logic: the mandate, payees, keys and the loosening time-lock Λ
/// @notice Linked library operating on the wallet's `AuthorityBook`. Called only from owner-gated functions.
/// @dev `setMandate` accepts a later mandate only if every field is equal or tighter. Anything that loosens
///      authority is a typed `Change` that waits `max(readyAt, proposedAt + current Λ)`, so lengthening Λ
///      delays pending changes and shortening Λ never brings one forward. Cancelling is immediate.
///      A change can never undo a tightening made after it was proposed. A MANDATE change is stale once the
///      mandate it was built on changes. Every change is stale once a later freeze, payee removal or agent
///      revocation moves its tightening epoch (see `_epoch`). A stale change cannot be applied and must be
///      proposed again.
library AuthorityLogic {
    /// @notice Sets the mandate: immediately the first time, afterwards only if it is equal or tighter.
    /// @return wasSet Whether a mandate was already in force before this call.
    function setMandate(AuthorityBook storage a, string calldata mission, Mandate calldata m)
        external
        returns (bool wasSet)
    {
        if (!MandateRules.isWellFormed(m, block.timestamp)) revert IPolicyWalletErrors.InvalidMandate();
        wasSet = a.mandateSet;
        if (wasSet && !MandateRules.isTighterOrEqual(a.mandate, m)) {
            revert IPolicyWalletErrors.LooseningNeedsTimelock();
        }
        bytes32 mHash = keccak256(bytes(mission));
        emit IPolicyWalletEvents.MissionStated(mHash, mission);
        _install(a, mHash, m);
    }

    /// @notice Records a loosening change of `kind` with its typed fields. Not for MANDATE changes.
    /// @dev The caller validates the kind-specific fields that need state outside this book.
    function propose(AuthorityBook storage a, ChangeKind kind, bytes32 key, address account, uint64 obligationId)
        external
        returns (uint256 id)
    {
        if (!a.mandateSet) revert IPolicyWalletErrors.MandateNotSet();
        if (kind == ChangeKind.ADD_PAYEE || kind == ChangeKind.AGENT || kind == ChangeKind.GUARDIAN) {
            if (account == address(0)) revert IPolicyWalletErrors.ZeroAddress();
        } else if (kind == ChangeKind.UNFREEZE) {
            if (!a.frozen) revert IPolicyWalletErrors.WalletNotFrozen();
        } else if (kind != ChangeKind.REMOVE_OBLIGATION) {
            revert IPolicyWalletErrors.InvalidChangeKind();
        }
        id = _newChange(a, kind);
        Change storage c = a.changes[id];
        c.key = key;
        c.account = account;
        c.obligationId = obligationId;
    }

    /// @notice Records a proposed mandate that is looser than the current one in at least one field.
    function proposeMandate(AuthorityBook storage a, string calldata mission, Mandate calldata m)
        external
        returns (uint256 id)
    {
        if (!a.mandateSet) revert IPolicyWalletErrors.MandateNotSet();
        if (!MandateRules.isWellFormed(m, block.timestamp)) revert IPolicyWalletErrors.InvalidMandate();
        bytes32 mHash = keccak256(bytes(mission));
        emit IPolicyWalletEvents.MissionStated(mHash, mission);
        id = _newChange(a, ChangeKind.MANDATE);
        a.changes[id].key = mHash;
        a.proposedMandates[id] = m;
    }

    /// @notice Applies pending change `changeId` once its wait has passed.
    /// @return kind The kind applied.
    /// @return obligationId For REMOVE_OBLIGATION, the obligation the wallet must now remove from its ledger.
    function applyChange(AuthorityBook storage a, uint256 changeId)
        external
        returns (ChangeKind kind, uint64 obligationId)
    {
        Change storage c = _pending(a, changeId);
        uint64 ready = readyAt(a, changeId);
        if (block.timestamp < ready) revert IPolicyWalletErrors.ChangeNotReady(changeId, ready);
        kind = c.kind;
        if (c.epoch != _epoch(a, kind) || (kind == ChangeKind.MANDATE && c.baseMandateHash != a.mandateHash)) {
            revert IPolicyWalletErrors.ProposalStale(changeId);
        }
        c.status = ChangeStatus.APPLIED;
        if (kind == ChangeKind.ADD_PAYEE) {
            _addPayee(a, c.key, c.account);
        } else if (kind == ChangeKind.MANDATE) {
            Mandate memory m = a.proposedMandates[changeId];
            if (!MandateRules.isWellFormed(m, block.timestamp)) revert IPolicyWalletErrors.InvalidMandate();
            _install(a, c.key, m);
        } else if (kind == ChangeKind.REMOVE_OBLIGATION) {
            obligationId = c.obligationId;
        } else if (kind == ChangeKind.AGENT) {
            a.agent = c.account;
            emit IPolicyWalletEvents.AgentChanged(c.account);
        } else if (kind == ChangeKind.GUARDIAN) {
            a.guardian = c.account;
            emit IPolicyWalletEvents.GuardianChanged(c.account);
        } else {
            a.frozen = false;
            emit IPolicyWalletEvents.WalletUnfrozen();
        }
        emit IPolicyWalletEvents.ChangeApplied(changeId, kind);
    }

    /// @notice Cancels pending change `changeId`.
    function cancelChange(AuthorityBook storage a, uint256 changeId) external {
        _pending(a, changeId).status = ChangeStatus.CANCELLED;
        emit IPolicyWalletEvents.ChangeCancelled(changeId);
    }

    /// @notice Removes payee `payeeId`. Tightening, so immediate.
    function removePayee(AuthorityBook storage a, uint32 payeeId) external {
        if (payeeId == 0 || payeeId > a.payees.length) revert IPolicyWalletErrors.UnknownPayee(payeeId);
        Payee storage p = a.payees[payeeId - 1];
        if (!p.active) revert IPolicyWalletErrors.PayeeNotActive(payeeId);
        p.active = false;
        a.payeeRemovalEpoch += 1;
        delete a.activePayeeByPair[_pairHash(p.identityHash, p.account)];
        emit IPolicyWalletEvents.PayeeRemoved(payeeId);
    }

    /// @notice Earliest time change `changeId` can be applied under the current Λ.
    function readyAt(AuthorityBook storage a, uint256 changeId) public view returns (uint64) {
        Change storage c = a.changes[changeId];
        uint64 underCurrent = c.proposedAt + a.mandate.looseningDelay;
        return underCurrent > c.readyAt ? underCurrent : c.readyAt;
    }

    function _newChange(AuthorityBook storage a, ChangeKind kind) private returns (uint256 id) {
        id = ++a.changeCount;
        uint64 ready = uint64(block.timestamp) + a.mandate.looseningDelay;
        Change storage c = a.changes[id];
        c.kind = kind;
        c.status = ChangeStatus.PENDING;
        c.proposedAt = uint64(block.timestamp);
        c.readyAt = ready;
        c.epoch = _epoch(a, kind);
        if (kind == ChangeKind.MANDATE) c.baseMandateHash = a.mandateHash;
        emit IPolicyWalletEvents.ChangeProposed(id, kind, ready);
    }

    /// @dev The tightening epoch a change of `kind` depends on. Every epoch only grows, so the sum grows
    ///      whenever any of its terms does: a freeze makes every pending change stale, a payee removal every
    ///      pending ADD_PAYEE, an agent revocation every pending AGENT change.
    function _epoch(AuthorityBook storage a, ChangeKind kind) private view returns (uint64 e) {
        e = a.freezeEpoch;
        if (kind == ChangeKind.ADD_PAYEE) e += a.payeeRemovalEpoch;
        else if (kind == ChangeKind.AGENT) e += a.agentRevokeEpoch;
    }

    function _pending(AuthorityBook storage a, uint256 changeId) private view returns (Change storage c) {
        if (changeId == 0 || changeId > a.changeCount) revert IPolicyWalletErrors.UnknownChange(changeId);
        c = a.changes[changeId];
        if (c.status != ChangeStatus.PENDING) revert IPolicyWalletErrors.ChangeNotPending(changeId);
    }

    function _addPayee(AuthorityBook storage a, bytes32 identityHash, address account) private {
        bytes32 pair = _pairHash(identityHash, account);
        uint32 existing = a.activePayeeByPair[pair];
        if (existing != 0) revert IPolicyWalletErrors.PayeeAlreadyActive(existing);
        a.payees.push(Payee({identityHash: identityHash, account: account, active: true, paidCount: 0, maxPaid: 0}));
        uint32 id = uint32(a.payees.length);
        a.activePayeeByPair[pair] = id;
        emit IPolicyWalletEvents.PayeeAdded(id, identityHash, account);
    }

    /// @dev `mandateHash = keccak256(abi.encode(missionHash, mandate))`.
    function _install(AuthorityBook storage a, bytes32 mHash, Mandate memory m) private {
        a.mandate = m;
        a.mandateSet = true;
        a.missionHash = mHash;
        bytes32 hash = keccak256(abi.encode(mHash, m));
        a.mandateHash = hash;
        emit IPolicyWalletEvents.MandateSet(hash, mHash);
    }

    function _pairHash(bytes32 identityHash, address account) private pure returns (bytes32) {
        return keccak256(abi.encode(identityHash, account));
    }
}
