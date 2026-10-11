// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Mandate, ScheduleTerms, Tiers} from "./AgentVaxTypes.sol";
import {Item, ItemBook, ItemStatus, Request} from "../wallet/WalletTypes.sol";
import {IPolicyWalletEvents} from "../interfaces/IPolicyWalletEvents.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";

/// @title Item logic: the L2 queue and L3 proposals
/// @notice Linked library operating on the wallet's `ItemBook`.
/// @dev An L2 item can execute at queuedAt + max(Δ when queued, current Δ). An approved L3 item can execute at
///      approvedAt, plus max(Π when approved, current Π) if it carries a pressure flag or a full capsule match
///      at decision time or now. Both add any extension from `extendHold`. Lengthening a delay delays pending
///      items and shortening never brings them forward.
library ItemLogic {
    /// @notice Stores an intent that did not execute at L1.
    function store(
        ItemBook storage b,
        Mandate storage m,
        bytes32 intentHash,
        Request memory r,
        bool hold,
        uint8 tier,
        ScheduleTerms memory terms
    ) external returns (uint256 itemId) {
        itemId = ++b.count;
        Item storage s = b.items[itemId];
        s.intentHash = intentHash;
        s.req = r;
        s.tier = tier;
        s.hold = hold;
        s.queuedAt = uint64(block.timestamp);
        s.terms = terms;
        if (tier == Tiers.L2) {
            s.status = ItemStatus.QUEUED;
            s.lockSnapshot = m.delay;
            emit IPolicyWalletEvents.Queued(itemId, intentHash, uint64(block.timestamp) + m.delay);
        } else {
            s.status = ItemStatus.PROPOSED;
            emit IPolicyWalletEvents.Proposed(itemId, intentHash);
        }
    }

    /// @notice The request of a proposed L3 item, for the wallet to assess before the owner's approval.
    function proposedRequest(ItemBook storage b, uint256 itemId) external view returns (Request memory) {
        Item storage s = _item(b, itemId);
        if (s.status != ItemStatus.PROPOSED) revert IPolicyWalletErrors.ItemNotProposed(itemId);
        return s.req;
    }

    /// @notice Owner approval of a proposed L3 item.
    /// @param affordNow q2 of the item at the moment of approval. Execution later needs q2 no worse than this.
    function approve(ItemBook storage b, Mandate storage m, uint256 itemId, uint8 affordNow) external {
        Item storage s = _item(b, itemId);
        if (s.status != ItemStatus.PROPOSED) revert IPolicyWalletErrors.ItemNotProposed(itemId);
        s.status = ItemStatus.APPROVED;
        s.approvedAt = uint64(block.timestamp);
        s.lockSnapshot = m.pressureHold;
        s.approvedAfford = affordNow;
        emit IPolicyWalletEvents.Approved(itemId, _readyAt(s, m, false));
    }

    /// @notice Cancels a queued, proposed or approved item.
    function cancel(ItemBook storage b, uint256 itemId) external {
        _pending(b, itemId).status = ItemStatus.CANCELLED;
        emit IPolicyWalletEvents.ItemCancelled(itemId);
    }

    /// @notice Adds `extraSeconds` to the wait of a pending item.
    function extendHold(ItemBook storage b, uint256 itemId, uint64 extraSeconds) external {
        if (extraSeconds == 0) revert IPolicyWalletErrors.InvalidHoldExtension();
        Item storage s = _pending(b, itemId);
        s.extraHold += extraSeconds;
        emit IPolicyWalletEvents.HoldExtended(itemId, s.extraHold);
    }

    /// @notice The request of an item that may be executed: queued (L2) or approved (L3).
    function executableRequest(ItemBook storage b, uint256 itemId) external view returns (Request memory) {
        Item storage s = _item(b, itemId);
        if (s.status != ItemStatus.QUEUED && s.status != ItemStatus.APPROVED) {
            revert IPolicyWalletErrors.ItemNotExecutable(itemId);
        }
        return s.req;
    }

    /// @notice Marks an item executed after checking the tier it would get now, its affordability and its wait.
    /// @dev A queued item may not now need a higher tier than it was queued at. An approved item already has the
    ///      highest tier, so instead q2 now may not be worse than q2 at approval.
    /// @param tierNow Tier the item's request gets under the current state.
    /// @param holdNow Whether a pressure flag or a full capsule match is present now.
    /// @param affordNow q2 of the item's request under the current state.
    function markExecuted(
        ItemBook storage b,
        Mandate storage m,
        uint256 itemId,
        uint8 tierNow,
        bool holdNow,
        uint8 affordNow
    ) external returns (bytes32 intentHash, uint8 tier, ScheduleTerms memory terms) {
        Item storage s = _item(b, itemId);
        tier = s.tier;
        if (tierNow > tier) revert IPolicyWalletErrors.NoLongerAuthorised(itemId, tierNow);
        if (s.status == ItemStatus.APPROVED && affordNow > s.approvedAfford) {
            revert IPolicyWalletErrors.NoLongerAffordable(itemId);
        }
        uint64 ready = _readyAt(s, m, holdNow);
        if (block.timestamp < ready) revert IPolicyWalletErrors.ItemNotReady(itemId, ready);
        s.status = ItemStatus.EXECUTED;
        return (s.intentHash, tier, s.terms);
    }

    /// @notice Earliest execution time of item `itemId` under the current mandate, from what is stored.
    function readyAt(ItemBook storage b, Mandate storage m, uint256 itemId) external view returns (uint64) {
        return _readyAt(_item(b, itemId), m, false);
    }

    function _readyAt(Item storage s, Mandate storage m, bool holdNow) private view returns (uint64) {
        if (s.tier == Tiers.L2) {
            uint64 delta = m.delay;
            if (s.lockSnapshot > delta) delta = s.lockSnapshot;
            return s.queuedAt + delta + s.extraHold;
        }
        if (s.status != ItemStatus.APPROVED) return type(uint64).max;
        uint64 base = s.approvedAt;
        if (s.hold || holdNow) {
            uint64 pi = m.pressureHold;
            base += s.lockSnapshot > pi ? s.lockSnapshot : pi;
        }
        return base + s.extraHold;
    }

    function _item(ItemBook storage b, uint256 itemId) private view returns (Item storage) {
        if (itemId == 0 || itemId > b.count) revert IPolicyWalletErrors.UnknownItem(itemId);
        return b.items[itemId];
    }

    function _pending(ItemBook storage b, uint256 itemId) private view returns (Item storage s) {
        s = _item(b, itemId);
        if (s.status != ItemStatus.QUEUED && s.status != ItemStatus.PROPOSED && s.status != ItemStatus.APPROVED) {
            revert IPolicyWalletErrors.ItemNotPending(itemId);
        }
    }
}
