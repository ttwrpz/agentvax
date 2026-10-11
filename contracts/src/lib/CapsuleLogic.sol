// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CapsuleAction, Tiers} from "./AgentVaxTypes.sol";
import {CapsuleBook, CapsuleMatch} from "../wallet/WalletTypes.sol";
import {IThreatBulletin} from "../interfaces/IThreatBulletin.sol";
import {IPolicyWalletEvents} from "../interfaces/IPolicyWalletEvents.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";

/// @title Capsule logic: syncing and matching bulletin capsules
/// @notice Linked library operating on the wallet's `CapsuleBook`.
/// @dev New bulletin capsules are synced in bounded chunks. A capsule applies when it is unexpired, not
///      dismissed and its channel is in the profile when synced. Each applicable capsule is marked seen and
///      counted once for allowance halving, however often it is scanned.
///      Applicable capsules live in two bounded lists. The tracked list, matched on every request, holds the
///      strongest and the spilled list holds the rest. Strength is ranked from the bulletin as it is now:
///      effective restriction, then attestations, then expiry. Every sync re-ranks both lists, so a capsule
///      that gains quorum after losing its slot is matched again with its new restriction.
///      The wallet fails closed, raising every request to at least L2, while capsules remain unprocessed,
///      while any capsule is spilled, and until a capsule that fits in neither list expires.
///      Pending items may not execute while a backlog remains, while such a dropped capsule is unexpired, or
///      while a spilled capsule demands owner approval. These delays are bounded by the capsule lifetime.
///      Fail-closed never becomes an owner-approval requirement.
///      Nothing here can lower a tier or write mandate state.
library CapsuleLogic {
    /// @notice Most unexpired applicable capsules a wallet tracks and matches on every request.
    uint256 internal constant MAX_TRACKED = 16;
    /// @notice Most applicable capsules a wallet keeps for re-ranking beyond the tracked ones.
    uint256 internal constant MAX_SPILLED = 16;

    uint8 private constant MATCH_NONE = 0;
    uint8 private constant MATCH_PARTIAL = 1;
    uint8 private constant MATCH_FULL = 2;

    /// @notice Drops expired and dismissed capsules, then processes up to `maxCount` bulletin capsules.
    /// @return processed Capsules the cursor moved past.
    /// @return applicable How many newly seen capsules apply to `profile`. The wallet halves its allowance
    ///         once for each.
    function sync(CapsuleBook storage c, IThreatBulletin bulletin, uint8 profile, uint256 maxCount)
        external
        returns (uint256 processed, uint256 applicable)
    {
        _prune(c, bulletin);
        uint256 total = bulletin.capsuleCount();
        uint256 cursor = c.cursor;
        while (cursor < total && processed < maxCount) {
            uint256 id = cursor + 1;
            if (!c.seen[id] && !c.dismissed[id]) {
                (uint8 channel,,,, uint64 expiry) = bulletin.matchFields(id);
                if (expiry > block.timestamp && (profile >> channel) & 1 == 1) {
                    c.seen[id] = true;
                    ++applicable;
                    _admit(c, bulletin, id);
                }
            }
            cursor = id;
            ++processed;
        }
        if (processed > 0) {
            c.cursor = cursor;
            emit IPolicyWalletEvents.CapsulesSynced(cursor, c.tracked.length);
        }
        _rebalance(c, bulletin);
    }

    /// @notice Reverts while a pending item must not execute or be approved: capsules remain unprocessed, or,
    ///         with `forExecution`, an applicable capsule is in neither list or a spilled capsule demands owner
    ///         approval.
    function requireClear(CapsuleBook storage c, IThreatBulletin bulletin, bool forExecution) external view {
        uint256 total = bulletin.capsuleCount();
        if (total > c.cursor) revert IPolicyWalletErrors.CapsuleBacklog(total - c.cursor);
        if (forExecution && (c.overflowUntil > block.timestamp || c.spilledTop >= Tiers.L3)) {
            revert IPolicyWalletErrors.CapsuleOverflow();
        }
    }

    /// @notice Moves the cursor back to the first capsule that may still be unexpired. Called when a channel
    ///         is added to the profile.
    /// @dev Capsules already seen are skipped by the rescan, so none is tracked or counted twice.
    function rewind(CapsuleBook storage c, IThreatBulletin bulletin) external {
        uint256 from = bulletin.firstPossiblyLive() - 1;
        if (from >= c.cursor) return;
        c.cursor = from;
        emit IPolicyWalletEvents.CapsulesSynced(from, c.tracked.length);
    }

    /// @notice True while every request must wait at least Δ: capsules remain unprocessed, or an applicable
    ///         unexpired capsule is not in the tracked list.
    function isFailClosed(CapsuleBook storage c, IThreatBulletin bulletin) internal view returns (bool) {
        return bulletin.capsuleCount() > c.cursor || c.spilled.length > 0 || c.overflowUntil > block.timestamp;
    }

    /// @notice Matches a request against every tracked capsule. Bounded by MAX_TRACKED.
    /// @dev Internal so that the decision library can inline it.
    function matchRequest(
        CapsuleBook storage c,
        IThreatBulletin bulletin,
        uint8 profile,
        CapsuleAction action,
        uint16 flags
    ) internal view returns (CapsuleMatch memory m) {
        m.failClosed = isFailClosed(c, bulletin);
        if (action == CapsuleAction.NONE) return m;
        uint256 n = c.tracked.length;
        for (uint256 i = 0; i < n; ++i) {
            uint256 id = c.tracked[i];
            (uint8 kind, uint8 r) = _matchOne(c, bulletin, profile, id, uint8(action), flags);
            if (kind == MATCH_FULL && r > m.restriction) {
                m.restriction = r;
                m.fullId = id;
            } else if (kind == MATCH_PARTIAL && m.partialId == 0) {
                m.partialId = id;
            }
        }
    }

    /// @notice Lists the tracked capsules that fully or partially match, for the interface.
    function matchLists(CapsuleBook storage c, IThreatBulletin bulletin, uint8 profile, uint8 action, uint16 flags)
        external
        view
        returns (uint256[] memory fullIds, uint256[] memory partialIds, uint8 restriction)
    {
        uint8[] memory kinds;
        (kinds, restriction) = _classify(c, bulletin, profile, action, flags);
        fullIds = _select(c, kinds, MATCH_FULL);
        partialIds = _select(c, kinds, MATCH_PARTIAL);
    }

    function _classify(CapsuleBook storage c, IThreatBulletin bulletin, uint8 profile, uint8 action, uint16 flags)
        private
        view
        returns (uint8[] memory kinds, uint8 restriction)
    {
        uint256 n = c.tracked.length;
        kinds = new uint8[](n);
        for (uint256 i = 0; i < n; ++i) {
            uint8 r;
            (kinds[i], r) = _matchOne(c, bulletin, profile, c.tracked[i], action, flags);
            if (kinds[i] == MATCH_FULL && r > restriction) restriction = r;
        }
    }

    function _select(CapsuleBook storage c, uint8[] memory kinds, uint8 wanted)
        private
        view
        returns (uint256[] memory ids)
    {
        uint256 count;
        for (uint256 i = 0; i < kinds.length; ++i) {
            if (kinds[i] == wanted) ++count;
        }
        ids = new uint256[](count);
        count = 0;
        for (uint256 i = 0; i < kinds.length; ++i) {
            if (kinds[i] == wanted) ids[count++] = c.tracked[i];
        }
    }

    /// @dev Full match: unexpired, not dismissed, channel in profile, same action, every feature present.
    ///      Partial match: the same, but only at least half of the features present.
    function _matchOne(
        CapsuleBook storage c,
        IThreatBulletin bulletin,
        uint8 profile,
        uint256 id,
        uint8 action,
        uint16 flags
    ) private view returns (uint8 kind, uint8 restriction) {
        if (action == uint8(CapsuleAction.NONE) || c.dismissed[id]) return (MATCH_NONE, 0);
        (uint8 channel, uint16 features, uint8 capsuleAction, uint8 r, uint64 expiry) = bulletin.matchFields(id);
        if (expiry <= block.timestamp || capsuleAction != action) return (MATCH_NONE, 0);
        if ((profile >> channel) & 1 == 0) return (MATCH_NONE, 0);
        uint16 present = features & flags;
        if (present == features) return (MATCH_FULL, r);
        if (_popcount(present) * 2 >= _popcount(features)) return (MATCH_PARTIAL, 0);
        return (MATCH_NONE, 0);
    }

    /// @dev Places newly seen capsule `id` in the tracked list if it has room, otherwise in the spilled list.
    ///      If both are full, the weaker of `id` and the weakest spilled capsule drops out of both lists and the
    ///      wallet fails closed until it expires. `_rebalance` then puts the strongest capsules in the tracked list.
    function _admit(CapsuleBook storage c, IThreatBulletin bulletin, uint256 id) private {
        if (c.tracked.length < MAX_TRACKED) {
            c.tracked.push(id);
            emit IPolicyWalletEvents.CapsuleTracked(id);
            return;
        }
        uint256 n = c.spilled.length;
        if (n < MAX_SPILLED) {
            c.spilled.push(id);
            emit IPolicyWalletEvents.CapsuleSpilled(id);
            return;
        }
        uint256 weakest;
        uint256 weakestRank = type(uint256).max;
        for (uint256 i = 0; i < n; ++i) {
            uint256 r = _rank(bulletin, c.spilled[i]);
            if (r < weakestRank) {
                weakestRank = r;
                weakest = i;
            }
        }
        uint256 dropped = id;
        if (_rank(bulletin, id) > weakestRank) {
            dropped = c.spilled[weakest];
            c.spilled[weakest] = id;
            emit IPolicyWalletEvents.CapsuleSpilled(id);
        }
        (,, uint64 expiry) = bulletin.strength(dropped);
        if (expiry > c.overflowUntil) c.overflowUntil = expiry;
        emit IPolicyWalletEvents.CapsuleUntracked(dropped, c.overflowUntil);
    }

    /// @dev Re-ranks both lists against the bulletin as it is now. Fills free tracked slots with the strongest
    ///      spilled capsules, then swaps the strongest spilled with the weakest tracked while the spilled one
    ///      ranks higher. The loop is bounded by MAX_TRACKED + MAX_SPILLED rounds. Records the highest effective
    ///      restriction left among spilled capsules.
    function _rebalance(CapsuleBook storage c, IThreatBulletin bulletin) private {
        uint256 ns = c.spilled.length;
        if (ns == 0) {
            if (c.spilledTop != 0) c.spilledTop = 0;
            return;
        }
        uint256 nt = c.tracked.length;
        uint256[] memory tr = new uint256[](MAX_TRACKED);
        uint256[] memory sr = new uint256[](ns);
        for (uint256 i = 0; i < nt; ++i) {
            tr[i] = _rank(bulletin, c.tracked[i]);
        }
        for (uint256 i = 0; i < ns; ++i) {
            sr[i] = _rank(bulletin, c.spilled[i]);
        }
        for (uint256 round = 0; ns > 0 && round < MAX_TRACKED + MAX_SPILLED; ++round) {
            uint256 si = _argMax(sr, ns);
            if (nt < MAX_TRACKED) {
                uint256 promoted = c.spilled[si];
                c.tracked.push(promoted);
                tr[nt++] = sr[si];
                ns -= 1;
                c.spilled[si] = c.spilled[ns];
                c.spilled.pop();
                sr[si] = sr[ns];
                emit IPolicyWalletEvents.CapsuleTracked(promoted);
                continue;
            }
            uint256 ti = _argMin(tr, nt);
            if (sr[si] <= tr[ti]) break;
            (c.tracked[ti], c.spilled[si]) = (c.spilled[si], c.tracked[ti]);
            (tr[ti], sr[si]) = (sr[si], tr[ti]);
            emit IPolicyWalletEvents.CapsuleTracked(c.tracked[ti]);
            emit IPolicyWalletEvents.CapsuleSpilled(c.spilled[si]);
        }
        uint8 top;
        for (uint256 i = 0; i < ns; ++i) {
            uint8 r = uint8(sr[i] >> 72);
            if (r > top) top = r;
        }
        c.spilledTop = top;
    }

    /// @dev Effective restriction, then attestations, then expiry, packed so that a larger value is stronger.
    function _rank(IThreatBulletin bulletin, uint256 id) private view returns (uint256) {
        (uint8 restriction, uint8 attestations, uint64 expiry) = bulletin.strength(id);
        return (uint256(restriction) << 72) | (uint256(attestations) << 64) | uint256(expiry);
    }

    function _argMax(uint256[] memory a, uint256 n) private pure returns (uint256 at) {
        for (uint256 i = 1; i < n; ++i) {
            if (a[i] > a[at]) at = i;
        }
    }

    function _argMin(uint256[] memory a, uint256 n) private pure returns (uint256 at) {
        for (uint256 i = 1; i < n; ++i) {
            if (a[i] < a[at]) at = i;
        }
    }

    /// @dev Drops expired and dismissed capsules from both lists.
    function _prune(CapsuleBook storage c, IThreatBulletin bulletin) private {
        _pruneList(c, c.tracked, bulletin);
        _pruneList(c, c.spilled, bulletin);
    }

    function _pruneList(CapsuleBook storage c, uint256[] storage list, IThreatBulletin bulletin) private {
        uint256 i = 0;
        while (i < list.length) {
            uint256 id = list[i];
            (,,,, uint64 expiry) = bulletin.matchFields(id);
            if (expiry <= block.timestamp || c.dismissed[id]) {
                list[i] = list[list.length - 1];
                list.pop();
            } else {
                ++i;
            }
        }
    }

    function _popcount(uint16 x) private pure returns (uint256 count) {
        while (x != 0) {
            x &= x - 1;
            ++count;
        }
    }
}
