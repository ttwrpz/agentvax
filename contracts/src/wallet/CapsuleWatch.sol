// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CapsuleLogic} from "../lib/CapsuleLogic.sol";
import {Ledger} from "./Ledger.sol";

/// @title Capsule watch: the wallet's side of the threat bulletin
/// @notice New applicable capsules are synced in bounded chunks and each halves the allowance once. While a
///         backlog remains, every request is raised to at least L2. Matching is in `CapsuleLogic`.
/// @dev Capsules can only raise a tier or charge the allowance. Nothing here writes mandate state.
abstract contract CapsuleWatch is Ledger {
    /// @notice Most unexpired applicable capsules the wallet tracks.
    uint256 public constant MAX_TRACKED_CAPSULES = CapsuleLogic.MAX_TRACKED;
    /// @notice Most applicable capsules the wallet keeps for re-ranking beyond the tracked ones.
    uint256 public constant MAX_SPILLED_CAPSULES = CapsuleLogic.MAX_SPILLED;
    /// @notice Capsules processed automatically before each decision.
    uint256 public constant AUTO_SYNC_CHUNK = 8;

    /// @notice Processes up to `maxCount` new bulletin capsules. Anyone may call.
    /// @return processed Number of capsules processed.
    function syncCapsules(uint256 maxCount) external whenMandateSet returns (uint256 processed) {
        return _syncCapsules(maxCount);
    }

    /// @notice Dismisses capsule `capsuleId` for this wallet only. Owner only, immediate.
    /// @dev The only loosening that skips Λ. It affects this wallet's capsule view and never the mandate.
    function dismissCapsule(uint256 capsuleId) external onlyOwner {
        bulletin.getCapsule(capsuleId);
        _capsules.dismissed[capsuleId] = true;
        emit CapsuleDismissed(capsuleId);
    }

    /// @notice Publishes a capsule from this wallet after the owner confirmed an attack. Owner only.
    /// @dev A fixed call to the fixed bulletin, not an arbitrary call. The bulletin validates every field.
    function publishCapsule(
        uint8 family,
        uint8 channel,
        uint16 features,
        uint8 action,
        uint8 restriction,
        uint64 lifetime,
        uint32 guardVersion
    ) external onlyOwner returns (uint256 capsuleId) {
        return bulletin.publish(family, channel, features, action, restriction, lifetime, guardVersion);
    }

    /// @notice Attests capsule `capsuleId` from this wallet. Owner only.
    function attestCapsule(uint256 capsuleId) external onlyOwner {
        bulletin.attest(capsuleId);
    }

    /// @notice Highest bulletin capsule id this wallet has processed.
    function capsuleCursor() external view returns (uint256) {
        return _capsules.cursor;
    }

    /// @notice Whether the owner dismissed capsule `capsuleId` for this wallet.
    function capsuleDismissed(uint256 capsuleId) external view returns (bool) {
        return _capsules.dismissed[capsuleId];
    }

    /// @notice Capsules published to the bulletin that this wallet has not processed yet.
    function capsuleBacklog() external view returns (uint256) {
        return bulletin.capsuleCount() - _capsules.cursor;
    }

    /// @notice Ids of the capsules the wallet tracks, including any that expired since the last sync.
    function trackedCapsules() external view returns (uint256[] memory) {
        return _capsules.tracked;
    }

    /// @notice Synced capsules that fully or partially match a request with `action` and `flags` right now,
    ///         for the interface. `failClosed` reports unsynced capsules, or an unexpired applicable capsule
    ///         without a tracking slot, either of which raises every request to L2.
    function matchCapsules(uint8 action, uint16 flags)
        external
        view
        returns (uint256[] memory fullIds, uint256[] memory partialIds, uint8 restriction, bool failClosed)
    {
        (fullIds, partialIds, restriction) =
            CapsuleLogic.matchLists(_capsules, bulletin, _auth.mandate.channelProfile, action, flags);
        failClosed = CapsuleLogic.isFailClosed(_capsules, bulletin);
    }

    function _syncCapsules(uint256 maxCount) internal returns (uint256 processed) {
        uint256 applicable;
        (processed, applicable) = CapsuleLogic.sync(_capsules, bulletin, _auth.mandate.channelProfile, maxCount);
        if (applicable > 0) _halveAllowance(applicable);
    }
}
