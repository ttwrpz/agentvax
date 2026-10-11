// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Capsule} from "../lib/AgentVaxTypes.sol";

/// @title Threat bulletin interface used by the PolicyWallet
interface IThreatBulletin {
    /// @notice Number of capsules ever published. Capsule ids run from 1 to this value.
    function capsuleCount() external view returns (uint256);

    /// @notice The stored capsule `id`.
    function getCapsule(uint256 id) external view returns (Capsule memory);

    /// @notice The fields a wallet needs to match capsule `id`, with the restriction capped by confidence.
    function matchFields(uint256 id)
        external
        view
        returns (uint8 channel, uint16 features, uint8 action, uint8 effectiveRestriction, uint64 expiry);

    /// @notice How strongly capsule `id` restricts now, for ranking: its effective restriction, then its
    ///         attestations, then its expiry. A larger tuple is stronger.
    function strength(uint256 id) external view returns (uint8 effectiveRestriction, uint8 attestations, uint64 expiry);

    /// @notice Lowest capsule id that may still be unexpired, or `capsuleCount() + 1` if none may be.
    /// @dev Capsule ids increase with publication time and no capsule outlives its publication by more than the
    ///      maximum lifetime, so every capsule below this id has expired.
    function firstPossiblyLive() external view returns (uint256);

    /// @notice Publishes a capsule. Only a registered wallet may call.
    function publish(
        uint8 family,
        uint8 channel,
        uint16 features,
        uint8 action,
        uint8 restriction,
        uint64 lifetime,
        uint32 guardVersion
    ) external returns (uint256 id);

    /// @notice Attests capsule `id`. Only a registered wallet other than the issuer may call.
    function attest(uint256 id) external;
}
