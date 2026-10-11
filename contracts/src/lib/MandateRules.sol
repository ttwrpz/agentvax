// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Mandate, Channels} from "./AgentVaxTypes.sol";

/// @title Rules for mandate values
/// @notice Well-formedness and the tightening order on mandates.
/// @dev `next` is tighter or equal to `cur` only if every field moves in its tightening direction or stays
///      equal. A mixed update with even one looser field must go through Λ.
library MandateRules {
    /// @notice Longest L2 delay Δ. Lengthening Δ is immediate, so the bound limits how long one call can
    ///         hold queued payments.
    uint64 internal constant MAX_DELAY = 30 days;
    /// @notice Longest loosening delay Λ. Lengthening Λ is immediate, so the bound keeps every later
    ///         loosening, including unfreezing, reachable.
    uint64 internal constant MAX_LOOSENING_DELAY = 30 days;
    /// @notice Longest pressure hold Π.
    uint64 internal constant MAX_PRESSURE_HOLD = 7 days;

    /// @notice True if `m` is internally consistent, its delays are within their bounds, and it has not
    ///         expired at `nowTs`.
    function isWellFormed(Mandate memory m, uint256 nowTs) internal pure returns (bool) {
        return m.c1 <= m.c2 && m.delay > 0 && m.delay <= MAX_DELAY && m.looseningDelay > 0
            && m.looseningDelay <= MAX_LOOSENING_DELAY && m.pressureHold > 0 && m.pressureHold <= MAX_PRESSURE_HOLD
            && m.refillPeriod > 0 && m.horizon > 0 && m.expiry > nowTs && m.channelProfile <= Channels.ALL_MASK;
    }

    /// @notice True if every field of `next` is equal to or tighter than the same field of `cur`.
    function isTighterOrEqual(Mandate memory cur, Mandate memory next) internal pure returns (bool) {
        return _limitsTighter(cur, next) && _delaysTighter(cur, next) && _allowanceTighter(cur, next)
            && _feesTighter(cur, next);
    }

    function _limitsTighter(Mandate memory cur, Mandate memory next) private pure returns (bool) {
        return next.reserve >= cur.reserve && next.c1 <= cur.c1 && next.d1 <= cur.d1 && next.c2 <= cur.c2
            && next.horizon >= cur.horizon && next.expiry <= cur.expiry;
    }

    function _delaysTighter(Mandate memory cur, Mandate memory next) private pure returns (bool) {
        return next.delay >= cur.delay && next.looseningDelay >= cur.looseningDelay
            && next.pressureHold >= cur.pressureHold;
    }

    function _allowanceTighter(Mandate memory cur, Mandate memory next) private pure returns (bool) {
        // Channel profiles are compared as sets: the new profile must contain every current channel.
        return next.allowanceMax <= cur.allowanceMax && next.refillPeriod >= cur.refillPeriod
            && (next.channelProfile & cur.channelProfile) == cur.channelProfile
            && next.chargeExternal >= cur.chargeExternal && next.chargeOverHalfD >= cur.chargeOverHalfD
            && next.chargeAnomaly >= cur.chargeAnomaly && next.chargeFirstPayment >= cur.chargeFirstPayment
            && next.chargePartialCapsule >= cur.chargePartialCapsule;
    }

    function _feesTighter(Mandate memory cur, Mandate memory next) private pure returns (bool) {
        return next.feeTopUpCap <= cur.feeTopUpCap && next.feeDailyBudget <= cur.feeDailyBudget
            && next.agentBalanceFloor <= cur.agentBalanceFloor && next.nativeReserve >= cur.nativeReserve;
    }
}
