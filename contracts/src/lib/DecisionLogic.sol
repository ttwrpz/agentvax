// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {CapsuleAction, Flags, Mandate, Task, Tiers} from "./AgentVaxTypes.sol";
import {CapsuleLogic} from "./CapsuleLogic.sol";
import {LedgerLogic} from "./LedgerLogic.sol";
import {IThreatBulletin} from "../interfaces/IThreatBulletin.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";
import {
    AuthorityBook,
    BlockReason,
    CapsuleBook,
    CapsuleMatch,
    LedgerBook,
    Obligation,
    Payee,
    Request,
    Verdict
} from "../wallet/WalletTypes.sol";

/// @title Decision logic: the three questions
/// @notice Linked library. Read-only: it decides, the wallet enforces.
/// @dev tier = max(q1 allowed, q2 affordable, q3 safe now).
///      q1: L1 if amount <= c1 and today's L1 total stays within d1, L2 if amount <= c2, otherwise L3.
///      q2: L1 if amount <= D (comfortable), L2 if amount <= B - R (tight), otherwise L3 (breach).
///      q3: band low L1, medium L2, high L3. A pressure flag or fail-closed capsule state raises it to at
///      least L2, and a full capsule match raises it to the capsule's effective restriction.
///      The deciding check is the lowest-numbered check that demanded the final tier. The allowance step
///      (check 4) is applied by the wallet.
///      Sweeps and fee top-ups have no payee and no spending limit. Their q1 and q2 are L1, a sweep above D
///      is blocked, and a top-up is bounded by the fee budget. Fee top-ups are never matched against capsules.
library DecisionLogic {
    uint8 private constant SOURCE_EXTERNAL = 1;

    /// @notice Inputs a decision reads from the wallet besides its books.
    struct Context {
        IERC20 token;
        IThreatBulletin bulletin;
        uint256 spentToday; // token sent at L1 today
        uint256 toppedUpToday; // native token sent by top-ups today
    }

    /// @notice Decides request `r` under the current mandate, payees, obligations and capsules.
    /// @param strict When true, revert with the matching error if the request cannot proceed at all.
    ///        When false, report it in `v.reason` (used by schedule runs, which hold instead of reverting).
    function evaluate(
        AuthorityBook storage a,
        LedgerBook storage l,
        CapsuleBook storage c,
        Context memory ctx,
        Request memory r,
        bool strict
    ) external view returns (Verdict memory v) {
        Mandate storage m = a.mandate;
        uint256 aboveReserve = _aboveReserve(ctx.token, m.reserve);
        v.discretionary =
            LedgerLogic.computeDiscretionary(l, aboveReserve, block.timestamp + m.horizon, r.obligationRef);
        v.flags = r.flags;
        v.reason = _blockReason(a, l, ctx, r, v);
        if (v.reason != BlockReason.NONE) {
            if (strict) _revertFor(v.reason, r, v.discretionary);
            return v;
        }

        uint8 q1 = Tiers.L1;
        uint8 q2 = Tiers.L1;
        if (_paysPayee(r.task)) {
            Payee storage p = a.payees[r.payeeId - 1];
            if (p.paidCount > 0 && r.amount > p.maxPaid) v.flags |= Flags.AMOUNT_ANOMALY;
            q1 = _allowedTier(m, r.amount, ctx.spentToday);
            if (r.amount > v.discretionary) q2 = r.amount <= aboveReserve ? Tiers.L2 : Tiers.L3;
        }

        uint8 q3 = r.band + 1;
        bool pressure = (v.flags & Flags.PRESSURE) != 0;
        CapsuleMatch memory cm =
            CapsuleLogic.matchRequest(c, ctx.bulletin, m.channelProfile, capsuleActionFor(r.task), v.flags);
        if ((pressure || cm.failClosed) && q3 < Tiers.L2) q3 = Tiers.L2;
        if (cm.restriction > q3) q3 = cm.restriction;
        v.capsuleId = cm.fullId != 0 ? cm.fullId : cm.partialId;
        // An approval waits Π on pressure, on a full match, and while an unmatched capsule could be one.
        v.hold = pressure || cm.fullId != 0 || cm.failClosed;

        v.afford = q2;
        v.tier = q1 > q2 ? q1 : q2;
        if (q3 > v.tier) v.tier = q3;
        if (q1 == v.tier) v.check = Tiers.CHECK_ALLOWED;
        else if (q2 == v.tier) v.check = Tiers.CHECK_AFFORDABLE;
        else v.check = Tiers.CHECK_SAFE_NOW;

        v.charge = _charge(a, r, v, cm.fullId == 0 && cm.partialId != 0);
    }

    /// @notice Capsule action matched for intent task `task`. FEE_TOPUP and unknown tasks map to NONE.
    function capsuleActionFor(uint8 task) public pure returns (CapsuleAction) {
        if (task == uint8(Task.PAYMENT)) return CapsuleAction.PAYMENT;
        if (task == uint8(Task.SCHEDULE_CREATE)) return CapsuleAction.SCHEDULE_CREATE;
        if (task == uint8(Task.SWEEP)) return CapsuleAction.SWEEP;
        return CapsuleAction.NONE;
    }

    /// @dev Conditions under which nothing may happen, whatever the tier. Sets `v.topUp` for FEE_TOPUP.
    function _blockReason(
        AuthorityBook storage a,
        LedgerBook storage l,
        Context memory ctx,
        Request memory r,
        Verdict memory v
    ) private view returns (BlockReason) {
        if (a.frozen) return BlockReason.FROZEN;
        if (block.timestamp >= a.mandate.expiry) return BlockReason.EXPIRED;
        if (_paysPayee(r.task)) {
            if (r.payeeId == 0 || r.payeeId > a.payees.length) revert IPolicyWalletErrors.UnknownPayee(r.payeeId);
            if (!a.payees[r.payeeId - 1].active) return BlockReason.PAYEE_NOT_ACTIVE;
            if (r.obligationRef != 0) {
                Obligation storage o = l.obligations[r.obligationRef];
                if (!o.open || o.payeeId != r.payeeId || o.amount != r.amount) {
                    return BlockReason.OBLIGATION_MISMATCH;
                }
                // A schedule occurrence is not paid before it is due, so a payment cannot advance the
                // schedule ahead of its signed cadence. One-off bills may be paid early.
                if (o.scheduleId != 0 && block.timestamp < o.due) return BlockReason.OBLIGATION_NOT_DUE;
            }
        } else if (r.task == uint8(Task.SWEEP)) {
            if (r.amount > v.discretionary) return BlockReason.OVER_DISCRETIONARY;
        } else {
            v.topUp = _topUpAmount(a, r.amount, ctx.toppedUpToday);
            if (v.topUp == 0) return BlockReason.NOTHING_TO_TOP_UP;
        }
        return BlockReason.NONE;
    }

    function _revertFor(BlockReason reason, Request memory r, uint256 d) private pure {
        if (reason == BlockReason.FROZEN) revert IPolicyWalletErrors.WalletIsFrozen();
        if (reason == BlockReason.EXPIRED) revert IPolicyWalletErrors.MandateExpired();
        if (reason == BlockReason.PAYEE_NOT_ACTIVE) revert IPolicyWalletErrors.PayeeNotActive(r.payeeId);
        if (reason == BlockReason.OBLIGATION_MISMATCH) {
            revert IPolicyWalletErrors.ObligationMismatch(r.obligationRef);
        }
        if (reason == BlockReason.OBLIGATION_NOT_DUE) revert IPolicyWalletErrors.ObligationNotDue(r.obligationRef);
        if (reason == BlockReason.OVER_DISCRETIONARY) {
            revert IPolicyWalletErrors.SweepExceedsDiscretionary(r.amount, d);
        }
        revert IPolicyWalletErrors.NothingToTopUp();
    }

    /// @dev q1 for a payment of `amount` given what was already spent at L1 today.
    function _allowedTier(Mandate storage m, uint256 amount, uint256 spent) private view returns (uint8) {
        if (amount <= m.c1 && spent <= m.d1 && amount <= m.d1 - spent) return Tiers.L1;
        if (amount <= m.c2) return Tiers.L2;
        return Tiers.L3;
    }

    /// @dev Allowance points for an otherwise routine request. A clean request costs 0.
    function _charge(AuthorityBook storage a, Request memory r, Verdict memory v, bool partialMatch)
        private
        view
        returns (uint256 points)
    {
        Mandate storage m = a.mandate;
        if (r.source == SOURCE_EXTERNAL) points += m.chargeExternal;
        if (r.task != uint8(Task.FEE_TOPUP) && r.amount > v.discretionary / 2) points += m.chargeOverHalfD;
        if ((v.flags & Flags.AMOUNT_ANOMALY) != 0) points += m.chargeAnomaly;
        if (_paysPayee(r.task) && a.payees[r.payeeId - 1].paidCount == 0) points += m.chargeFirstPayment;
        if (partialMatch) points += m.chargePartialCapsule;
    }

    /// @dev Native token a top-up of at most `requested` may send now: bounded by the per-top-up cap, the
    ///      agent's deficit below the floor, the rest of today's budget, and the wallet's native reserve.
    function _topUpAmount(AuthorityBook storage a, uint256 requested, uint256 usedToday)
        private
        view
        returns (uint256 amount)
    {
        address agentKey = a.agent;
        Mandate storage m = a.mandate;
        if (agentKey == address(0) || agentKey.balance >= m.agentBalanceFloor) return 0;
        if (usedToday >= m.feeDailyBudget || address(this).balance <= m.nativeReserve) return 0;
        amount = _min(requested, m.feeTopUpCap);
        amount = _min(amount, m.agentBalanceFloor - agentKey.balance);
        amount = _min(amount, m.feeDailyBudget - usedToday);
        amount = _min(amount, address(this).balance - m.nativeReserve);
    }

    function _aboveReserve(IERC20 token, uint256 reserve) private view returns (uint256) {
        uint256 balance = token.balanceOf(address(this));
        return balance > reserve ? balance - reserve : 0;
    }

    function _paysPayee(uint8 task) private pure returns (bool) {
        return task == uint8(Task.PAYMENT) || task == uint8(Task.SCHEDULE_CREATE);
    }

    function _min(uint256 x, uint256 y) private pure returns (uint256) {
        return x < y ? x : y;
    }
}
