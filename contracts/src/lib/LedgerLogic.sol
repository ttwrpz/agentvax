// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Flags, ScheduleTerms, Task} from "./AgentVaxTypes.sol";
import {LedgerBook, Obligation, Request, Schedule} from "../wallet/WalletTypes.sol";
import {IPolicyWalletEvents} from "../interfaces/IPolicyWalletEvents.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";

/// @title Ledger logic: obligations, schedules and the discretionary amount
/// @notice Linked library operating on the wallet's `LedgerBook`.
/// @dev D = (B - R) - sum(open obligations due within H, except the one being paid), floored at zero.
///      Each schedule keeps exactly one open obligation for its next occurrence. Every occurrence gets a
///      fresh obligation id, so a settled reference can never exclude an obligation again.
library LedgerLogic {
    /// @notice Most open obligations a wallet holds.
    uint256 internal constant MAX_OBLIGATIONS = 32;
    /// @notice Most active schedules a wallet holds. Each holds one open obligation.
    uint256 internal constant MAX_SCHEDULES = 16;
    /// @notice Most open obligations the agent key may have added. With every schedule slot in use this still
    ///         leaves MAX_OBLIGATIONS - MAX_SCHEDULES - MAX_AGENT_OBLIGATIONS = 4 slots for the owner alone.
    uint256 internal constant MAX_AGENT_OBLIGATIONS = 12;

    /// @notice Discretionary amount, given `aboveReserve` = max(B - R, 0) and the end of the horizon.
    function discretionary(LedgerBook storage l, uint256 aboveReserve, uint256 horizonEnd, uint64 excluded)
        external
        view
        returns (uint256)
    {
        return computeDiscretionary(l, aboveReserve, horizonEnd, excluded);
    }

    /// @dev Saturating: no obligation amount can overflow it. Internal so other libraries can inline it.
    function computeDiscretionary(LedgerBook storage l, uint256 aboveReserve, uint256 horizonEnd, uint64 excluded)
        internal
        view
        returns (uint256 available)
    {
        available = aboveReserve;
        uint256 n = l.openIds.length;
        for (uint256 i = 0; i < n; ++i) {
            uint64 id = l.openIds[i];
            if (id == excluded) continue;
            Obligation storage o = l.obligations[id];
            if (o.due > horizonEnd) continue;
            if (o.amount >= available) return 0;
            available -= o.amount;
        }
    }

    /// @notice Registers a one-off obligation added by `by`. `byAgent` marks the agent key, whose open
    ///         obligations are capped at MAX_AGENT_OBLIGATIONS.
    function addObligation(LedgerBook storage l, uint32 payeeId, uint256 amount, uint64 due, address by, bool byAgent)
        external
        returns (uint64 id)
    {
        if (amount == 0 || due == 0) revert IPolicyWalletErrors.InvalidObligation();
        if (byAgent) {
            if (l.agentOpen >= MAX_AGENT_OBLIGATIONS) revert IPolicyWalletErrors.AgentObligationsFull();
            l.agentOpen += 1;
        }
        id = _open(l, payeeId, amount, due, 0, by);
        if (byAgent) l.obligations[id].byAgent = true;
    }

    /// @notice Closes obligation `id` without paying it. Used when the owner removes it after Λ.
    function removeObligation(LedgerBook storage l, uint64 id) external {
        requireRemovable(l, id);
        _close(l, id);
        emit IPolicyWalletEvents.ObligationRemoved(id);
    }

    /// @notice Settles a paid obligation. If it is the current occurrence of an active schedule, the
    ///         schedule advances: a fresh obligation is opened for the next occurrence, or the schedule completes.
    function settleObligation(LedgerBook storage l, uint64 id) external {
        _close(l, id);
        emit IPolicyWalletEvents.ObligationSettled(id);
        uint64 scheduleId = l.obligations[id].scheduleId;
        if (scheduleId == 0) return;
        Schedule storage s = l.schedules[scheduleId];
        if (!s.active || s.obligationId != id) return;
        s.runsDone += 1;
        if (s.runsDone >= s.terms.maxRuns) {
            s.active = false;
            s.obligationId = 0;
            l.activeSchedules -= 1;
            emit IPolicyWalletEvents.ScheduleCompleted(scheduleId);
            return;
        }
        s.nextDue += s.terms.period;
        s.obligationId = _open(l, s.payeeId, s.amount, s.nextDue, scheduleId, address(this));
    }

    /// @notice Creates a schedule and registers its first occurrence as an obligation.
    function createSchedule(LedgerBook storage l, uint32 payeeId, uint256 amount, ScheduleTerms memory terms)
        external
        returns (uint64 id)
    {
        if (l.activeSchedules >= MAX_SCHEDULES) revert IPolicyWalletErrors.SchedulesFull();
        id = ++l.scheduleCount;
        l.activeSchedules += 1;
        emit IPolicyWalletEvents.ScheduleCreated(id, payeeId, amount, terms);
        uint64 obligationId = _open(l, payeeId, amount, terms.firstDue, id, address(this));
        Schedule storage s = l.schedules[id];
        s.payeeId = payeeId;
        s.active = true;
        s.nextDue = terms.firstDue;
        s.obligationId = obligationId;
        s.terms = terms;
        s.amount = amount;
    }

    /// @notice The payment request for the due occurrence of schedule `id`. Reverts if it is not active or not due.
    /// @dev A run carries no guardian attestation: band low, owner source, and only the known-payee flag.
    function dueRun(LedgerBook storage l, uint64 id) external view returns (Request memory) {
        if (id == 0 || id > l.scheduleCount) revert IPolicyWalletErrors.UnknownSchedule(id);
        Schedule storage s = l.schedules[id];
        if (!s.active) revert IPolicyWalletErrors.ScheduleNotActive(id);
        if (block.timestamp < s.nextDue) revert IPolicyWalletErrors.ScheduleNotDue(id, s.nextDue);
        return Request({
            task: uint8(Task.PAYMENT),
            band: 0,
            source: 0,
            flags: Flags.KNOWN_PAYEE_IDENTITY,
            payeeId: s.payeeId,
            obligationRef: s.obligationId,
            amount: s.amount
        });
    }

    /// @notice Stops schedule `id`. Its open obligation stays registered.
    function cancelSchedule(LedgerBook storage l, uint64 id) external {
        if (id == 0 || id > l.scheduleCount) revert IPolicyWalletErrors.UnknownSchedule(id);
        Schedule storage s = l.schedules[id];
        if (!s.active) revert IPolicyWalletErrors.ScheduleNotActive(id);
        s.active = false;
        l.activeSchedules -= 1;
        emit IPolicyWalletEvents.ScheduleCancelled(id);
    }

    /// @notice Reverts unless obligation `id` is open and is not the current occurrence of an active schedule.
    function requireRemovable(LedgerBook storage l, uint64 id) public view {
        Obligation storage o = l.obligations[id];
        if (!o.open) revert IPolicyWalletErrors.ObligationNotOpen(id);
        if (o.scheduleId != 0) {
            Schedule storage s = l.schedules[o.scheduleId];
            if (s.active && s.obligationId == id) {
                revert IPolicyWalletErrors.ObligationBelongsToSchedule(id, o.scheduleId);
            }
        }
    }

    function _open(LedgerBook storage l, uint32 payeeId, uint256 amount, uint64 due, uint64 scheduleId, address by)
        private
        returns (uint64 id)
    {
        if (l.openIds.length >= MAX_OBLIGATIONS) revert IPolicyWalletErrors.ObligationsFull();
        id = ++l.obligationCount;
        l.obligations[id] = Obligation({
            payeeId: payeeId, due: due, scheduleId: scheduleId, open: true, byAgent: false, amount: amount
        });
        l.openIds.push(id);
        emit IPolicyWalletEvents.ObligationAdded(id, payeeId, amount, due, by);
    }

    function _close(LedgerBook storage l, uint64 id) private {
        Obligation storage o = l.obligations[id];
        o.open = false;
        if (o.byAgent) l.agentOpen -= 1;
        uint256 n = l.openIds.length;
        for (uint256 i = 0; i < n; ++i) {
            if (l.openIds[i] == id) {
                l.openIds[i] = l.openIds[n - 1];
                l.openIds.pop();
                return;
            }
        }
    }
}
