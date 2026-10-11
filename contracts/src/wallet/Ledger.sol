// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ScheduleTerms} from "../lib/AgentVaxTypes.sol";
import {LedgerLogic} from "../lib/LedgerLogic.sol";
import {Obligation, Payee, Schedule} from "./WalletTypes.sol";
import {CautionAllowance} from "./CautionAllowance.sol";

/// @title Ledger: payees, obligations, schedules and the discretionary amount
/// @notice D = B - R - sum(open obligations due within H), floored at zero, leaving out the obligation
///         being paid. Expected income is not counted.
/// @dev The agent may add obligations, which can only lower D. Only the owner removes one, through Λ.
abstract contract Ledger is CautionAllowance {
    /// @notice Most open obligations the wallet holds.
    uint256 public constant MAX_OBLIGATIONS = LedgerLogic.MAX_OBLIGATIONS;
    /// @notice Most active schedules the wallet holds.
    uint256 public constant MAX_SCHEDULES = LedgerLogic.MAX_SCHEDULES;
    /// @notice Most open obligations the agent may have added at one time.
    uint256 public constant MAX_AGENT_OBLIGATIONS = LedgerLogic.MAX_AGENT_OBLIGATIONS;
    /// @notice Shortest period a schedule may have.
    uint64 public constant MIN_SCHEDULE_PERIOD = 1 days;
    /// @notice Type hash that `Intent.purposeHash` commits to for SCHEDULE_CREATE.
    bytes32 public constant SCHEDULE_TERMS_TYPEHASH =
        keccak256("ScheduleTerms(uint64 period,uint64 firstDue,uint32 maxRuns)");

    // ------------------------------------------------------------------ external

    /// @notice Registers a bill, which lowers the discretionary amount. Owner or agent. The agent may have at
    ///         most MAX_AGENT_OBLIGATIONS open at once so that it cannot fill the owner's slots.
    /// @param payeeId Existing payee the bill is owed to.
    /// @param amount Token amount in base units.
    /// @param due Time the bill is due.
    /// @return id The new obligation id.
    function addObligation(uint32 payeeId, uint256 amount, uint64 due) external whenMandateSet returns (uint64 id) {
        bool byOwner = msg.sender == owner;
        if (!byOwner && msg.sender != _auth.agent) revert NotOwnerOrAgent();
        _payee(payeeId);
        return LedgerLogic.addObligation(_ledger, payeeId, amount, due, msg.sender, !byOwner);
    }

    /// @notice Stops a schedule. Owner only, immediate. Its open obligation stays registered until the
    ///         owner removes it through Λ, because removing it would raise D.
    function cancelSchedule(uint64 scheduleId) external onlyOwner {
        LedgerLogic.cancelSchedule(_ledger, scheduleId);
    }

    // ------------------------------------------------------------------ views

    /// @notice The discretionary amount now, leaving out obligation `excludedObligation` (0 for none).
    function discretionary(uint64 excludedObligation) external view returns (uint256) {
        return _discretionary(excludedObligation);
    }

    /// @notice Hash `Intent.purposeHash` must equal for a SCHEDULE_CREATE intent with these terms.
    function hashScheduleTerms(ScheduleTerms memory terms) public pure returns (bytes32) {
        return keccak256(abi.encode(SCHEDULE_TERMS_TYPEHASH, terms.period, terms.firstDue, terms.maxRuns));
    }

    /// @notice Number of payees ever added. Payee ids run from 1 to this value.
    function payeeCount() external view returns (uint256) {
        return _auth.payees.length;
    }

    /// @notice Payee `payeeId`.
    function getPayee(uint32 payeeId) external view returns (Payee memory) {
        return _payee(payeeId);
    }

    /// @notice Obligation `obligationId`.
    function getObligation(uint64 obligationId) external view returns (Obligation memory) {
        return _ledger.obligations[obligationId];
    }

    /// @notice Open obligations added by the agent.
    function agentObligationCount() external view returns (uint256) {
        return _ledger.agentOpen;
    }

    /// @notice Ids of all open obligations.
    function openObligationIds() external view returns (uint64[] memory) {
        return _ledger.openIds;
    }

    /// @notice Schedule `scheduleId`.
    function getSchedule(uint64 scheduleId) external view returns (Schedule memory) {
        return _ledger.schedules[scheduleId];
    }

    /// @notice Number of schedules ever created and the number still active.
    function scheduleCounts() external view returns (uint64 created, uint256 active) {
        return (_ledger.scheduleCount, _ledger.activeSchedules);
    }

    // ------------------------------------------------------------------ internal

    /// @dev B - R - sum(open obligations due by now + H, except `excluded`), floored at zero.
    function _discretionary(uint64 excluded) internal view returns (uint256) {
        return LedgerLogic.discretionary(_ledger, _aboveReserve(), block.timestamp + _auth.mandate.horizon, excluded);
    }

    /// @dev B - R, floored at zero: the most a payment can be without breaching the reserve.
    function _aboveReserve() internal view returns (uint256) {
        uint256 balance = token.balanceOf(address(this));
        uint256 reserve = _auth.mandate.reserve;
        return balance > reserve ? balance - reserve : 0;
    }

    /// @dev True if schedule terms are within the contract's bounds.
    function _validScheduleTerms(ScheduleTerms memory terms) internal view returns (bool) {
        return terms.period >= MIN_SCHEDULE_PERIOD && terms.maxRuns > 0 && terms.firstDue >= block.timestamp;
    }

    function _payee(uint32 payeeId) internal view returns (Payee storage) {
        if (payeeId == 0 || payeeId > _auth.payees.length) revert UnknownPayee(payeeId);
        return _auth.payees[payeeId - 1];
    }
}
