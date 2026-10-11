// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ScheduleTerms} from "../lib/AgentVaxTypes.sol";
import {ChangeKind} from "../wallet/WalletTypes.sol";

/// @title Events of the PolicyWallet
/// @notice Shared by the wallet and its linked libraries. Events from a linked library are logged at the
///         wallet's address.
interface IPolicyWalletEvents {
    /// @notice The mandate changed. `mandateHash` = keccak256(abi.encode(missionHash, mandate)).
    event MandateSet(bytes32 indexed mandateHash, bytes32 indexed missionHash);
    /// @notice The mission text behind `missionHash`, published when it is set or proposed.
    event MissionStated(bytes32 indexed missionHash, string mission);
    /// @notice A loosening change was proposed and can be applied from `readyAt`.
    event ChangeProposed(uint256 indexed changeId, ChangeKind kind, uint64 readyAt);
    /// @notice A loosening change was applied after Λ.
    event ChangeApplied(uint256 indexed changeId, ChangeKind kind);
    /// @notice A loosening change was cancelled.
    event ChangeCancelled(uint256 indexed changeId);
    /// @notice A payee was added through the time-lock.
    event PayeeAdded(uint32 indexed payeeId, bytes32 indexed identityHash, address account);
    /// @notice A payee was removed by the owner.
    event PayeeRemoved(uint32 indexed payeeId);
    /// @notice The agent recorded a request to pay a new address. It carries no authority.
    event PayeeChangeRequested(bytes32 indexed identityHash, address account, uint16 flags);
    /// @notice An obligation was registered by `by`, which is the wallet itself for schedule occurrences.
    event ObligationAdded(uint64 indexed obligationId, uint32 indexed payeeId, uint256 amount, uint64 due, address by);
    /// @notice An obligation was paid.
    event ObligationSettled(uint64 indexed obligationId);
    /// @notice An obligation was removed by the owner after Λ.
    event ObligationRemoved(uint64 indexed obligationId);
    /// @notice A schedule was created.
    event ScheduleCreated(uint64 indexed scheduleId, uint32 indexed payeeId, uint256 amount, ScheduleTerms terms);
    /// @notice A scheduled occurrence was paid.
    event ScheduleRan(uint64 indexed scheduleId, uint64 obligationId, uint256 amount);
    /// @notice A due occurrence was not paid. `reason` is a `BlockReason`. `decidingCheck` is set when the
    ///         tier was above L1.
    event ScheduleHeld(uint64 indexed scheduleId, uint8 reason, uint8 decidingCheck);
    /// @notice A schedule ran all its occurrences.
    event ScheduleCompleted(uint64 indexed scheduleId);
    /// @notice The owner cancelled a schedule. Its registered obligation stays until removed through Λ.
    event ScheduleCancelled(uint64 indexed scheduleId);
    /// @notice The tier decided for a request and the check that decided it. Emitted on submission, on
    ///         re-assessment of a pending item at execution, and for every schedule run not blocked outright.
    ///         For a schedule run `intentHash` is zero and the following `ScheduleRan` or `ScheduleHeld` names it.
    event Decision(bytes32 indexed intentHash, uint8 tier, uint8 decidingCheck, uint256 capsuleId);
    /// @notice An L2 item was queued.
    event Queued(uint256 indexed itemId, bytes32 indexed intentHash, uint64 readyAt);
    /// @notice An L3 item waits for the owner.
    event Proposed(uint256 indexed itemId, bytes32 indexed intentHash);
    /// @notice The owner approved an L3 item. It can execute from `readyAt`.
    event Approved(uint256 indexed itemId, uint64 readyAt);
    /// @notice The owner lengthened the wait of an item. `extraHold` is the total added so far.
    event HoldExtended(uint256 indexed itemId, uint64 extraHold);
    /// @notice The owner cancelled an item.
    event ItemCancelled(uint256 indexed itemId);
    /// @notice An intent took effect. `itemId` is 0 for an L1 execution and for schedule runs. For
    ///         SCHEDULE_CREATE no value moves and `to` is the payee.
    event Executed(uint256 indexed itemId, bytes32 indexed intentHash, uint8 task, address to, uint256 amount);
    /// @notice The allowance was charged for an L1 execution. Values in allowance units.
    event AllowanceCharged(bytes32 indexed intentHash, uint256 charge, uint256 remaining);
    /// @notice The allowance was halved `times` times because applicable capsules arrived.
    event AllowanceHalved(uint256 times, uint256 remaining);
    /// @notice The owner confirmed an attack. The allowance is zero.
    event AttackConfirmed();
    /// @notice A newly synced capsule applies to this wallet's channel profile.
    event CapsuleTracked(uint256 indexed capsuleId);
    /// @notice An applicable capsule ranks below every tracked one and is kept in the spilled list. While any
    ///         capsule is spilled, every request waits at least Δ.
    event CapsuleSpilled(uint256 indexed capsuleId);
    /// @notice An applicable capsule found no room in the tracked or the spilled list. Every request waits at
    ///         least Δ, and no pending item executes, until `failClosedUntil`.
    event CapsuleUntracked(uint256 indexed capsuleId, uint64 failClosedUntil);
    /// @notice The wallet processed bulletin capsules up to `cursor`. A lower cursor than before means a rescan
    ///         after a channel was added to the profile.
    event CapsulesSynced(uint256 cursor, uint256 tracked);
    /// @notice The owner dismissed a capsule for this wallet only.
    event CapsuleDismissed(uint256 indexed capsuleId);
    /// @notice The wallet was frozen.
    event WalletFrozen();
    /// @notice The wallet was unfrozen after Λ.
    event WalletUnfrozen();
    /// @notice The agent key changed. `address(0)` means revoked.
    event AgentChanged(address agent);
    /// @notice The guardian key changed.
    event GuardianChanged(address guardian);
    /// @notice Native token arrived for the fee reserve.
    event FeeReserveFunded(address indexed from, uint256 amount);
}
