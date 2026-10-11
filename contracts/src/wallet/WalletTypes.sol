// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Mandate, ScheduleTerms} from "../lib/AgentVaxTypes.sol";

/// @title Record types internal to the PolicyWallet and its logic libraries

/// @notice An approved payee: the pair of an identity and an address.
struct Payee {
    bytes32 identityHash;
    address account;
    bool active;
    uint32 paidCount;
    uint256 maxPaid;
}

/// @notice A registered bill. Settled or removed obligations are never reopened.
struct Obligation {
    uint32 payeeId;
    uint64 due;
    uint64 scheduleId; // 0 for a one-off bill
    bool open;
    bool byAgent; // added by the agent key, counts toward the agent's share of the slots
    uint256 amount;
}

/// @notice A recurring payment created by a SCHEDULE_CREATE intent.
struct Schedule {
    uint32 payeeId;
    bool active;
    uint32 runsDone;
    uint64 nextDue;
    uint64 obligationId; // obligation registered for the next occurrence, 0 once inactive by completion
    ScheduleTerms terms;
    uint256 amount;
}

/// @notice Obligations and schedules of one wallet. Operated on by `LedgerLogic`.
struct LedgerBook {
    mapping(uint64 id => Obligation) obligations;
    uint64 obligationCount;
    uint64[] openIds;
    uint256 agentOpen; // open obligations added by the agent
    mapping(uint64 id => Schedule) schedules;
    uint64 scheduleCount;
    uint256 activeSchedules;
}

/// @notice The wallet's view of the bulletin. Operated on by `CapsuleLogic`.
struct CapsuleBook {
    uint256 cursor; // highest bulletin capsule id processed
    uint256[] tracked; // unexpired capsules that applied to the channel profile when synced
    mapping(uint256 capsuleId => bool) dismissed;
    mapping(uint256 capsuleId => bool) seen; // applied when synced, counted once for allowance halving
    uint256[] spilled; // applicable capsules ranked below every tracked one, re-ranked at every sync
    uint8 spilledTop; // highest effective restriction among spilled capsules at the last sync
    uint64 overflowUntil; // latest expiry of an applicable capsule in neither list, fail closed until then
}

/// @notice Result of matching one request against the tracked capsules.
struct CapsuleMatch {
    uint8 restriction; // highest effective restriction of a full match, 0 if none
    uint256 fullId; // capsule that set `restriction`
    uint256 partialId; // first partially matching capsule, 0 if none
    bool failClosed; // backlog, spilled or dropped capsules: every request waits at least Δ
}

/// @notice Status of a queued (L2) or proposed (L3) item.
enum ItemStatus {
    NONE,
    QUEUED, // L2, waits Δ
    PROPOSED, // L3, waits for the owner
    APPROVED, // L3 approved, waits Π if held
    EXECUTED,
    CANCELLED
}

/// @notice The facts a decision is made on: the intent fields and the guardian's signed band, source and flags.
struct Request {
    uint8 task; // `Task`
    uint8 band; // 0 low, 1 medium, 2 high
    uint8 source; // 0 owner instruction, 1 external content
    uint16 flags; // `Flags`, the contract adds AMOUNT_ANOMALY itself
    uint32 payeeId;
    uint64 obligationRef; // PAYMENT only: 1-based obligation being paid, 0 for none
    uint256 amount;
}

/// @notice Why a request cannot proceed at all, whatever its tier.
enum BlockReason {
    NONE,
    FROZEN,
    EXPIRED,
    PAYEE_NOT_ACTIVE,
    OBLIGATION_MISMATCH,
    OVER_DISCRETIONARY,
    NOTHING_TO_TOP_UP,
    OBLIGATION_NOT_DUE
}

/// @notice Outcome of the three questions for one request, before the allowance step.
struct Verdict {
    BlockReason reason; // when not NONE, nothing else is meaningful
    uint8 tier; // max(q1, q2, q3)
    uint8 afford; // q2 alone: 1 comfortable, 2 tight, 3 breach
    uint8 check; // lowest-numbered check that demanded `tier`
    uint256 capsuleId; // full match that raised the tier, else the first partial match, else 0
    uint16 flags; // request flags with AMOUNT_ANOMALY added when it applies
    bool hold; // a pressure flag or a full capsule match: an owner approval waits Π
    uint256 discretionary; // D, leaving out the bound obligation
    uint256 charge; // allowance points an L1 execution would cost
    uint256 topUp; // FEE_TOPUP only: native amount that may be sent now
}

/// @notice An intent that did not execute at L1. Executed later through the same value gate.
struct Item {
    bytes32 intentHash;
    Request req;
    uint8 tier; // tier it was authorised at: 2 queued, 3 owner approval
    uint8 approvedAfford; // L3 only: q2 when the owner approved, execution needs q2 no worse than this
    ItemStatus status;
    bool hold; // a pressure flag or a full capsule match was present at decision time
    uint64 queuedAt;
    uint64 approvedAt;
    uint64 lockSnapshot; // Δ when queued (L2) or Π when approved (L3)
    uint64 extraHold; // seconds added by the owner through extendHold
    ScheduleTerms terms; // SCHEDULE_CREATE only
}

/// @notice Queued and proposed items. Operated on by `ItemLogic`.
struct ItemBook {
    mapping(uint256 id => Item) items;
    uint256 count; // item ids run from 1 to count
}

/// @notice Kind of a loosening change waiting on the time-lock Λ.
enum ChangeKind {
    NONE,
    ADD_PAYEE,
    MANDATE,
    REMOVE_OBLIGATION,
    AGENT,
    GUARDIAN,
    UNFREEZE
}

/// @notice Status of a loosening change.
enum ChangeStatus {
    NONE,
    PENDING,
    APPLIED,
    CANCELLED
}

/// @notice A loosening change. Typed fields, no generic payload.
struct Change {
    ChangeKind kind;
    ChangeStatus status;
    uint64 proposedAt;
    uint64 readyAt; // proposedAt + Λ at proposal time
    address account; // ADD_PAYEE, AGENT, GUARDIAN
    uint64 obligationId; // REMOVE_OBLIGATION
    uint64 epoch; // tightening epoch of this kind when proposed, a later tightening makes the change stale
    bytes32 key; // identity hash (ADD_PAYEE) or mission hash (MANDATE)
    bytes32 baseMandateHash; // MANDATE: the mandate hash in force when proposed
}

/// @notice Everything only the owner can change: the mandate, payees, keys, freeze and pending loosening
///         changes. Operated on by `AuthorityLogic`.
struct AuthorityBook {
    Mandate mandate;
    bool mandateSet;
    bool frozen;
    address agent;
    address guardian;
    bytes32 missionHash; // keccak256 of the mission text
    bytes32 mandateHash; // keccak256(abi.encode(missionHash, mandate))
    Payee[] payees; // payee id = index + 1
    mapping(bytes32 pairHash => uint32 payeeId) activePayeeByPair;
    mapping(uint256 id => Change) changes;
    mapping(uint256 id => Mandate) proposedMandates;
    uint256 changeCount;
    // Tightening epochs. Each only grows. A pending change is stale once an epoch it depends on has grown.
    uint32 freezeEpoch; // grows on every freeze, all pending changes depend on it
    uint32 payeeRemovalEpoch; // grows on every payee removal, ADD_PAYEE depends on it
    uint32 agentRevokeEpoch; // grows on every agent revocation, AGENT depends on it
}
