// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Shared types of the AgentVax contracts
/// @notice Enumerations, structs and bit constants used by the wallet, the bulletin and the off-chain runtime.
///         Numeric values are part of the external interface (EIP-712 fields, capsule fields) and never change.

/// @notice Task carried in the EIP-712 `Intent.task` field.
enum Task {
    NONE, // 0, never valid
    PAYMENT, // 1
    SCHEDULE_CREATE, // 2
    SWEEP, // 3
    FEE_TOPUP // 4
}

/// @notice Action a capsule targets. Distinct from `Task`: FEE_TOPUP has no capsule action.
enum CapsuleAction {
    NONE, // 0, never matched
    PAYMENT, // 1
    SCHEDULE_CREATE, // 2
    SWEEP, // 3
    PAYEE_OR_MANDATE_CHANGE // 4
}

/// @notice The owner's mandate. Every field has a tightening direction, see `MandateRules`.
/// @dev Token amounts are in MockUSD base units (6 decimals). Native amounts are in wei. Durations are in seconds.
struct Mandate {
    uint256 reserve; // R, kept back from discretionary spending. Larger is tighter
    uint256 c1; // autonomous limit per payment. Smaller is tighter
    uint256 d1; // autonomous limit per day. Smaller is tighter
    uint256 c2; // limit with delay. Smaller is tighter
    uint64 delay; // Δ, the L2 delay. Longer is tighter
    uint64 looseningDelay; // Λ. Longer is tighter
    uint64 pressureHold; // Π. Longer is tighter
    uint64 refillPeriod; // time for the allowance to refill from zero to A. Longer is tighter
    uint64 horizon; // H, obligations due within it are reserved. Longer is tighter
    uint64 expiry; // absolute time after which no value moves. Earlier is tighter
    uint32 allowanceMax; // A in points. Smaller is tighter
    uint8 channelProfile; // bitmask of channels the wallet listens to. A superset is tighter
    uint8 chargeExternal; // points for a request that came from external content. Larger is tighter
    uint8 chargeOverHalfD; // points for a request above half of D. Larger is tighter
    uint8 chargeAnomaly; // points for AMOUNT_ANOMALY. Larger is tighter
    uint8 chargeFirstPayment; // points for the first payment to a payee. Larger is tighter
    uint8 chargePartialCapsule; // points for a partial capsule match. Larger is tighter
    uint256 feeTopUpCap; // native token per top-up. Smaller is tighter
    uint256 feeDailyBudget; // native token per day for top-ups. Smaller is tighter
    uint256 agentBalanceFloor; // top-ups only bring the agent up to this. Smaller is tighter
    uint256 nativeReserve; // native token the wallet always keeps. Larger is tighter
}

/// @notice EIP-712 `Intent(uint8 task,uint32 payeeId,uint256 amount,uint64 scheduleId,bytes32 purposeHash,uint256 nonce)`.
/// @dev For PAYMENT, `scheduleId` is a 1-based obligation reference (0 means none). For SCHEDULE_CREATE,
///      `purposeHash` commits to the schedule terms. For SWEEP and FEE_TOPUP, `payeeId` and `scheduleId` are 0.
struct Intent {
    uint8 task;
    uint32 payeeId;
    uint256 amount;
    uint64 scheduleId;
    bytes32 purposeHash;
    uint256 nonce;
}

/// @notice EIP-712 `Attestation(bytes32 intentHash,uint8 band,uint8 source,uint16 flags,uint64 validUntil)`,
///         signed by the guardian key.
struct Attestation {
    bytes32 intentHash;
    uint8 band; // 0 low, 1 medium, 2 high
    uint8 source; // 0 owner instruction, 1 external content
    uint16 flags; // see `Flags`
    uint64 validUntil;
}

/// @notice Terms of a recurring payment. Committed to by `Intent.purposeHash`.
struct ScheduleTerms {
    uint64 period;
    uint64 firstDue;
    uint32 maxRuns;
}

/// @notice An immunity capsule as stored in the bulletin.
struct Capsule {
    uint8 family; // 1 direct, 2 indirect, 3 memory, 4 encoded, 5 recipient substitution
    uint8 channel; // bit index: 0 owner chat, 1 web page, 2 message, 3 memory, 4 token metadata
    uint16 features; // `Flags` bits the attack showed
    uint8 action; // `CapsuleAction`
    uint8 restriction; // 2 delay (L2), 3 owner approval (L3)
    uint64 expiry;
    uint32 guardVersion;
    address issuer;
    uint8 attestations; // counts the issuer
}

/// @notice Request flag bits carried in `Attestation.flags` and `Capsule.features`.
library Flags {
    uint16 internal constant KNOWN_PAYEE_IDENTITY = 1 << 0;
    uint16 internal constant NEW_DESTINATION = 1 << 1;
    uint16 internal constant URGENCY = 1 << 2;
    uint16 internal constant SECRECY = 1 << 3;
    uint16 internal constant OVERRIDE_ATTEMPT = 1 << 4;
    uint16 internal constant ENCODED_CONTENT = 1 << 5;
    uint16 internal constant AMOUNT_ANOMALY = 1 << 6;
    uint16 internal constant MEMORY_SOURCED = 1 << 7;
    uint16 internal constant ALL = 0xFF;
    uint16 internal constant PRESSURE = URGENCY | SECRECY | OVERRIDE_ATTEMPT;
}

/// @notice Permission tiers and the identifiers of the check that decided a tier.
library Tiers {
    uint8 internal constant L1 = 1;
    uint8 internal constant L2 = 2;
    uint8 internal constant L3 = 3;

    uint8 internal constant CHECK_ALLOWED = 1;
    uint8 internal constant CHECK_AFFORDABLE = 2;
    uint8 internal constant CHECK_SAFE_NOW = 3;
    uint8 internal constant CHECK_ALLOWANCE = 4;
}

/// @notice Channel bit indices of the capsule `channel` field and the wallet channel profile.
library Channels {
    uint8 internal constant COUNT = 5;
    uint8 internal constant ALL_MASK = 0x1F;
}
