// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Errors of the PolicyWallet
/// @notice Shared by the wallet and its linked libraries so that both revert with the same errors.
interface IPolicyWalletErrors {
    error NotOwner();
    error NotAgent();
    error NotOwnerOrAgent();
    error ZeroAddress();
    error VaultAssetMismatch();
    error MandateNotSet();
    error InvalidMandate();
    error LooseningNeedsTimelock();
    error InvalidChangeKind();
    error UnknownChange(uint256 changeId);
    error ChangeNotPending(uint256 changeId);
    error ChangeNotReady(uint256 changeId, uint64 readyAt);
    error UnknownPayee(uint32 payeeId);
    error PayeeNotActive(uint32 payeeId);
    error PayeeAlreadyActive(uint32 payeeId);
    error InvalidObligation();
    error ObligationsFull();
    error ObligationNotOpen(uint64 obligationId);
    error ObligationMismatch(uint64 obligationId);
    error ObligationBelongsToSchedule(uint64 obligationId, uint64 scheduleId);
    error SchedulesFull();
    error InvalidScheduleTerms();
    error ScheduleTermsMismatch();
    error ScheduleTermsRequired();
    error UnknownSchedule(uint64 scheduleId);
    error ScheduleNotActive(uint64 scheduleId);
    error ScheduleNotDue(uint64 scheduleId, uint64 nextDue);
    error WalletIsFrozen();
    error WalletNotFrozen();
    error MandateExpired();
    error InvalidIntent();
    error InvalidNonce(uint256 expected, uint256 provided);
    error IntentAlreadyUsed(bytes32 intentHash);
    error AttestationMismatch();
    error AttestationExpired(uint64 validUntil);
    error InvalidAttestation();
    error InvalidGuardianSignature();
    error SweepExceedsDiscretionary(uint256 amount, uint256 discretionary);
    error NothingToTopUp();
    error UnknownItem(uint256 itemId);
    error ItemNotPending(uint256 itemId);
    error ItemNotProposed(uint256 itemId);
    error ItemNotExecutable(uint256 itemId);
    error ItemNotReady(uint256 itemId, uint64 readyAt);
    error NoLongerAuthorised(uint256 itemId, uint8 tierNow);
    error InvalidHoldExtension();
    error ProposalStale(uint256 changeId);
    error KeysNotDistinct();
    error AgentObligationsFull();
    error NoLongerAffordable(uint256 itemId);
    error AttestationValidityTooLong(uint64 validUntil);
    error CapsuleBacklog(uint256 remaining);
    error CapsuleOverflow();
    error ObligationNotDue(uint64 obligationId);
}
