// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Attestation, Intent, ScheduleTerms, Task, Tiers} from "./lib/AgentVaxTypes.sol";
import {CapsuleLogic} from "./lib/CapsuleLogic.sol";
import {DecisionLogic} from "./lib/DecisionLogic.sol";
import {IntentLogic} from "./lib/IntentLogic.sol";
import {ItemLogic} from "./lib/ItemLogic.sol";
import {LedgerLogic} from "./lib/LedgerLogic.sol";
import {ISavingsVault} from "./interfaces/ISavingsVault.sol";
import {IThreatBulletin} from "./interfaces/IThreatBulletin.sol";
import {WalletStorage} from "./wallet/WalletStorage.sol";
import {MandateControl} from "./wallet/MandateControl.sol";
import {BlockReason, Item, Payee, Request, Verdict} from "./wallet/WalletTypes.sol";

/// @title PolicyWallet
/// @notice The AgentVax smart-contract wallet. The agent proposes typed intents, a guardian attests them,
///         and this contract decides the tier and enforces it.
/// @dev Every path that moves value or creates a schedule (L1 in `submit`, a pending item in
///      `executePending`, `runSchedule`) calls `_decide` and then `_move` in the same transaction. The decision
///      re-checks freeze, expiry, the payee, the obligation reference, current limits, affordability and
///      current capsules.
///      There is no function that makes an arbitrary call. Tokens go only to an active payee or the fixed vault,
///      native token only to the current agent within the fee budget.
contract PolicyWallet is MandateControl, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice EIP-712 domain name.
    string public constant EIP712_NAME = "AgentVax PolicyWallet";
    /// @notice EIP-712 type hash of `Intent`.
    bytes32 public constant INTENT_TYPEHASH = IntentLogic.INTENT_TYPEHASH;
    /// @notice EIP-712 type hash of `Attestation`.
    bytes32 public constant ATTESTATION_TYPEHASH = IntentLogic.ATTESTATION_TYPEHASH;

    /// @param owner_ Owner key.
    /// @param agent_ Agent session key.
    /// @param guardian_ Guardian signer.
    /// @param token_ The token the wallet pays in.
    /// @param vault_ The only sweep destination. Its asset must be `token_`.
    /// @param bulletin_ The capsule registry.
    constructor(
        address owner_,
        address agent_,
        address guardian_,
        IERC20 token_,
        ISavingsVault vault_,
        IThreatBulletin bulletin_
    ) WalletStorage(owner_, agent_, guardian_, token_, vault_, bulletin_) EIP712(EIP712_NAME, VERSION) {}

    /// @notice Funds the native fee reserve.
    receive() external payable {
        emit FeeReserveFunded(msg.sender, msg.value);
    }

    // ------------------------------------------------------------------ agent entry points

    /// @notice Submits a PAYMENT, SWEEP or FEE_TOPUP intent with its guardian attestation. Agent only.
    /// @dev Executes at L1, queues at L2 or proposes at L3. A valid, unexpired guardian signature is required
    ///      at every tier.
    /// @param intent The typed intent. `intent.nonce` must equal `nonce`.
    /// @param attestation Guardian attestation whose `intentHash` is `hashIntent(intent)`.
    /// @param guardianSig Guardian EIP-712 signature over `attestation`.
    /// @return itemId Id of the queued or proposed item, 0 if executed at L1.
    function submit(Intent calldata intent, Attestation calldata attestation, bytes calldata guardianSig)
        external
        nonReentrant
        onlyAgent
        whenMandateSet
        returns (uint256 itemId)
    {
        if (intent.task == uint8(Task.SCHEDULE_CREATE)) revert ScheduleTermsRequired();
        ScheduleTerms memory noTerms;
        return _submit(intent, noTerms, attestation, guardianSig);
    }

    /// @notice Submits a SCHEDULE_CREATE intent. `intent.purposeHash` must equal `hashScheduleTerms(terms)`.
    /// @param intent The typed intent with task SCHEDULE_CREATE. `amount` is the amount of each run.
    /// @param terms Period, first due time and number of runs, committed to by the intent.
    /// @param attestation Guardian attestation over the intent.
    /// @param guardianSig Guardian EIP-712 signature over `attestation`.
    /// @return itemId Id of the queued or proposed item, 0 if the schedule was created at L1.
    function submitSchedule(
        Intent calldata intent,
        ScheduleTerms calldata terms,
        Attestation calldata attestation,
        bytes calldata guardianSig
    ) external nonReentrant onlyAgent whenMandateSet returns (uint256 itemId) {
        if (intent.task != uint8(Task.SCHEDULE_CREATE)) revert InvalidIntent();
        if (intent.purposeHash != hashScheduleTerms(terms)) revert ScheduleTermsMismatch();
        if (!_validScheduleTerms(terms)) revert InvalidScheduleTerms();
        return _submit(intent, terms, attestation, guardianSig);
    }

    // ------------------------------------------------------------------ pending items

    /// @notice Executes a queued L2 item after Δ, or an approved L3 item after any hold. Anyone may call.
    /// @dev Refuses while capsules remain unsynced, while an applicable capsule is in neither capsule list, or
    ///      while a spilled capsule demands owner approval. The item is re-assessed now. Reverts if it can no
    ///      longer proceed, if a queued item would now get a higher tier than it was queued at, or if an
    ///      approved item is now less affordable than when the owner approved it.
    function executePending(uint256 itemId) external nonReentrant whenMandateSet {
        Request memory r = ItemLogic.executableRequest(_itemBook, itemId);
        _syncCapsules(AUTO_SYNC_CHUNK);
        CapsuleLogic.requireClear(_capsules, bulletin, true);
        Verdict memory v = _decide(r, true);
        (bytes32 ih, uint8 tier, ScheduleTerms memory terms) =
            ItemLogic.markExecuted(_itemBook, _auth.mandate, itemId, v.tier, v.hold, v.afford);
        emit Decision(ih, v.tier, v.check, v.capsuleId);
        _move(itemId, ih, r, v, tier, terms);
    }

    /// @notice Approves an L3 item. Owner only. It becomes executable at once, or after Π if it carries a
    ///         pressure flag or a full capsule match.
    /// @dev The item is assessed now and its affordability recorded. It can later execute only while it is no
    ///      less affordable. Reverts if the item could not proceed now, or while capsules remain unsynced so
    ///      that the assessment sees every capsule.
    function approve(uint256 itemId) external onlyOwner {
        CapsuleLogic.requireClear(_capsules, bulletin, false);
        Verdict memory v = _decide(ItemLogic.proposedRequest(_itemBook, itemId), true);
        ItemLogic.approve(_itemBook, _auth.mandate, itemId, v.afford);
    }

    /// @notice Cancels a queued, proposed or approved item. Owner only, immediate.
    function cancel(uint256 itemId) external onlyOwner {
        ItemLogic.cancel(_itemBook, itemId);
    }

    /// @notice Lengthens the wait of a pending item by `extraSeconds`. Owner only. A wait can never be shortened.
    function extendHold(uint256 itemId, uint64 extraSeconds) external onlyOwner {
        ItemLogic.extendHold(_itemBook, itemId, extraSeconds);
    }

    // ------------------------------------------------------------------ schedules

    /// @notice Pays the due occurrence of schedule `scheduleId`. Anyone may call. No attestation is needed.
    /// @dev Pays only at L1, otherwise emits `ScheduleHeld` and the occurrence stays due. A run is not charged
    ///      to the allowance because its terms were decided when the schedule was created.
    /// @return ran True if the occurrence was paid.
    function runSchedule(uint64 scheduleId) external nonReentrant whenMandateSet returns (bool ran) {
        Request memory r = LedgerLogic.dueRun(_ledger, scheduleId);
        _syncCapsules(AUTO_SYNC_CHUNK);
        Verdict memory v = _decide(r, false);
        if (v.reason == BlockReason.NONE) emit Decision(bytes32(0), v.tier, v.check, v.capsuleId);
        if (v.reason != BlockReason.NONE || v.tier != Tiers.L1) {
            emit ScheduleHeld(scheduleId, uint8(v.reason), v.reason == BlockReason.NONE ? v.check : 0);
            return false;
        }
        ScheduleTerms memory noTerms;
        _move(0, bytes32(0), r, v, Tiers.L1, noTerms);
        emit ScheduleRan(scheduleId, r.obligationRef, r.amount);
        return true;
    }

    // ------------------------------------------------------------------ views

    /// @notice EIP-712 digest of `intent` under this wallet's domain. This is the intent hash.
    function hashIntent(Intent calldata intent) external view returns (bytes32) {
        return IntentLogic.hashIntent(_domainSeparatorV4(), intent);
    }

    /// @notice EIP-712 digest of `attestation` that the guardian signs.
    function hashAttestation(Attestation calldata attestation) external view returns (bytes32) {
        return IntentLogic.hashAttestation(_domainSeparatorV4(), attestation);
    }

    /// @notice Item `itemId`.
    function getItem(uint256 itemId) external view returns (Item memory) {
        return _itemBook.items[itemId];
    }

    /// @notice Number of items ever queued or proposed. Item ids run from 1 to this value.
    function itemCount() external view returns (uint256) {
        return _itemBook.count;
    }

    /// @notice Earliest execution time of item `itemId` under the current mandate. A capsule that matches
    ///         later can still add the pressure hold to an approved L3 item.
    function itemReadyAt(uint256 itemId) external view returns (uint64) {
        return ItemLogic.readyAt(_itemBook, _auth.mandate, itemId);
    }

    // ------------------------------------------------------------------ decision

    function _submit(
        Intent calldata intent,
        ScheduleTerms memory terms,
        Attestation calldata att,
        bytes calldata sig
    ) private returns (uint256) {
        bytes32 ih = IntentLogic.verify(_domainSeparatorV4(), _auth.guardian, intent, att, sig);
        if (intent.nonce != nonce) revert InvalidNonce(nonce, intent.nonce);
        if (intentUsed[ih]) revert IntentAlreadyUsed(ih);
        nonce += 1;
        intentUsed[ih] = true;
        _syncCapsules(AUTO_SYNC_CHUNK);

        Request memory r = Request({
            task: intent.task,
            band: att.band,
            source: att.source,
            flags: att.flags,
            payeeId: intent.payeeId,
            obligationRef: intent.scheduleId,
            amount: intent.amount
        });
        return _act(ih, r, terms);
    }

    /// @dev Decides a verified request, applies the allowance step, then executes at L1 or stores the item.
    function _act(bytes32 ih, Request memory r, ScheduleTerms memory terms) private returns (uint256) {
        Verdict memory v = _decide(r, true);
        uint8 tier = v.tier;
        uint8 check = v.check;
        if (tier == Tiers.L1) {
            if (_trySpendAllowance(v.charge)) {
                emit AllowanceCharged(ih, v.charge * ALLOWANCE_UNIT, allowance());
            } else {
                tier = Tiers.L2;
                check = Tiers.CHECK_ALLOWANCE;
            }
        }
        emit Decision(ih, tier, check, v.capsuleId);
        if (tier == Tiers.L1) {
            _move(0, ih, r, v, Tiers.L1, terms);
            return 0;
        }
        r.flags = v.flags;
        return ItemLogic.store(_itemBook, _auth.mandate, ih, r, v.hold, tier, terms);
    }

    /// @dev The three questions under the current state. `strict` reverts if the request cannot proceed.
    function _decide(Request memory r, bool strict) private view returns (Verdict memory) {
        uint256 day = _today();
        return DecisionLogic.evaluate(
            _auth,
            _ledger,
            _capsules,
            DecisionLogic.Context({
                token: token,
                bulletin: bulletin,
                spentToday: spentOnDay[day],
                toppedUpToday: toppedUpOnDay[day]
            }),
            r,
            strict
        );
    }

    // ------------------------------------------------------------------ value gate

    /// @dev The only function that moves value or creates a schedule. Callers obtain `v` from `_decide` in the
    ///      same transaction. Freeze and expiry are checked again here.
    function _move(
        uint256 itemId,
        bytes32 ih,
        Request memory r,
        Verdict memory v,
        uint8 tier,
        ScheduleTerms memory terms
    ) private {
        if (_auth.frozen) revert WalletIsFrozen();
        if (block.timestamp >= _auth.mandate.expiry) revert MandateExpired();
        if (r.task == uint8(Task.PAYMENT)) {
            if (r.obligationRef != 0) LedgerLogic.settleObligation(_ledger, r.obligationRef);
            Payee storage p = _auth.payees[r.payeeId - 1];
            if (r.amount > p.maxPaid) p.maxPaid = r.amount;
            p.paidCount += 1;
            if (tier == Tiers.L1) spentOnDay[_today()] += r.amount;
            emit Executed(itemId, ih, r.task, p.account, r.amount);
            token.safeTransfer(p.account, r.amount);
        } else if (r.task == uint8(Task.SCHEDULE_CREATE)) {
            LedgerLogic.createSchedule(_ledger, r.payeeId, r.amount, terms);
            emit Executed(itemId, ih, r.task, _auth.payees[r.payeeId - 1].account, r.amount);
        } else if (r.task == uint8(Task.SWEEP)) {
            emit Executed(itemId, ih, r.task, address(vault), r.amount);
            token.forceApprove(address(vault), r.amount);
            vault.deposit(r.amount);
        } else {
            uint256 sent = v.topUp;
            toppedUpOnDay[_today()] += sent;
            address to = _auth.agent;
            emit Executed(itemId, ih, r.task, to, sent);
            Address.sendValue(payable(to), sent);
        }
    }
}
