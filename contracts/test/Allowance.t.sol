// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {PolicyWallet} from "../src/PolicyWallet.sol";
import {CapsuleAction, Flags, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {ItemStatus} from "../src/wallet/WalletTypes.sol";

/// @notice The caution allowance. Default charges: external source 2, amount above
///         half of D 2, AMOUNT_ANOMALY 3, first payment to a payee 3, partial capsule match 5. A = 10 points,
///         refilled linearly over 24 hours. Allowance values are in `ALLOWANCE_UNIT` (1e6) per point.
contract AllowanceTest is Base {
    uint256 internal constant POINT = 1e6;
    uint8 internal constant OWNER_SOURCE = 0;
    uint8 internal constant EXTERNAL = 1;

    function setUp() public override {
        super.setUp();
        _fund(10_000 * USD); // D = 10,000 - 600 = 9,400, so no payment below 4,700 is above half of D
    }


    function test_Allowance_CleanRequestCostsZero() public {
        _pay(hostingId, 100 * USD); // the first payment to a payee costs 3
        uint256 before = wallet.allowance();
        assertEq(before, 7 * POINT);

        // Known payee, already paid, owner instruction, band low, not above the previous maximum, small.
        Signed memory clean = _signedPayment(hostingId, 100 * USD);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(clean.att.intentHash, 0, before);
        vm.recordLogs();
        uint256 itemId = _send(clean);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());

        assertEq(itemId, 0);
        assertEq(tier, Tiers.L1);
        assertEq(wallet.allowance(), before, "a clean request costs nothing");
        assertEq(token.balanceOf(hosting), 200 * USD);
    }

    function test_Allowance_ChargesFlags_QueuesWhenSpent() public {
        assertEq(wallet.allowance(), 10 * POINT);

        // First payment to the payee: 3.
        Signed memory first = _signed(_payment(softwareId, 100 * USD), 0, OWNER_SOURCE, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(first.att.intentHash, 3 * POINT, 7 * POINT);
        _send(first);

        // External content 2, and above the previous maximum (AMOUNT_ANOMALY, added by the contract) 3.
        Signed memory anomalous = _signed(_payment(softwareId, 150 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(anomalous.att.intentHash, 5 * POINT, 2 * POINT);
        _send(anomalous);

        // External content only: 2. The allowance is now spent.
        Signed memory external_ = _signed(_payment(softwareId, 50 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(external_.att.intentHash, 2 * POINT, 0);
        _send(external_);
        assertEq(token.balanceOf(software), 300 * USD);

        // Another routine request that costs 2 no longer fits: it waits Δ, decided by the allowance.
        vm.recordLogs();
        uint256 itemId = _submit(_payment(softwareId, 50 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_ALLOWANCE);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(wallet.allowance(), 0, "a queued request is not charged");
        assertEq(token.balanceOf(software), 300 * USD);
    }

    function test_Allowance_Refills_CappedAtA() public {
        _spendAllowance();
        uint256 spentAt = block.timestamp;
        assertEq(wallet.allowance(), 0);

        vm.warp(spentAt + 12 hours);
        assertEq(wallet.allowance(), 5 * POINT, "half of A after half of the refill period");
        vm.warp(spentAt + 18 hours);
        assertEq(wallet.allowance(), 75 * POINT / 10);
        vm.warp(spentAt + 24 hours);
        assertEq(wallet.allowance(), 10 * POINT);
        vm.warp(spentAt + 30 days);
        assertEq(wallet.allowance(), 10 * POINT, "never above A");

        // Refill resumes from the value after a charge, and is capped again.
        _submit(_payment(softwareId, 50 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        assertEq(wallet.allowance(), 8 * POINT);
        vm.warp(block.timestamp + 6 hours);
        assertEq(wallet.allowance(), 10 * POINT);
    }

    function test_Allowance_HalvedOnApplicableCapsule() public {
        assertEq(wallet.allowance(), 10 * POINT);
        (PolicyWallet other, address otherOwner) = _otherWallet();
        // A capsule on the message channel, which this wallet listens to, for a different action.
        vm.prank(otherOwner);
        other.publishCapsule(5, 2, Flags.ENCODED_CONTENT, uint8(CapsuleAction.SWEEP), Tiers.L2, 1 days, 1);

        // The next submission syncs the capsule and halves the allowance before charging the request.
        Signed memory s = _signedPayment(hostingId, 100 * USD);
        vm.expectEmit(false, false, false, true, address(wallet));
        emit AllowanceHalved(1, 5 * POINT);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(s.att.intentHash, 3 * POINT, 2 * POINT);
        _send(s);
        assertEq(wallet.allowance(), 2 * POINT);

        // Syncing again does not halve it again for the same capsule.
        wallet.syncCapsules(10);
        assertEq(wallet.allowance(), 2 * POINT);

        // A second applicable capsule halves it once more.
        vm.prank(otherOwner);
        other.publishCapsule(5, 2, Flags.ENCODED_CONTENT, uint8(CapsuleAction.SWEEP), Tiers.L2, 1 days, 1);
        wallet.syncCapsules(10);
        assertEq(wallet.allowance(), 1 * POINT);
    }

    function test_Allowance_ZeroOnConfirmedAttack() public {
        _pay(hostingId, 100 * USD);
        assertEq(wallet.allowance(), 7 * POINT);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.confirmAttack();

        vm.expectEmit(false, false, false, true, address(wallet));
        emit AttackConfirmed();
        vm.prank(owner);
        wallet.confirmAttack();
        assertEq(wallet.allowance(), 0);

        // Any request that costs points now waits.
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 50 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_ALLOWANCE);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    function test_ProbingSequence_ThirdInvoiceWaits() public {
        // An approved payee that has been paid before, then a full refill.
        _pay(hostingId, 100 * USD);
        vm.warp(block.timestamp + 24 hours);
        assertEq(wallet.allowance(), 10 * POINT);

        // Three invoices from external content, each slightly above the previous maximum: 2 + 3 = 5 points each.
        Signed memory first = _signed(_payment(hostingId, 110 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(first.att.intentHash, 5 * POINT, 5 * POINT);
        vm.recordLogs();
        assertEq(_send(first), 0);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);

        Signed memory second = _signed(_payment(hostingId, 120 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(second.att.intentHash, 5 * POINT, 0);
        vm.recordLogs();
        assertEq(_send(second), 0);
        (tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
        assertEq(token.balanceOf(hosting), 330 * USD);

        Signed memory third = _signed(_payment(hostingId, 130 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        vm.recordLogs();
        uint256 itemId = _send(third);
        uint8 check;
        (tier, check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "the third invoice waits");
        assertEq(check, Tiers.CHECK_ALLOWANCE);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(wallet.itemReadyAt(itemId), block.timestamp + 1 hours);
        assertTrue(wallet.getItem(itemId).req.flags & Flags.AMOUNT_ANOMALY != 0, "the contract added the anomaly flag");
        assertEq(token.balanceOf(hosting), 330 * USD, "nothing of the third invoice left the wallet");
    }

    // ------------------------------------------------------------------ further charges

    function test_Allowance_ChargesAboveHalfOfD() public {
        // A bill due within H brings D down to 400, so 201 is above half of D.
        _addObligation(landlordId, 9000 * USD, uint64(block.timestamp + 5 days));
        assertEq(wallet.discretionary(0), 400 * USD);

        Signed memory s = _signedPayment(hostingId, 201 * USD);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(s.att.intentHash, 5 * POINT, 5 * POINT); // first payment 3, above half of D 2
        _send(s);
    }

    function test_Allowance_QueuedRequestExecutesAfterDelta() public {
        _spendAllowance();
        uint256 itemId = _submit(_payment(softwareId, 50 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        vm.warp(block.timestamp + 1 hours);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(software), 350 * USD);
        assertEq(wallet.allowance(), 10 * POINT / 24, "executing a queued item is not charged");
    }

    // ------------------------------------------------------------------ helpers

    /// @dev Spends the full allowance on payments to the software vendor: 3, then 5, then 2 points.
    function _spendAllowance() internal {
        _submit(_payment(softwareId, 100 * USD), 0, OWNER_SOURCE, Flags.KNOWN_PAYEE_IDENTITY);
        _submit(_payment(softwareId, 150 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        _submit(_payment(softwareId, 50 * USD), 0, EXTERNAL, Flags.KNOWN_PAYEE_IDENTITY);
        assertEq(wallet.allowance(), 0);
    }

    function _otherWallet() internal returns (PolicyWallet other, address otherOwner) {
        otherOwner = makeAddr("otherOwner");
        other = _newWallet(otherOwner, makeAddr("otherAgent"));
    }
}
