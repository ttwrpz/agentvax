// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {Base} from "./Base.t.sol";
import {Attestation, Flags, Intent, Mandate, ScheduleTerms, Task, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {IntentLogic} from "../src/lib/IntentLogic.sol";
import {ItemStatus} from "../src/wallet/WalletTypes.sol";

contract TiersGuardianTest is Base {
    function setUp() public override {
        super.setUp();
        _fund(10_000 * USD);
    }

    // ------------------------------------------------------------------ guardian

    function test_L1_ExecutesWithSessionKeyAndGuardianSig() public {
        Intent memory i = _payment(hostingId, 200 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);

        vm.recordLogs();
        vm.prank(agent);
        uint256 itemId = wallet.submit(i, a, sig);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());

        assertEq(itemId, 0, "executed in the same transaction, nothing queued");
        assertEq(tier, Tiers.L1);
        assertEq(token.balanceOf(hosting), 200 * USD);
        assertEq(wallet.nonce(), 1);
        assertTrue(wallet.intentUsed(a.intentHash));
    }

    function test_L1_RevertsWithoutGuardianSig() public {
        Intent memory i = _payment(hostingId, 200 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.InvalidGuardianSignature.selector);
        wallet.submit(i, a, "");
        assertEq(token.balanceOf(hosting), 0);
        assertEq(wallet.nonce(), 0);
    }

    function test_L1_RevertsWithForgedGuardianSig() public {
        Intent memory i = _payment(hostingId, 200 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        (, uint256 forgerKey) = makeAddrAndKey("forger");
        bytes memory forged = _sign(a, forgerKey);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.InvalidGuardianSignature.selector);
        wallet.submit(i, a, forged);

        // A genuine signature over a different attestation (band high) cannot be reused for band low.
        Attestation memory high = _attestation(i, 2, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sigForHigh = _sign(high, guardianKey);
        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.InvalidGuardianSignature.selector);
        wallet.submit(i, a, sigForHigh);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_L1_RevertsWithExpiredAttestation() public {
        Intent memory i = _payment(hostingId, 200 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);

        vm.warp(a.validUntil + 1);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.AttestationExpired.selector, a.validUntil));
        wallet.submit(i, a, sig);
        assertEq(token.balanceOf(hosting), 0);
    }

    // ------------------------------------------------------------------ tiers

    function test_AmountAboveC1_QueuesL2() public {
        vm.recordLogs();
        uint256 itemId = _pay(hostingId, 501 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());

        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_ALLOWED);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_L2_ExecutesAfterDelay() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        uint64 ready = wallet.itemReadyAt(itemId);
        assertEq(ready, block.timestamp + 1 hours);

        vm.warp(ready - 1);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, ready));
        wallet.executePending(itemId);

        vm.warp(ready);
        vm.prank(makeAddr("anyone"));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 800 * USD);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.EXECUTED));

        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotExecutable.selector, itemId));
        wallet.executePending(itemId);
    }

    function test_L2_OwnerCanCancel() public {
        uint256 itemId = _pay(hostingId, 800 * USD);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.cancel(itemId);

        vm.prank(owner);
        wallet.cancel(itemId);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.CANCELLED));

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotExecutable.selector, itemId));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_AmountAboveC2_RequiresOwner() public {
        vm.recordLogs();
        uint256 itemId = _pay(hostingId, 2001 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3);
        assertEq(check, Tiers.CHECK_ALLOWED);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));

        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotExecutable.selector, itemId));
        wallet.executePending(itemId);

        vm.prank(owner);
        wallet.approve(itemId);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 2001 * USD);
    }

    function test_DailyCap_Enforced() public {
        _pay(hostingId, 500 * USD);
        _pay(softwareId, 500 * USD);
        assertEq(wallet.spentOnDay(block.timestamp / 1 days), 1000 * USD);

        vm.recordLogs();
        uint256 itemId = _pay(hostingId, 1 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "d1 is used up, so even a small payment waits");
        assertEq(check, Tiers.CHECK_ALLOWED);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(token.balanceOf(hosting), 500 * USD);

        vm.warp((block.timestamp / 1 days + 1) * 1 days);
        _pay(hostingId, 1 * USD);
        assertEq(token.balanceOf(hosting), 501 * USD, "a new day restores d1");
    }

    function test_BandMedium_QueuesL2() public {
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 1, 0, Flags.KNOWN_PAYEE_IDENTITY);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_BandHigh_RequiresOwner() public {
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 2, 0, Flags.KNOWN_PAYEE_IDENTITY);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_Decision_EmitsDecidingCheck() public {
        Intent memory i = _payment(hostingId, 600 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);

        vm.expectEmit(true, false, false, true, address(wallet));
        emit Decision(a.intentHash, Tiers.L2, Tiers.CHECK_ALLOWED, 0);
        vm.prank(agent);
        wallet.submit(i, a, sig);
    }

    function test_Freeze_BlocksAllValueMovement() public {
        uint256 queued = _pay(hostingId, 800 * USD);
        uint256 proposed = _pay(hostingId, 2500 * USD);
        vm.prank(owner);
        wallet.approve(proposed);
        uint64 scheduleFirstDue = uint64(block.timestamp + 1 hours);
        _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, scheduleFirstDue, 3));
        uint256 balanceBefore = token.balanceOf(address(wallet));

        vm.prank(owner);
        wallet.freeze();
        assertTrue(wallet.frozen());
        vm.warp(block.timestamp + 2 hours);

        Signed memory payment = _signedPayment(hostingId, 10 * USD);
        vm.expectRevert(IPolicyWalletErrors.WalletIsFrozen.selector);
        _send(payment);
        vm.expectRevert(IPolicyWalletErrors.WalletIsFrozen.selector);
        wallet.executePending(queued);
        vm.expectRevert(IPolicyWalletErrors.WalletIsFrozen.selector);
        wallet.executePending(proposed);
        Signed memory sweep = _signed(_intent(Task.SWEEP, 0, 10 * USD), 0, 0, 0);
        vm.expectRevert(IPolicyWalletErrors.WalletIsFrozen.selector);
        _send(sweep);
        Signed memory topUp = _signed(_intent(Task.FEE_TOPUP, 0, 0.01 ether), 0, 0, 0);
        vm.expectRevert(IPolicyWalletErrors.WalletIsFrozen.selector);
        _send(topUp);

        assertFalse(wallet.runSchedule(1), "the schedule is held, not run");
        assertEq(token.balanceOf(address(wallet)), balanceBefore);
        assertEq(address(wallet).balance, 1 ether);
    }

    function test_Decision_EmitsDecidingCheck_Allowance() public {
        vm.prank(owner);
        wallet.confirmAttack();
        // L1 on every check, but the first payment to a payee costs 3 points and none are left.
        Signed memory s = _signedPayment(hostingId, 100 * USD);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit Decision(s.att.intentHash, Tiers.L2, Tiers.CHECK_ALLOWANCE, 0);
        _send(s);
    }

    function test_ExecutePending_EmitsDecision() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        bytes32 intentHash = wallet.getItem(itemId).intentHash;
        vm.warp(block.timestamp + 1 hours);
        // The item is decided again when it executes, and that decision is logged like any other.
        vm.expectEmit(true, false, false, true, address(wallet));
        emit Decision(intentHash, Tiers.L2, Tiers.CHECK_ALLOWED, 0);
        wallet.executePending(itemId);
    }

    function test_Attestation_ValidityAboveTTL_Rejected() public {
        Intent memory i = _payment(hostingId, 100 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        a.validUntil = uint64(block.timestamp + IntentLogic.MAX_ATTESTATION_TTL + 1);
        bytes memory sig = _sign(a, guardianKey);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.AttestationValidityTooLong.selector, a.validUntil));
        wallet.submit(i, a, sig);

        a.validUntil = uint64(block.timestamp + IntentLogic.MAX_ATTESTATION_TTL);
        sig = _sign(a, guardianKey);
        vm.prank(agent);
        wallet.submit(i, a, sig);
        assertEq(token.balanceOf(hosting), 100 * USD, "exactly the longest validity is accepted");
    }

    // ------------------------------------------------------------------ replay and binding

    function test_Nonce_ReplayRejected() public {
        Intent memory i = _payment(hostingId, 100 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);
        vm.prank(agent);
        wallet.submit(i, a, sig);

        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.InvalidNonce.selector, 1, 0));
        wallet.submit(i, a, sig);
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    function test_Attestation_ForOtherIntent_Rejected() public {
        Intent memory small = _payment(hostingId, 10 * USD);
        Intent memory large = _payment(hostingId, 450 * USD);
        Attestation memory a = _attestation(small, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.AttestationMismatch.selector);
        wallet.submit(large, a, sig);
    }

    function test_Submit_OnlyAgent() public {
        Intent memory i = _payment(hostingId, 100 * USD);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.NotAgent.selector);
        wallet.submit(i, a, sig);
    }

    function test_PressureFlag_RaisesToAtLeastL2() public {
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 50 * USD), 0, 0, Flags.KNOWN_PAYEE_IDENTITY | Flags.URGENCY);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertTrue(wallet.getItem(itemId).hold);
    }

    // ------------------------------------------------------------------ stale pending items

    function test_StaleL2_AfterOwnerLowersC2_CannotExecute() public {
        uint256 itemId = _pay(hostingId, 1500 * USD);
        Mandate memory m = wallet.mandate();
        m.c1 = 400 * USD;
        m.c2 = 1000 * USD;
        _setMandateAs(owner, m);

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.NoLongerAuthorised.selector, itemId, Tiers.L3));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_StaleL2_AfterPayeeRemoved_CannotExecute() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        vm.prank(owner);
        wallet.removePayee(hostingId);

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.PayeeNotActive.selector, hostingId));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_StaleL2_AfterMandateExpires_CannotExecute() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        Mandate memory m = wallet.mandate();
        m.expiry = uint64(block.timestamp + 30 minutes);
        _setMandateAs(owner, m);

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(IPolicyWalletErrors.MandateExpired.selector);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_LengtheningDelta_DelaysQueuedItem() public {
        uint64 queuedAt = uint64(block.timestamp);
        uint256 itemId = _pay(hostingId, 800 * USD);
        Mandate memory m = wallet.mandate();
        m.delay = 3 hours;
        _setMandateAs(owner, m);
        assertEq(wallet.itemReadyAt(itemId), queuedAt + 3 hours);

        vm.warp(queuedAt + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, queuedAt + 3 hours));
        wallet.executePending(itemId);

        vm.warp(queuedAt + 3 hours);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 800 * USD);
    }

    function test_ShorteningDelta_NeverAdvancesQueuedItem() public {
        Mandate memory m = wallet.mandate();
        m.delay = 30 minutes;
        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, m);

        uint64 queuedAt = uint64(block.timestamp);
        uint256 itemId = _pay(hostingId, 800 * USD);

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertEq(wallet.mandate().delay, 30 minutes);
        assertEq(wallet.itemReadyAt(itemId), queuedAt + 1 hours, "the delay in force when queued still applies");
    }

    function test_ExtendHold_DelaysL2() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        uint64 ready = wallet.itemReadyAt(itemId);
        vm.prank(owner);
        wallet.extendHold(itemId, 2 hours);
        assertEq(wallet.itemReadyAt(itemId), ready + 2 hours);

        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.InvalidHoldExtension.selector);
        wallet.extendHold(itemId, 0);
    }

    function test_ApprovedL3_WithPressure_WaitsPi() public {
        uint256 itemId = _submit(_payment(hostingId, 2500 * USD), 0, 0, Flags.KNOWN_PAYEE_IDENTITY | Flags.SECRECY);
        vm.prank(owner);
        wallet.approve(itemId);
        uint64 ready = wallet.itemReadyAt(itemId);
        assertEq(ready, block.timestamp + 60 minutes);

        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, ready));
        wallet.executePending(itemId);
        vm.warp(ready);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 2500 * USD);
    }

    function test_ScheduleCreate_WithoutTermsRejected() public {
        Signed memory s = _signed(_intent(Task.SCHEDULE_CREATE, landlordId, 400 * USD), 0, 0, 0);
        vm.expectRevert(IPolicyWalletErrors.ScheduleTermsRequired.selector);
        _send(s);
    }

    function test_Decision_LogsAreOnePerSubmission() public {
        vm.recordLogs();
        _pay(hostingId, 100 * USD);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 count;
        for (uint256 k = 0; k < logs.length; ++k) {
            if (logs[k].topics[0] == Decision.selector) ++count;
        }
        assertEq(count, 1);
    }
}
