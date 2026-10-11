// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {Base} from "./Base.t.sol";
import {PolicyWallet} from "../src/PolicyWallet.sol";
import {SavingsVault} from "../src/SavingsVault.sol";
import {Attestation, Flags, Intent, ScheduleTerms, Task, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {Obligation, Payee, Schedule} from "../src/wallet/WalletTypes.sol";

contract TasksTest is Base {

    function test_T1_Payment() public {
        _fund(2000 * USD);
        Signed memory s = _signedPayment(hostingId, 150 * USD);

        vm.expectEmit(true, true, false, true, address(wallet));
        emit Executed(0, s.att.intentHash, uint8(Task.PAYMENT), hosting, 150 * USD);
        uint256 itemId = _send(s);

        assertEq(itemId, 0);
        assertEq(token.balanceOf(hosting), 150 * USD);
        assertEq(token.balanceOf(address(wallet)), 1850 * USD);
        Payee memory p = wallet.getPayee(hostingId);
        assertEq(p.paidCount, 1);
        assertEq(p.maxPaid, 150 * USD);
        assertEq(wallet.spentOnDay(block.timestamp / 1 days), 150 * USD);
    }

    function test_T2_Schedule_RegistersObligation() public {
        _fund(3000 * USD);
        uint256 dBefore = wallet.discretionary(0);
        uint64 firstDue = uint64(block.timestamp + 5 days);

        uint256 itemId = _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, firstDue, 12));
        assertEq(itemId, 0, "created at L1");

        Schedule memory sch = wallet.getSchedule(1);
        assertTrue(sch.active);
        assertEq(sch.payeeId, landlordId);
        assertEq(sch.amount, 400 * USD);
        assertEq(sch.nextDue, firstDue);
        assertEq(sch.terms.period, 30 days);
        assertEq(sch.terms.maxRuns, 12);

        Obligation memory o = wallet.getObligation(sch.obligationId);
        assertTrue(o.open);
        assertEq(o.payeeId, landlordId);
        assertEq(o.amount, 400 * USD);
        assertEq(o.due, firstDue);
        assertEq(o.scheduleId, 1);
        assertEq(wallet.discretionary(0), dBefore - 400 * USD, "the next run is reserved");
        assertEq(token.balanceOf(landlord), 0, "creating a schedule moves no value");
    }

    function test_T2_RunSchedule_NeedsNoAttestation() public {
        _fund(3000 * USD);
        uint64 firstDue = uint64(block.timestamp + 1 days);
        _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, firstDue, 12));
        uint64 firstObligation = wallet.getSchedule(1).obligationId;

        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ScheduleNotDue.selector, 1, firstDue));
        wallet.runSchedule(1);

        vm.warp(firstDue);
        uint256 nonceBefore = wallet.nonce();
        vm.prank(makeAddr("keeper"));
        assertTrue(wallet.runSchedule(1));

        assertEq(token.balanceOf(landlord), 400 * USD);
        assertEq(wallet.nonce(), nonceBefore, "no intent, no attestation");
        Schedule memory sch = wallet.getSchedule(1);
        assertEq(sch.runsDone, 1);
        assertEq(sch.nextDue, firstDue + 30 days);
        assertFalse(wallet.getObligation(firstObligation).open);
        assertTrue(sch.obligationId != firstObligation, "every occurrence has a fresh obligation");
        assertEq(wallet.getObligation(sch.obligationId).due, firstDue + 30 days);

        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ScheduleNotDue.selector, 1, firstDue + 30 days));
        wallet.runSchedule(1);
        assertEq(token.balanceOf(landlord), 400 * USD, "an occurrence runs once");
    }

    function test_T3_Sweep_OnlyDiscretionary_ToVaultOnly() public {
        _workedExampleState();
        assertEq(wallet.discretionary(0), 180 * USD);

        Signed memory tooMuch = _signed(_intent(Task.SWEEP, 0, 181 * USD), 0, 0, 0);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyWalletErrors.SweepExceedsDiscretionary.selector, 181 * USD, 180 * USD)
        );
        _send(tooMuch);

        Signed memory withPayee = _signed(_intent(Task.SWEEP, hostingId, 100 * USD), 0, 0, 0);
        vm.expectRevert(IPolicyWalletErrors.InvalidIntent.selector);
        _send(withPayee);

        _submit(_intent(Task.SWEEP, 0, 180 * USD), 0, 0, 0);
        assertEq(vault.balanceOf(address(wallet)), 180 * USD);
        assertEq(token.balanceOf(address(vault)), 180 * USD);
        assertEq(token.balanceOf(address(wallet)), 1670 * USD);
        assertEq(wallet.discretionary(0), 0);
        assertEq(token.allowance(address(wallet), address(vault)), 0, "no approval is left behind");
    }

    function test_T4_FeeTopUp_Capped() public {
        assertEq(agent.balance, 0);
        Intent memory i = _intent(Task.FEE_TOPUP, 0, 1 ether);

        vm.recordLogs();
        _submit(i, 0, 0, 0);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());

        assertEq(tier, Tiers.L1);
        assertEq(agent.balance, 0.01 ether, "capped at feeTopUpCap whatever was asked");
        assertEq(address(wallet).balance, 0.99 ether);
        assertEq(wallet.toppedUpOnDay(block.timestamp / 1 days), 0.01 ether);
    }

    // ------------------------------------------------------------------ fee budget

    function test_T4_RepeatedTopUps_BoundedByDailyBudget() public {
        for (uint256 k = 0; k < 3; ++k) {
            _submit(_intent(Task.FEE_TOPUP, 0, 1 ether), 0, 0, 0);
            assertEq(agent.balance, 0.01 ether);
            vm.deal(agent, 0); // the agent spends or moves its native token away
        }
        Signed memory fourth = _signed(_intent(Task.FEE_TOPUP, 0, 1 ether), 0, 0, 0);
        vm.expectRevert(IPolicyWalletErrors.NothingToTopUp.selector);
        _send(fourth);
        assertEq(address(wallet).balance, 0.97 ether, "at most the daily budget left the wallet");
    }

    function test_T4_TopUp_OnlyTheDeficit() public {
        vm.deal(agent, 0.015 ether);
        _submit(_intent(Task.FEE_TOPUP, 0, 1 ether), 0, 0, 0);
        assertEq(agent.balance, 0.02 ether, "brought up to the floor, no further");

        Signed memory again = _signed(_intent(Task.FEE_TOPUP, 0, 1 ether), 0, 0, 0);
        vm.expectRevert(IPolicyWalletErrors.NothingToTopUp.selector);
        _send(again);
    }

    function test_T4_TopUp_KeepsNativeReserve() public {
        vm.deal(address(wallet), 0.105 ether);
        _submit(_intent(Task.FEE_TOPUP, 0, 1 ether), 0, 0, 0);
        assertEq(address(wallet).balance, 0.1 ether);
        assertEq(agent.balance, 0.005 ether);
    }

    // ------------------------------------------------------------------ schedule terms

    function test_T2_UnsignedTermsRejected() public {
        _fund(3000 * USD);
        ScheduleTerms memory signedTerms = _scheduleTerms(30 days, uint64(block.timestamp + 1 days), 12);
        ScheduleTerms memory otherTerms = _scheduleTerms(1 days, uint64(block.timestamp), 365);
        Intent memory i = _intent(Task.SCHEDULE_CREATE, landlordId, 400 * USD);
        i.purposeHash = wallet.hashScheduleTerms(signedTerms);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.ScheduleTermsMismatch.selector);
        wallet.submitSchedule(i, otherTerms, a, sig);
        (uint64 created,) = wallet.scheduleCounts();
        assertEq(created, 0);
    }

    function test_T2_PeriodBelowMinimumRejected() public {
        _fund(3000 * USD);
        ScheduleTerms memory terms = _scheduleTerms(1 hours, uint64(block.timestamp + 1 days), 12);
        Intent memory i = _intent(Task.SCHEDULE_CREATE, landlordId, 400 * USD);
        i.purposeHash = wallet.hashScheduleTerms(terms);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.InvalidScheduleTerms.selector);
        wallet.submitSchedule(i, terms, a, sig);
    }

    function test_T2_RunSchedule_HeldWhenNotComfortable() public {
        _fund(1500 * USD);
        uint64 firstDue = uint64(block.timestamp + 1 days);
        _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, firstDue, 12));
        // A bill registered by the agent leaves less than the run needs.
        _addObligation(hostingId, 450 * USD, uint64(block.timestamp + 2 days));
        assertEq(wallet.discretionary(wallet.getSchedule(1).obligationId), 450 * USD);
        _addObligation(softwareId, 100 * USD, uint64(block.timestamp + 2 days));

        vm.warp(firstDue);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit ScheduleHeld(1, 0, Tiers.CHECK_AFFORDABLE);
        assertFalse(wallet.runSchedule(1));
        assertEq(token.balanceOf(landlord), 0);
        assertEq(wallet.getSchedule(1).runsDone, 0, "a held occurrence stays due");
    }

    function test_SchedulePayment_BeforeDue_Rejected() public {
        _fund(3000 * USD);
        uint64 firstDue = uint64(block.timestamp + 1 days);
        _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, firstDue, 12));
        uint64 occurrence = wallet.getSchedule(1).obligationId;

        // An ordinary payment that names the schedule's occurrence cannot pay it early and advance the schedule.
        Intent memory early = _payment(landlordId, 400 * USD);
        early.scheduleId = occurrence;
        Signed memory s = _signed(early, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ObligationNotDue.selector, occurrence));
        _send(s);
        assertEq(wallet.getSchedule(1).runsDone, 0);
        assertEq(wallet.getSchedule(1).nextDue, firstDue);

        // From the due time it may be paid this way, and the schedule moves on once.
        vm.warp(firstDue);
        Intent memory due = _payment(landlordId, 400 * USD);
        due.scheduleId = occurrence;
        _submitClean(due);
        assertEq(token.balanceOf(landlord), 400 * USD);
        assertEq(wallet.getSchedule(1).runsDone, 1);
        assertEq(wallet.getSchedule(1).nextDue, firstDue + 30 days);
    }

    function test_OneOffObligation_MayBePaidEarly() public {
        _fund(3000 * USD);
        uint64 bill = _addObligation(hostingId, 150 * USD, uint64(block.timestamp + 10 days));
        Intent memory i = _payment(hostingId, 150 * USD);
        i.scheduleId = bill;
        _submitClean(i);
        assertFalse(wallet.getObligation(bill).open);
    }

    function test_RunSchedule_EmitsDecision() public {
        _fund(3000 * USD);
        uint64 firstDue = uint64(block.timestamp + 1 days);
        _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, firstDue, 12));
        vm.warp(firstDue);
        // A run has no intent, so its decision carries the zero intent hash. ScheduleRan names the schedule.
        vm.expectEmit(true, false, false, true, address(wallet));
        emit Decision(bytes32(0), Tiers.L1, Tiers.CHECK_ALLOWED, 0);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit ScheduleRan(1, wallet.getSchedule(1).obligationId, 400 * USD);
        assertTrue(wallet.runSchedule(1));
    }

    function test_RunSchedule_Held_EmitsDecision() public {
        _fund(1500 * USD);
        uint64 firstDue = uint64(block.timestamp + 1 days);
        _submitSchedule(landlordId, 400 * USD, _scheduleTerms(30 days, firstDue, 12));
        _addObligation(hostingId, 550 * USD, uint64(block.timestamp + 2 days));
        vm.warp(firstDue);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit Decision(bytes32(0), Tiers.L2, Tiers.CHECK_AFFORDABLE, 0);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit ScheduleHeld(1, 0, Tiers.CHECK_AFFORDABLE);
        assertFalse(wallet.runSchedule(1));
    }

    function test_T2_Schedule_CompletesAfterMaxRuns() public {
        _fund(3000 * USD);
        uint64 firstDue = uint64(block.timestamp + 1 days);
        _submitSchedule(landlordId, 100 * USD, _scheduleTerms(1 days, firstDue, 2));
        vm.warp(firstDue);
        wallet.runSchedule(1);
        vm.warp(firstDue + 1 days);
        wallet.runSchedule(1);
        assertFalse(wallet.getSchedule(1).active);
        assertEq(wallet.openObligationIds().length, 0);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ScheduleNotActive.selector, 1));
        wallet.runSchedule(1);
        assertEq(token.balanceOf(landlord), 200 * USD);
    }

    // ------------------------------------------------------------------ vault accounts

    function test_Vault_WithdrawByAnotherWalletsOwner_Reverts() public {
        _workedExampleState();
        _submit(_intent(Task.SWEEP, 0, 180 * USD), 0, 0, 0);

        address ownerB = makeAddr("ownerB");
        PolicyWallet walletB = _newWallet(ownerB, makeAddr("agentB"));
        vm.prank(ownerB);
        vm.expectRevert(SavingsVault.NotWalletOwner.selector);
        vault.withdraw(address(wallet), 180 * USD);

        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(SavingsVault.InsufficientBalance.selector, 0, 180 * USD));
        vault.withdraw(address(walletB), 180 * USD);

        vm.prank(owner);
        vault.withdraw(address(wallet), 180 * USD);
        assertEq(token.balanceOf(owner), 180 * USD);
        assertEq(vault.balanceOf(address(wallet)), 0);
    }

    // ------------------------------------------------------------------ helpers

    /// @dev Balance 1,850, R 600, rent 800 due in 5 days, hosting 150, software 120.
    function _workedExampleState() internal {
        _fund(1850 * USD);
        _addObligation(landlordId, 800 * USD, uint64(block.timestamp + 5 days));
        _addObligation(hostingId, 150 * USD, uint64(block.timestamp + 10 days));
        _addObligation(softwareId, 120 * USD, uint64(block.timestamp + 20 days));
    }
}
