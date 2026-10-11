// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {Flags, Mandate, Task, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {ChangeKind, ChangeStatus, Change, ItemStatus, Payee} from "../src/wallet/WalletTypes.sol";

/// @notice The owner under pressure: anything that loosens authority waits Λ, even for the owner, while
///         tightening, cancelling and freezing are immediate. Pressure flags block L1 and make an owner
///         approval wait Π. Default profile: Λ 24 hours, Π 60 minutes, Δ 1 hour.
contract OwnerPressureTest is Base {
    uint64 internal constant LAMBDA = 24 hours;
    uint64 internal constant PI = 60 minutes;
    uint16 internal constant KNOWN = Flags.KNOWN_PAYEE_IDENTITY;

    function setUp() public override {
        super.setUp();
        _fund(10_000 * USD);
    }

    // ------------------------------------------------------------------ loosening waits Λ

    function test_Loosening_AddPayee_WaitsLambda() public {
        address supplier = makeAddr("supplier");
        uint32 nextId = uint32(wallet.payeeCount() + 1);
        vm.prank(owner);
        uint256 changeId = wallet.proposeAddPayee(keccak256("supplier"), supplier);
        uint64 ready = wallet.changeReadyAt(changeId);
        assertEq(ready, block.timestamp + LAMBDA);

        vm.warp(ready - 1);
        _expectNotReady(changeId, ready);
        Signed memory early = _signedPayment(nextId, 100 * USD);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.UnknownPayee.selector, nextId));
        _send(early);

        vm.warp(ready);
        vm.prank(owner);
        wallet.applyChange(changeId);
        Payee memory p = wallet.getPayee(nextId);
        assertTrue(p.active);
        assertEq(p.account, supplier);
        _pay(nextId, 100 * USD);
        assertEq(token.balanceOf(supplier), 100 * USD);
    }

    function test_Loosening_RaiseLimit_WaitsLambda() public {
        Mandate memory looser = wallet.mandate();
        looser.c1 = 800 * USD;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
        wallet.setMandate(MISSION, looser);

        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, looser);
        vm.warp(block.timestamp + LAMBDA - 1);
        _expectNotReady(changeId, uint64(block.timestamp + 1));
        assertEq(wallet.mandate().c1, 500 * USD);
        vm.recordLogs();
        _pay(hostingId, 700 * USD);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "the old limit still applies during Lambda");

        vm.warp(block.timestamp + 1);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertEq(wallet.mandate().c1, 800 * USD);
        vm.recordLogs();
        _pay(softwareId, 700 * USD);
        (tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
    }

    function test_Loosening_LowerReserve_WaitsLambda() public {
        assertEq(wallet.discretionary(0), 9400 * USD);
        Mandate memory looser = wallet.mandate();
        looser.reserve = 300 * USD;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
        wallet.setMandate(MISSION, looser);

        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, looser);
        uint64 ready = wallet.changeReadyAt(changeId);
        vm.warp(ready - 1);
        _expectNotReady(changeId, ready);
        assertEq(wallet.mandate().reserve, 600 * USD);
        assertEq(wallet.discretionary(0), 9400 * USD);

        vm.warp(ready);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertEq(wallet.mandate().reserve, 300 * USD);
        assertEq(wallet.discretionary(0), 9700 * USD);
    }

    function test_Loosening_ShortenLambda_WaitsLambda() public {
        Mandate memory looser = wallet.mandate();
        looser.looseningDelay = 1 hours;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
        wallet.setMandate(MISSION, looser);

        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, looser);
        // The shorter Λ is not used to time its own change: it still waits the Λ in force.
        uint64 ready = wallet.changeReadyAt(changeId);
        assertEq(ready, block.timestamp + LAMBDA);
        vm.warp(block.timestamp + 1 hours);
        _expectNotReady(changeId, ready);

        vm.warp(ready);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertEq(wallet.mandate().looseningDelay, 1 hours);

        // From now on a new loosening waits the shorter Λ.
        vm.prank(owner);
        uint256 next = wallet.proposeAddPayee(keccak256("supplier"), makeAddr("supplier"));
        assertEq(wallet.changeReadyAt(next), block.timestamp + 1 hours);
    }

    function test_Loosening_Unfreeze_WaitsLambda() public {
        vm.prank(owner);
        wallet.freeze();

        vm.prank(owner);
        uint256 changeId = wallet.proposeUnfreeze();
        uint64 ready = wallet.changeReadyAt(changeId);
        assertEq(ready, block.timestamp + LAMBDA);

        vm.warp(ready - 1);
        _expectNotReady(changeId, ready);
        assertTrue(wallet.frozen());
        Signed memory early = _signedPayment(hostingId, 100 * USD);
        vm.expectRevert(IPolicyWalletErrors.WalletIsFrozen.selector);
        _send(early);

        vm.warp(ready);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertFalse(wallet.frozen());
        _pay(hostingId, 100 * USD);
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    // ------------------------------------------------------------------ tightening and cancelling

    function test_Tightening_IsImmediate() public {
        Mandate memory tighter = wallet.mandate();
        tighter.c1 = 100 * USD;
        tighter.d1 = 500 * USD;
        tighter.reserve = 1000 * USD;
        tighter.delay = 2 hours;
        tighter.looseningDelay = 48 hours;
        tighter.pressureHold = 2 hours;
        tighter.allowanceMax = 5;
        uint256 changesBefore = wallet.changeCount();
        _setMandateAs(owner, tighter);

        Mandate memory m = wallet.mandate();
        assertEq(m.c1, 100 * USD);
        assertEq(m.reserve, 1000 * USD);
        assertEq(m.delay, 2 hours);
        assertEq(m.looseningDelay, 48 hours);
        assertEq(wallet.allowance(), 5 * 1e6, "capped at the new A at once");
        assertEq(wallet.changeCount(), changesBefore, "no time-locked change was needed");

        // Effective in the same block: 200 used to be autonomous.
        vm.recordLogs();
        uint256 itemId = _pay(hostingId, 200 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_ALLOWED);
        assertEq(wallet.itemReadyAt(itemId), block.timestamp + 2 hours);

        // Removing a payee and freezing are immediate too.
        vm.prank(owner);
        wallet.removePayee(softwareId);
        assertFalse(wallet.getPayee(softwareId).active);
        vm.prank(owner);
        wallet.freeze();
        assertTrue(wallet.frozen());
    }

    function test_PendingChange_CancelIsImmediate() public {
        vm.prank(owner);
        uint256 changeId = wallet.proposeAddPayee(keccak256("supplier"), makeAddr("supplier"));

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.cancelChange(changeId);

        vm.expectEmit(true, false, false, true, address(wallet));
        emit ChangeCancelled(changeId);
        vm.prank(owner);
        wallet.cancelChange(changeId);
        (Change memory c,) = wallet.getChange(changeId);
        assertEq(uint8(c.status), uint8(ChangeStatus.CANCELLED));
        assertEq(uint8(c.kind), uint8(ChangeKind.ADD_PAYEE));

        vm.warp(block.timestamp + LAMBDA);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotPending.selector, changeId));
        wallet.applyChange(changeId);
        assertEq(wallet.payeeCount(), 3);
    }

    // ------------------------------------------------------------------ pressure

    function test_PressureFlag_BlocksL1() public {
        uint16[3] memory pressure = [Flags.URGENCY, Flags.SECRECY, Flags.OVERRIDE_ATTEMPT];
        for (uint256 k = 0; k < pressure.length; ++k) {
            // Small, known, band low, owner instruction: L1 in every respect except the pressure flag.
            vm.recordLogs();
            uint256 itemId = _submit(_payment(hostingId, 10 * USD), 0, 0, KNOWN | pressure[k]);
            (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
            assertEq(tier, Tiers.L2);
            assertEq(check, Tiers.CHECK_SAFE_NOW);
            assertGt(itemId, 0);
            assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        }
        assertEq(token.balanceOf(hosting), 0, "nothing executed in the same transaction");
        assertEq(wallet.spentOnDay(block.timestamp / 1 days), 0);
    }

    function test_PressureHold_OwnerApprovalWaitsPi() public {
        // An owner-approval payment carrying a pressure flag.
        uint256 pressured = _submit(_payment(hostingId, 2500 * USD), 0, 0, KNOWN | Flags.URGENCY);
        // The same without pressure, for contrast.
        uint256 calm = _submit(_payment(softwareId, 2500 * USD), 0, 0, KNOWN);
        assertEq(uint8(_status(pressured)), uint8(ItemStatus.PROPOSED));
        assertTrue(wallet.getItem(pressured).hold);
        assertFalse(wallet.getItem(calm).hold);

        vm.startPrank(owner);
        wallet.approve(pressured);
        wallet.approve(calm);
        vm.stopPrank();
        uint64 approvedAt = uint64(block.timestamp);

        wallet.executePending(calm);
        assertEq(token.balanceOf(software), 2500 * USD, "without pressure, executable at once");

        assertEq(wallet.itemReadyAt(pressured), approvedAt + PI);
        vm.warp(approvedAt + PI - 1);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, pressured, approvedAt + PI));
        wallet.executePending(pressured);
        assertEq(token.balanceOf(hosting), 0);

        vm.warp(approvedAt + PI);
        wallet.executePending(pressured);
        assertEq(token.balanceOf(hosting), 2500 * USD);
    }

    function test_ExtendHold_OnlyIncreases() public {
        uint256 itemId = _submit(_payment(hostingId, 2500 * USD), 0, 0, KNOWN | Flags.SECRECY);
        vm.prank(owner);
        wallet.approve(itemId);
        uint64 ready = wallet.itemReadyAt(itemId);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.extendHold(itemId, 1 hours);

        vm.prank(owner);
        wallet.extendHold(itemId, 30 minutes);
        assertEq(wallet.itemReadyAt(itemId), ready + 30 minutes);
        vm.prank(owner);
        wallet.extendHold(itemId, 2 hours);
        assertEq(wallet.itemReadyAt(itemId), ready + 150 minutes, "extensions add up");

        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.InvalidHoldExtension.selector);
        wallet.extendHold(itemId, 0);

        // A shorter Π, even once applied through Λ, does not shorten the hold of an approved item.
        Mandate memory looser = wallet.mandate();
        looser.pressureHold = 10 minutes;
        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, looser);
        vm.warp(block.timestamp + LAMBDA);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertEq(wallet.itemReadyAt(itemId), ready + 150 minutes);

        // Once executed, nothing can be extended.
        wallet.executePending(itemId);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotPending.selector, itemId));
        wallet.extendHold(itemId, 1 hours);
    }

    function test_PanickedOwner_NoValueLeavesBeforeDelay() public {
        address attacker = makeAddr("attacker");
        uint256 walletBalance = token.balanceOf(address(wallet));

        // A scammer pressures the owner. The agent proposes the pressured payment the scam asks for.
        uint256 itemId = _submit(
            _payment(hostingId, 2500 * USD), 2, 1, KNOWN | Flags.URGENCY | Flags.SECRECY | Flags.OVERRIDE_ATTEMPT
        );
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));

        // The owner approves everything at once: the payment, and adding the scammer's address as a payee.
        uint64 t0 = uint64(block.timestamp);
        vm.startPrank(owner);
        wallet.approve(itemId);
        uint256 changeId = wallet.proposeAddPayee(keccak256("attacker"), attacker);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, changeId, t0 + LAMBDA));
        wallet.applyChange(changeId);
        vm.stopPrank();
        uint32 attackerId = uint32(wallet.payeeCount() + 1);

        // Nothing leaves before Π, whoever calls and whenever within Π.
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, t0 + PI));
        wallet.executePending(itemId);
        vm.warp(t0 + PI - 1);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, t0 + PI));
        wallet.executePending(itemId);
        Signed memory toAttacker = _signedPayment(attackerId, 100 * USD);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.UnknownPayee.selector, attackerId));
        _send(toAttacker);
        assertEq(token.balanceOf(address(wallet)), walletBalance, "no MockUSD left before Pi");
        assertEq(token.balanceOf(attacker), 0);

        // The owner had Π to come to their senses. They did not, so the approved payment goes through.
        vm.warp(t0 + PI);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(address(wallet)), walletBalance - 2500 * USD);

        // The new payee still cannot be paid until Λ has passed.
        vm.warp(t0 + LAMBDA - 1);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, changeId, t0 + LAMBDA));
        wallet.applyChange(changeId);
        Signed memory stillEarly = _signedPayment(attackerId, 100 * USD);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.UnknownPayee.selector, attackerId));
        _send(stillEarly);
        assertEq(token.balanceOf(attacker), 0, "the new payee was not paid before Lambda");

        vm.warp(t0 + LAMBDA);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertTrue(wallet.getPayee(attackerId).active);
    }

    // ------------------------------------------------------------------ further behaviour

    function test_ApprovedL3_ThatNowBreachesReserve_CannotExecute() public {
        // Above c2, so owner approval, but comfortably affordable when approved.
        uint256 itemId = _pay(hostingId, 2500 * USD);
        vm.prank(owner);
        wallet.approve(itemId);

        // The agent then sweeps most of the balance to savings at L1. 2,500 would now dig into the reserve.
        _submit(_intent(Task.SWEEP, 0, 7200 * USD), 0, 0, 0);
        assertEq(token.balanceOf(address(wallet)), 2800 * USD);

        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.NoLongerAffordable.selector, itemId));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(address(wallet)), 2800 * USD);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_ApprovedL3_StillAffordable_Executes() public {
        uint256 itemId = _pay(hostingId, 2500 * USD);
        vm.prank(owner);
        wallet.approve(itemId);
        // Spending that leaves it comfortable does not block it.
        _submit(_intent(Task.SWEEP, 0, 1000 * USD), 0, 0, 0);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 2500 * USD);
    }

    function test_Loosening_KeyChangesWaitLambda() public {
        address newAgent = makeAddr("newAgent");
        address newGuardian = makeAddr("newGuardian");
        vm.startPrank(owner);
        uint256 agentChange = wallet.proposeAgent(newAgent);
        uint256 guardianChange = wallet.proposeGuardian(newGuardian);
        vm.warp(block.timestamp + LAMBDA - 1);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, agentChange, block.timestamp + 1)
        );
        wallet.applyChange(agentChange);
        vm.stopPrank();
        assertEq(wallet.agent(), agent);
        assertEq(wallet.guardian(), guardian);

        vm.warp(block.timestamp + 1);
        vm.startPrank(owner);
        wallet.applyChange(agentChange);
        wallet.applyChange(guardianChange);
        vm.stopPrank();
        assertEq(wallet.agent(), newAgent);
        assertEq(wallet.guardian(), newGuardian);
    }

    function test_RevokeAgent_IsImmediate() public {
        vm.prank(owner);
        wallet.revokeAgent();
        assertEq(wallet.agent(), address(0));
        Signed memory s = _signedPayment(hostingId, 100 * USD);
        vm.expectRevert(IPolicyWalletErrors.NotAgent.selector);
        _send(s);
    }

    // ------------------------------------------------------------------ helpers

    function _expectNotReady(uint256 changeId, uint64 ready) internal {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, changeId, ready));
        wallet.applyChange(changeId);
    }
}
