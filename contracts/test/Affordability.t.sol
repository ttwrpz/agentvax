// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {Base} from "./Base.t.sol";
import {Flags, Intent, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {ItemStatus, Obligation} from "../src/wallet/WalletTypes.sol";

contract AffordabilityTest is Base {
    uint64 internal rentId;
    uint64 internal hostingBillId;
    uint64 internal softwareBillId;

    /// @dev Balance 1,850, R 600, rent 800 due in 5 days, hosting 150, software 120.
    function setUp() public override {
        super.setUp();
        _fund(1850 * USD);
        rentId = _addObligation(landlordId, 800 * USD, uint64(block.timestamp + 5 days));
        hostingBillId = _addObligation(hostingId, 150 * USD, uint64(block.timestamp + 10 days));
        softwareBillId = _addObligation(softwareId, 120 * USD, uint64(block.timestamp + 20 days));
    }


    function test_Discretionary_MatchesWorkedExample() public {
        assertEq(wallet.discretionary(0), 180 * USD);

        Signed memory upgrade = _signedPayment(hostingId, 300 * USD);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit Decision(upgrade.att.intentHash, Tiers.L2, Tiers.CHECK_AFFORDABLE, 0);
        uint256 itemId = _send(upgrade);

        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED), "tight: allowed but queued");
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_Afford_Comfortable_Tight_Breach() public {
        // Comfortable: 100 <= D = 180.
        vm.recordLogs();
        _pay(hostingId, 100 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
        assertEq(check, Tiers.CHECK_ALLOWED);
        assertEq(token.balanceOf(hosting), 100 * USD);
        assertEq(wallet.discretionary(0), 80 * USD);

        // Tight: D = 80 < 300 <= B - R = 1,150.
        vm.recordLogs();
        _pay(hostingId, 300 * USD);
        (tier, check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_AFFORDABLE);

        // Breach: 1,300 > B - R = 1,150. Within c2, so only affordability demands the owner.
        vm.recordLogs();
        uint256 itemId = _pay(hostingId, 1300 * USD);
        (tier, check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3);
        assertEq(check, Tiers.CHECK_AFFORDABLE);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    function test_PayingRegisteredObligation_ExcludesItself() public {
        // A larger hosting bill takes D to zero; paying exactly that bill must not count it against itself.
        uint64 bigBill = _addObligation(hostingId, 180 * USD, uint64(block.timestamp + 3 days));
        assertEq(wallet.discretionary(0), 0);
        assertEq(wallet.discretionary(bigBill), 180 * USD);

        // Without the reference the same payment is tight.
        vm.recordLogs();
        _pay(hostingId, 180 * USD);
        (uint8 tierWithout,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tierWithout, Tiers.L2);

        vm.recordLogs();
        _submitClean(_obligationPayment(bigBill, hostingId, 180 * USD));
        (uint8 tierWith,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tierWith, Tiers.L1);
        assertEq(token.balanceOf(hosting), 180 * USD);
        assertFalse(wallet.getObligation(bigBill).open, "settled by the payment");
        assertEq(wallet.discretionary(0), 0, "paying a reserved bill leaves D unchanged");
    }

    function test_AgentCanAddObligation_OnlyOwnerRemoves() public {
        uint64 extra = _addObligation(softwareId, 50 * USD, uint64(block.timestamp + 1 days));
        assertEq(wallet.discretionary(0), 130 * USD, "adding a bill lowers D at once");

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.proposeRemoveObligation(extra);

        vm.prank(owner);
        uint256 changeId = wallet.proposeRemoveObligation(extra);
        uint64 ready = wallet.changeReadyAt(changeId);
        assertEq(ready, block.timestamp + 24 hours);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, changeId, ready));
        wallet.applyChange(changeId);
        assertEq(wallet.discretionary(0), 130 * USD);

        vm.warp(ready);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertFalse(wallet.getObligation(extra).open);
        assertEq(wallet.discretionary(0), 180 * USD);
    }

    // ------------------------------------------------------------------ obligation reference binding

    function test_ObligationRef_ForOtherPayee_Rejected() public {
        Signed memory s = _signed(_obligationPayment(rentId, hostingId, 800 * USD), 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ObligationMismatch.selector, rentId));
        _send(s);
        assertTrue(wallet.getObligation(rentId).open);
        assertEq(wallet.discretionary(0), 180 * USD, "D was not inflated");
    }

    function test_ObligationRef_ForOtherAmount_Rejected() public {
        Signed memory s =
            _signed(_obligationPayment(hostingBillId, hostingId, 300 * USD), 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ObligationMismatch.selector, hostingBillId));
        _send(s);
        assertTrue(wallet.getObligation(hostingBillId).open);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_ObligationRef_Settled_CannotBeReused() public {
        _submitClean(_obligationPayment(hostingBillId, hostingId, 150 * USD));
        assertFalse(wallet.getObligation(hostingBillId).open);

        Signed memory again =
            _signed(_obligationPayment(hostingBillId, hostingId, 150 * USD), 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ObligationMismatch.selector, hostingBillId));
        _send(again);
    }

    function test_Obligation_BeyondHorizon_NotCounted() public {
        _addObligation(landlordId, 100 * USD, uint64(block.timestamp + 31 days));
        assertEq(wallet.discretionary(0), 180 * USD);
        vm.warp(block.timestamp + 2 days);
        assertEq(wallet.discretionary(0), 80 * USD, "it enters the horizon as time passes");
    }

    function test_Obligations_BoundedAt32() public {
        // The agent fills its share, the owner fills the rest.
        uint256 open = wallet.openObligationIds().length;
        uint256 agentCap = wallet.MAX_AGENT_OBLIGATIONS();
        for (uint256 k = open; k < agentCap; ++k) {
            _addObligation(softwareId, 1, uint64(block.timestamp + 40 days));
        }
        vm.startPrank(owner);
        for (uint256 k = agentCap; k < 32; ++k) {
            wallet.addObligation(softwareId, 1, uint64(block.timestamp + 40 days));
        }
        assertEq(wallet.openObligationIds().length, 32);
        vm.expectRevert(IPolicyWalletErrors.ObligationsFull.selector);
        wallet.addObligation(softwareId, 1, uint64(block.timestamp + 40 days));
        vm.stopPrank();
    }

    function test_AgentObligations_Capped_OwnerKeepsRoom() public {
        uint256 agentCap = wallet.MAX_AGENT_OBLIGATIONS();
        assertEq(wallet.agentObligationCount(), 3, "the three bills of setUp were added by the agent");
        for (uint256 k = 3; k < agentCap; ++k) {
            _addObligation(softwareId, 1, uint64(block.timestamp + 40 days));
        }
        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.AgentObligationsFull.selector);
        wallet.addObligation(softwareId, 1, uint64(block.timestamp + 40 days));

        // The owner still has room, and so do schedules: the agent's share plus every schedule leaves slots over.
        assertLt(agentCap + wallet.MAX_SCHEDULES(), wallet.MAX_OBLIGATIONS());
        vm.prank(owner);
        wallet.addObligation(landlordId, 1, uint64(block.timestamp + 40 days));

        // Paying one of the agent's bills frees a slot for the agent.
        _submitClean(_obligationPayment(hostingBillId, hostingId, 150 * USD));
        assertEq(token.balanceOf(hosting), 150 * USD);
        assertEq(wallet.agentObligationCount(), agentCap - 1);
        _addObligation(softwareId, 1, uint64(block.timestamp + 40 days));
        assertEq(wallet.agentObligationCount(), agentCap);
    }

    function test_Obligation_HugeAmount_SaturatesD() public {
        _addObligation(softwareId, type(uint256).max, uint64(block.timestamp + 1 days));
        assertEq(wallet.discretionary(0), 0);
    }

    // ------------------------------------------------------------------ helpers

    function _obligationPayment(uint64 obligationId, uint32 payeeId, uint256 amount)
        internal
        view
        returns (Intent memory i)
    {
        i = _payment(payeeId, amount);
        i.scheduleId = obligationId;
    }
}
