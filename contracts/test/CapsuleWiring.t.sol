// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {PolicyWallet} from "../src/PolicyWallet.sol";
import {ThreatBulletin} from "../src/ThreatBulletin.sol";
import {DecisionLogic} from "../src/lib/DecisionLogic.sol";
import {CapsuleAction, Flags, Mandate, Task, Tiers} from "../src/lib/AgentVaxTypes.sol";

/// @notice Wiring between the wallet and the bulletin: the task to capsule-action mapping, the
///         confidence cap, fail-closed sync and allowance halving.
contract CapsuleWiringTest is Base {
    uint8 internal constant FAMILY_RECIPIENT = 5;
    uint8 internal constant CHANNEL_MESSAGE = 2;
    uint16 internal constant FEATURES = Flags.NEW_DESTINATION | Flags.URGENCY;

    PolicyWallet internal walletB;
    address internal ownerB;

    function setUp() public override {
        super.setUp();
        _fund(10_000 * USD);
        ownerB = makeAddr("ownerB");
        walletB = _newWallet(ownerB, makeAddr("agentB"));
    }

    function test_CapsuleAction_MapsFromTask_FeeTopUpNeverMatched() public pure {
        assertEq(uint8(DecisionLogic.capsuleActionFor(uint8(Task.PAYMENT))), uint8(CapsuleAction.PAYMENT));
        assertEq(
            uint8(DecisionLogic.capsuleActionFor(uint8(Task.SCHEDULE_CREATE))), uint8(CapsuleAction.SCHEDULE_CREATE)
        );
        assertEq(uint8(DecisionLogic.capsuleActionFor(uint8(Task.SWEEP))), uint8(CapsuleAction.SWEEP));
        assertEq(uint8(DecisionLogic.capsuleActionFor(uint8(Task.FEE_TOPUP))), uint8(CapsuleAction.NONE));
        assertEq(uint8(DecisionLogic.capsuleActionFor(0)), uint8(CapsuleAction.NONE));
        assertEq(uint8(DecisionLogic.capsuleActionFor(5)), uint8(CapsuleAction.NONE));
    }

    function test_PayeeOrMandateChangeCapsule_DoesNotMatchFeeTopUp() public {
        // Action 4 equals the numeric value of FEE_TOPUP; the separate enums keep them apart.
        _publishFromB(uint8(CapsuleAction.PAYEE_OR_MANDATE_CHANGE), Tiers.L3, Flags.URGENCY);
        vm.recordLogs();
        _submit(_intent(Task.FEE_TOPUP, 0, 0.01 ether), 0, 0, Flags.URGENCY);
        (uint8 tier,, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(capsuleId, 0);
        assertEq(tier, Tiers.L2, "the pressure flag alone, not the capsule");
    }

    function test_SingleObserverCapsule_CappedAtDelay() public {
        uint256 id = _publishFromB(uint8(CapsuleAction.PAYMENT), Tiers.L3, FEATURES);
        assertEq(bulletin.effectiveRestriction(id), Tiers.L2);

        vm.recordLogs();
        _submit(_payment(hostingId, 100 * USD), 0, 0, FEATURES | Flags.KNOWN_PAYEE_IDENTITY);
        (uint8 tier, uint8 check, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);

        vm.prank(owner);
        wallet.attestCapsule(id);
        assertEq(bulletin.effectiveRestriction(id), Tiers.L3, "confirmed by a second wallet");
    }

    function test_CapsuleBacklog_FailsClosed() public {
        // A wallet that listens only to owner chat, so the capsules below do not apply to it.
        PolicyWallet narrow = _newWallet(owner, agent);
        Mandate memory m = defaultMandate();
        m.channelProfile = 0x01;
        vm.prank(owner);
        narrow.setMandate(MISSION, m);
        bytes32[] memory ids = new bytes32[](1);
        address[] memory accounts = new address[](1);
        ids[0] = keccak256("hosting");
        accounts[0] = hosting;
        _addPayees(narrow, owner, ids, accounts);
        wallet = narrow;
        _fund(10_000 * USD);

        // More capsules than one automatic sync processes, on the token-metadata channel.
        for (uint256 k = 0; k < 4; ++k) {
            PolicyWallet publisher = _newWallet(makeAddr(string(abi.encode("publisher", k))), makeAddr("pubAgent"));
            for (uint256 n = 0; n < 3; ++n) {
                vm.prank(publisher.owner());
                publisher.publishCapsule(1, 4, Flags.ENCODED_CONTENT, uint8(CapsuleAction.SWEEP), Tiers.L2, 1 days, 1);
            }
        }
        assertEq(bulletin.capsuleCount(), 12);

        vm.recordLogs();
        _pay(1, 10 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(wallet.capsuleCursor(), wallet.AUTO_SYNC_CHUNK());
        assertEq(tier, Tiers.L2, "unprocessed capsules raise every request to at least L2");
        assertEq(check, Tiers.CHECK_SAFE_NOW);

        wallet.syncCapsules(100);
        assertEq(wallet.capsuleBacklog(), 0);
        assertEq(wallet.trackedCapsules().length, 0, "none applied to this profile");
        vm.recordLogs();
        _pay(1, 10 * USD);
        (tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
    }

    function test_ApplicableCapsule_HalvesAllowanceOnce() public {
        uint256 full = wallet.allowance();
        _publishFromB(uint8(CapsuleAction.PAYMENT), Tiers.L2, FEATURES);
        wallet.syncCapsules(10);
        assertEq(wallet.allowance(), full / 2);
        wallet.syncCapsules(10);
        assertEq(wallet.allowance(), full / 2, "a capsule halves the allowance only once");
    }

    function test_Capsule_CannotTouchMandate() public {
        (, bytes32 before) = wallet.mandateHashes();
        uint256 payees = wallet.payeeCount();
        _publishFromB(uint8(CapsuleAction.PAYEE_OR_MANDATE_CHANGE), Tiers.L3, FEATURES);
        wallet.syncCapsules(10);
        (, bytes32 afterwards) = wallet.mandateHashes();
        assertEq(afterwards, before);
        assertEq(wallet.payeeCount(), payees);
    }

    function test_MatchCapsules_ViewListsFullAndPartial() public {
        uint256 full = _publishFromB(uint8(CapsuleAction.PAYMENT), Tiers.L2, Flags.URGENCY);
        uint256 partialOnly = _publishFromB(uint8(CapsuleAction.PAYMENT), Tiers.L2, FEATURES);
        wallet.syncCapsules(10);
        (uint256[] memory fullIds, uint256[] memory partialIds, uint8 restriction, bool failClosed) =
            wallet.matchCapsules(uint8(CapsuleAction.PAYMENT), Flags.URGENCY);
        assertEq(fullIds.length, 1);
        assertEq(fullIds[0], full);
        assertEq(partialIds.length, 1);
        assertEq(partialIds[0], partialOnly);
        assertEq(restriction, Tiers.L2);
        assertFalse(failClosed);
    }

    function test_ModelAnchor_OnlyAggregator_VersionsIncrease() public {
        vm.expectRevert(ThreatBulletin.NotAggregator.selector);
        bulletin.anchorModel(1, keccak256("model"));
        vm.prank(aggregator);
        bulletin.anchorModel(1, keccak256("model"));
        assertEq(bulletin.modelHash(1), keccak256("model"));
        vm.prank(aggregator);
        vm.expectRevert(abi.encodeWithSelector(ThreatBulletin.StaleModelVersion.selector, 1, 1));
        bulletin.anchorModel(1, keccak256("other"));
    }

    function _publishFromB(uint8 action, uint8 restriction, uint16 features) internal returns (uint256) {
        vm.prank(ownerB);
        return walletB.publishCapsule(FAMILY_RECIPIENT, CHANNEL_MESSAGE, features, action, restriction, 1 days, 1);
    }
}
