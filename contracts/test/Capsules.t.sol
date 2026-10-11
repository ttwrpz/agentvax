// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {PolicyWallet} from "../src/PolicyWallet.sol";
import {ThreatBulletin} from "../src/ThreatBulletin.sol";
import {Capsule, CapsuleAction, Flags, Mandate, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {ItemStatus} from "../src/wallet/WalletTypes.sol";

/// @notice Immunity capsules seen from a wallet: full and partial matches, the single-observer cap,
///         confirmation by a second wallet, expiry, the rate limit, owner dismissal and the model anchor.
///         Capsules come from other registered wallets, as on the shared bulletin.
contract CapsulesTest is Base {
    uint256 internal constant POINT = 1e6;
    uint8 internal constant FAMILY_MEMORY = 3;
    uint8 internal constant CHANNEL_MEMORY = 3;
    uint8 internal constant PAYMENT = uint8(CapsuleAction.PAYMENT);
    /// @dev A memory-poisoning attack seen elsewhere: content from memory, encoded.
    uint16 internal constant FEATURES = Flags.MEMORY_SOURCED | Flags.ENCODED_CONTENT;
    uint16 internal constant MATCHING = Flags.KNOWN_PAYEE_IDENTITY | FEATURES;

    PolicyWallet internal walletB;
    address internal ownerB;
    PolicyWallet internal walletC;
    address internal ownerC;

    event ModelAnchored(uint32 indexed version, bytes32 modelHash);

    function setUp() public override {
        super.setUp();
        _fund(10_000 * USD);
        ownerB = makeAddr("ownerB");
        walletB = _newWallet(ownerB, makeAddr("agentB"));
        ownerC = makeAddr("ownerC");
        walletC = _newWallet(ownerC, makeAddr("agentC"));
    }


    function test_Capsule_FullMatch_RaisesTier_NextTransaction() public {
        // Before any capsule, the request executes at once.
        vm.recordLogs();
        _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);

        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        assertEq(wallet.capsuleCursor(), 0, "nobody synced the wallet");

        // The very next transaction picks the capsule up and is raised to its restriction.
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        uint8 check;
        uint256 capsuleId;
        (tier, check, capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(wallet.capsuleCursor(), id);
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    function test_Capsule_PartialMatch_ChargesAllowance() public {
        _pay(hostingId, 100 * USD);
        vm.warp(block.timestamp + 24 hours);
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 7 days);
        wallet.syncCapsules(10);
        assertEq(wallet.allowance(), 5 * POINT, "halved once by the applicable capsule");

        // One of the two features is present: half of them, a partial match. The tier is not raised, but the
        // request costs the partial-match charge of 5.
        uint16 half = Flags.KNOWN_PAYEE_IDENTITY | Flags.MEMORY_SOURCED;
        Signed memory s = _signed(_payment(hostingId, 100 * USD), 0, 0, half);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit AllowanceCharged(s.att.intentHash, 5 * POINT, 0);
        vm.recordLogs();
        assertEq(_send(s), 0);
        (uint8 tier,, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
        assertEq(capsuleId, id);
        assertEq(token.balanceOf(hosting), 200 * USD);

        // The same request again no longer fits the allowance and waits.
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, half);
        uint8 check;
        (tier, check, capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_ALLOWANCE);
        assertEq(capsuleId, id);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
    }

    function test_Capsule_NotApplicable_WalletUnaffected() public {
        // A wallet that listens only to owner chat. The capsule is on the memory channel.
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
        (, bytes32 mandateBefore) = wallet.mandateHashes();

        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);
        vm.prank(ownerC);
        walletC.attestCapsule(id);

        vm.recordLogs();
        uint256 itemId = _submit(_payment(1, 100 * USD), 0, 0, MATCHING);
        (uint8 tier,, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(itemId, 0);
        assertEq(tier, Tiers.L1);
        assertEq(capsuleId, 0);
        assertEq(token.balanceOf(hosting), 100 * USD);
        assertEq(wallet.capsuleCursor(), id, "processed");
        assertEq(wallet.trackedCapsules().length, 0, "but not tracked");
        assertEq(wallet.allowance(), 7 * POINT, "only the first-payment charge, no halving");
        (, bytes32 mandateAfter) = wallet.mandateHashes();
        assertEq(mandateAfter, mandateBefore);
    }

    function test_Capsule_SingleObserver_MaxDelay() public {
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);
        Capsule memory c = bulletin.getCapsule(id);
        assertEq(c.restriction, Tiers.L3, "asked for owner approval");
        assertEq(c.attestations, 1);
        assertEq(bulletin.effectiveRestriction(id), Tiers.L2, "imposes at most a delay");

        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier, uint8 check, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);

        // No owner action is needed: after Δ anyone executes it while the capsule still matches.
        vm.warp(block.timestamp + 1 hours);
        vm.prank(makeAddr("anyone"));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    function test_Capsule_Confirmed_NeedsSecondWallet() public {
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);

        // The issuer cannot confirm its own capsule, and an unregistered address cannot attest.
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(ThreatBulletin.AlreadyAttested.selector, id, address(walletB)));
        walletB.attestCapsule(id);
        address outsider = makeAddr("outsider");
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ThreatBulletin.NotRegistered.selector, outsider));
        bulletin.attest(id);
        assertEq(bulletin.effectiveRestriction(id), Tiers.L2);

        vm.recordLogs();
        _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "one observer: a delay");

        // A second, distinct registered wallet confirms it.
        vm.prank(ownerC);
        walletC.attestCapsule(id);
        assertEq(bulletin.getCapsule(id).attestations, 2);
        assertEq(bulletin.effectiveRestriction(id), Tiers.L3);

        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        uint8 check;
        uint256 capsuleId;
        (tier, check, capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3, "confirmed: owner approval");
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));
        assertTrue(wallet.getItem(itemId).hold, "an approval of a capsule-matched item waits the pressure hold");
    }

    function test_Capsule_Expires_AutonomyReturns() public {
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        uint64 expiry = bulletin.getCapsule(id).expiry;

        vm.recordLogs();
        _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);
        assertEq(wallet.trackedCapsules().length, 1);

        vm.warp(expiry - 1);
        vm.recordLogs();
        _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "still in force one second before expiry");

        vm.warp(expiry);
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        uint256 capsuleId;
        (tier,, capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(itemId, 0);
        assertEq(tier, Tiers.L1, "autonomy returns without anyone acting");
        assertEq(capsuleId, 0);
        assertEq(wallet.trackedCapsules().length, 0, "the expired capsule was dropped");
        assertEq(token.balanceOf(hosting), 100 * USD);
    }

    function test_Capsule_CannotLoosen() public {
        // The bulletin refuses a capsule whose restriction is below a delay.
        vm.startPrank(ownerB);
        vm.expectRevert(ThreatBulletin.InvalidCapsule.selector);
        walletB.publishCapsule(FAMILY_MEMORY, CHANNEL_MEMORY, FEATURES, PAYMENT, Tiers.L1, 1 days, 1);
        vm.expectRevert(ThreatBulletin.InvalidCapsule.selector);
        walletB.publishCapsule(FAMILY_MEMORY, CHANNEL_MEMORY, FEATURES, PAYMENT, 0, 1 days, 1);
        vm.stopPrank();

        (, bytes32 mandateBefore) = wallet.mandateHashes();
        uint256 payeesBefore = wallet.payeeCount();
        uint256 allowanceBefore = wallet.allowance();

        // A full-match delay capsule does not lower a request that is already at owner approval.
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        _publish(walletB, ownerB, uint8(CapsuleAction.PAYEE_OR_MANDATE_CHANGE), Tiers.L2, FEATURES, 1 days);
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 2, 0, MATCHING);
        (uint8 tier, uint8 check, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3);
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));

        // Nothing about authority moved: same mandate, same payees, and the allowance only went down.
        (, bytes32 mandateAfter) = wallet.mandateHashes();
        assertEq(mandateAfter, mandateBefore);
        assertEq(wallet.payeeCount(), payeesBefore);
        assertEq(wallet.mandate().c1, 500 * USD);
        assertEq(wallet.mandate().reserve, 600 * USD);
        assertFalse(wallet.frozen());
        assertLt(wallet.allowance(), allowanceBefore);
    }

    function test_Capsule_RateLimit() public {
        uint256 limit = bulletin.MAX_PUBLISH_PER_DAY();
        for (uint256 k = 0; k < limit; ++k) {
            _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        }
        assertEq(bulletin.capsuleCount(), limit);

        uint256 day = block.timestamp / 1 days;
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(ThreatBulletin.PublishLimitReached.selector, day));
        walletB.publishCapsule(FAMILY_MEMORY, CHANNEL_MEMORY, FEATURES, PAYMENT, Tiers.L2, 1 days, 1);
        assertEq(bulletin.capsuleCount(), limit);

        // The limit is per wallet: another wallet can still publish today.
        _publish(walletC, ownerC, PAYMENT, Tiers.L2, FEATURES, 1 days);

        // And per day: the next day the first wallet can publish again.
        vm.warp((day + 1) * 1 days);
        _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        assertEq(bulletin.capsuleCount(), limit + 2);
    }

    function test_Capsule_OwnerDismiss() public {
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        vm.recordLogs();
        _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2);

        vm.prank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.dismissCapsule(id);

        (, bytes32 mandateBefore) = wallet.mandateHashes();
        vm.expectEmit(true, false, false, true, address(wallet));
        emit CapsuleDismissed(id);
        vm.prank(owner);
        wallet.dismissCapsule(id);
        assertTrue(wallet.capsuleDismissed(id));

        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        uint256 capsuleId;
        (tier,, capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(itemId, 0);
        assertEq(tier, Tiers.L1, "dismissed for this wallet");
        assertEq(capsuleId, 0);

        // Only for this wallet, and the mandate is untouched.
        assertFalse(walletC.capsuleDismissed(id));
        assertEq(bulletin.effectiveRestriction(id), Tiers.L2);
        assertGt(bulletin.getCapsule(id).expiry, block.timestamp);
        (, bytes32 mandateAfter) = wallet.mandateHashes();
        assertEq(mandateAfter, mandateBefore);
    }

    function test_ModelAnchor_RecordsVersionAndHash() public {
        bytes32 first = keccak256("detector v1 weights");
        bytes32 second = keccak256("detector v2 weights");

        vm.expectEmit(true, false, false, true, address(bulletin));
        emit ModelAnchored(1, first);
        vm.prank(aggregator);
        bulletin.anchorModel(1, first);

        vm.expectEmit(true, false, false, true, address(bulletin));
        emit ModelAnchored(2, second);
        vm.prank(aggregator);
        bulletin.anchorModel(2, second);

        assertEq(bulletin.latestModelVersion(), 2);
        assertEq(bulletin.modelHash(1), first, "earlier versions stay on record");
        assertEq(bulletin.modelHash(2), second);
    }

    // ------------------------------------------------------------------ further behaviour

    function test_Capsule_UnregisteredCannotPublish() public {
        address outsider = makeAddr("outsider");
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(ThreatBulletin.NotRegistered.selector, outsider));
        bulletin.publish(FAMILY_MEMORY, CHANNEL_MEMORY, FEATURES, PAYMENT, Tiers.L2, 1 days, 1);
    }

    function test_Capsule_LifetimeBounded() public {
        uint64 tooLong = bulletin.MAX_LIFETIME() + 1;
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(ThreatBulletin.InvalidLifetime.selector, tooLong));
        walletB.publishCapsule(FAMILY_MEMORY, CHANNEL_MEMORY, FEATURES, PAYMENT, Tiers.L2, tooLong, 1);
    }

    function test_Capsule_ConfirmedAfterApproval_AddsPressureHold() public {
        uint256 itemId = _pay(hostingId, 2500 * USD);
        vm.prank(owner);
        wallet.approve(itemId);
        assertEq(wallet.itemReadyAt(itemId), block.timestamp, "no hold without pressure or capsule");

        // A capsule that starts to match before execution adds Π to the approved item.
        _publish(walletB, ownerB, PAYMENT, Tiers.L2, Flags.KNOWN_PAYEE_IDENTITY, 1 days);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, block.timestamp + 60 minutes)
        );
        wallet.executePending(itemId);
        vm.warp(block.timestamp + 60 minutes);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 2500 * USD);
    }

    // ------------------------------------------------------------------ tracked list and channel profile

    function test_TrackedListFull_QuorumL3CapsuleStillImposesL3() public {
        _fillTrackedList();
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 7 days);
        vm.prank(ownerC);
        walletC.attestCapsule(id);

        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier, uint8 check, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3, "a confirmed capsule is not buried by a full list");
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));
        assertEq(wallet.trackedCapsules().length, wallet.MAX_TRACKED_CAPSULES());
        assertEq(wallet.capsuleBacklog(), 0);
    }

    function test_TrackedListFull_EvictedCapsuleStillFailsClosed() public {
        uint64 lastExpiry = _fillTrackedList();
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);
        vm.prank(ownerC);
        walletC.attestCapsule(id);
        wallet.syncCapsules(10);
        assertEq(wallet.capsuleBacklog(), 0);

        // A capsule that lost its slot is still unexpired, so every request waits at least Δ.
        (,,, bool failClosed) = wallet.matchCapsules(PAYMENT, Flags.KNOWN_PAYEE_IDENTITY);
        assertTrue(failClosed);
        vm.recordLogs();
        _pay(hostingId, 10 * USD);
        (uint8 tier, uint8 check,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "never above a delay for the overflow");
        assertEq(check, Tiers.CHECK_SAFE_NOW);

        // Once every capsule that lost its slot has expired, autonomy returns.
        vm.warp(lastExpiry);
        vm.recordLogs();
        _pay(hostingId, 10 * USD);
        (tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
    }

    function test_ChannelProfileWidened_PicksUpExistingCapsule() public {
        // A wallet that listens only to owner chat.
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

        // One capsule on owner chat, which applies now, and one on the memory channel, which does not.
        _publishOn(walletB, ownerB, 0, uint8(CapsuleAction.SWEEP), Tiers.L2, Flags.ENCODED_CONTENT, 7 days);
        uint256 onMemory = _publishOn(walletB, ownerB, CHANNEL_MEMORY, PAYMENT, Tiers.L2, FEATURES, 7 days);
        wallet.syncCapsules(10);
        assertEq(wallet.allowance(), 5 * POINT, "halved once, for the owner-chat capsule");
        vm.recordLogs();
        _submit(_payment(1, 100 * USD), 0, 0, MATCHING);
        (uint8 tier,,) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L1);
        assertEq(wallet.allowance(), 2 * POINT);

        // The owner starts listening to the memory channel too. Adding a channel tightens, so it is immediate.
        Mandate memory wider = wallet.mandate();
        wider.channelProfile = 0x01 | uint8(1 << CHANNEL_MEMORY);
        _setMandateAs(owner, wider);

        vm.recordLogs();
        uint256 itemId = _submit(_payment(1, 100 * USD), 0, 0, MATCHING);
        uint8 check;
        uint256 capsuleId;
        (tier, check, capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L2, "the capsule published before the change now applies");
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, onMemory);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));
        assertEq(wallet.trackedCapsules().length, 2, "no capsule is tracked twice");
        assertEq(wallet.allowance(), 1 * POINT, "halved once for the newly applicable capsule only");
    }

    // ------------------------------------------------------------------ backlog and untracked capsules

    function test_CapsuleBacklog_BlocksPendingExecution() public {
        uint256 itemId = _submit(_payment(hostingId, 800 * USD), 0, 0, MATCHING);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.QUEUED));

        // As many unrelated capsules as one automatic sync processes, then a confirmed match.
        _publishFillers(wallet.AUTO_SYNC_CHUNK(), 1 days);
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);
        vm.prank(ownerC);
        walletC.attestCapsule(id);

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.CapsuleBacklog.selector, 1));
        wallet.executePending(itemId);

        // Anyone clears the backlog. The item now needs owner approval and cannot execute.
        wallet.syncCapsules(10);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.NoLongerAuthorised.selector, itemId, Tiers.L3));
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_CapsuleBacklog_BlocksApproval() public {
        uint256 itemId = _pay(hostingId, 2500 * USD);
        _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.CapsuleBacklog.selector, 1));
        wallet.approve(itemId);

        wallet.syncCapsules(10);
        vm.prank(owner);
        wallet.approve(itemId);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.APPROVED));
    }

    function test_EvictedCapsule_GainingQuorum_ImposesL3() public {
        _fillTrackedList();
        // Asks for owner approval but has one observer, so its effective restriction is a delay. It expires
        // before the fillers, so it ranks below all of them and gets no tracking slot.
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);
        wallet.syncCapsules(10);
        assertFalse(_isTracked(id));

        // A second wallet confirms it. The next transaction re-ranks it and it takes a slot.
        vm.prank(ownerC);
        walletC.attestCapsule(id);
        vm.recordLogs();
        uint256 itemId = _submit(_payment(hostingId, 100 * USD), 0, 0, MATCHING);
        (uint8 tier, uint8 check, uint256 capsuleId) = _lastDecision(vm.getRecordedLogs());
        assertEq(tier, Tiers.L3, "confirmation after eviction still imposes owner approval");
        assertEq(check, Tiers.CHECK_SAFE_NOW);
        assertEq(capsuleId, id);
        assertEq(uint8(_status(itemId)), uint8(ItemStatus.PROPOSED));
        assertTrue(_isTracked(id));
    }

    function test_UntrackedCapsulesOverflow_PendingExecutionRefused() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        // More applicable capsules than the tracked and the spilled lists hold together.
        uint256 capacity = wallet.MAX_TRACKED_CAPSULES() + wallet.MAX_SPILLED_CAPSULES();
        uint64 lastExpiry = _publishFillers(capacity + 1, 2 days);
        wallet.syncCapsules(capacity + 1);
        assertEq(wallet.capsuleBacklog(), 0);

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(IPolicyWalletErrors.CapsuleOverflow.selector);
        wallet.executePending(itemId);

        // A delay bounded by the capsules' lifetime: once they expire the item executes.
        vm.warp(lastExpiry);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 800 * USD);
    }

    function test_SpilledConfirmedCapsule_BlocksPendingExecution() public {
        uint256 itemId = _pay(hostingId, 800 * USD);
        // Every tracked slot holds a confirmed owner-approval capsule for sweeps.
        uint256 slots = wallet.MAX_TRACKED_CAPSULES();
        uint256 firstFiller = bulletin.capsuleCount() + 1;
        _publishFillersL3(slots);
        for (uint256 k = 0; k < slots; ++k) {
            vm.prank(ownerC);
            walletC.attestCapsule(firstFiller + k);
        }
        // A confirmed match for the queued payment that ranks below them (it expires sooner).
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L3, FEATURES, 1 days);
        vm.prank(ownerC);
        walletC.attestCapsule(id);
        wallet.syncCapsules(slots + 1);
        assertFalse(_isTracked(id));

        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(IPolicyWalletErrors.CapsuleOverflow.selector);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 0);
    }

    function test_SpilledMatch_ApprovalWaitsPi() public {
        _fillTrackedList();
        // A single-observer delay capsule matching the payment, ranked below the fillers, so it is spilled.
        uint256 id = _publish(walletB, ownerB, PAYMENT, Tiers.L2, FEATURES, 1 days);
        wallet.syncCapsules(10);
        assertFalse(_isTracked(id));

        // A calm owner-approval payment that the spilled capsule fully matches.
        uint256 itemId = _submit(_payment(hostingId, 2500 * USD), 0, 0, MATCHING);
        vm.prank(owner);
        wallet.approve(itemId);
        uint64 ready = uint64(block.timestamp + 60 minutes);
        assertEq(wallet.itemReadyAt(itemId), ready, "an unmatched capsule could be a full match: wait Pi");
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ItemNotReady.selector, itemId, ready));
        wallet.executePending(itemId);
        vm.warp(ready);
        wallet.executePending(itemId);
        assertEq(token.balanceOf(hosting), 2500 * USD);
    }

    // ------------------------------------------------------------------ helpers

    function _isTracked(uint256 id) internal view returns (bool) {
        uint256[] memory tracked = wallet.trackedCapsules();
        for (uint256 i = 0; i < tracked.length; ++i) {
            if (tracked[i] == id) return true;
        }
        return false;
    }

    /// @dev Like `_publishFillers`, but each capsule asks for owner approval and lives 2 days.
    function _publishFillersL3(uint256 count) internal {
        uint256 perWallet = bulletin.MAX_PUBLISH_PER_DAY();
        uint256 published;
        while (published < count) {
            PolicyWallet publisher =
                _newWallet(makeAddr(string(abi.encode("filler", fillerWallets++))), makeAddr("fillerAgent"));
            for (uint256 n = 0; n < perWallet && published < count; ++n) {
                _publish(publisher, publisher.owner(), uint8(CapsuleAction.SWEEP), Tiers.L3, Flags.ENCODED_CONTENT, 2 days);
                ++published;
            }
        }
    }

    /// @dev Fills the wallet's tracked list with single-observer delay capsules for sweeps, from wallets
    ///      other than B and C, and syncs them. Returns the latest expiry among them.
    function _fillTrackedList() internal returns (uint64 lastExpiry) {
        uint256 slots = wallet.MAX_TRACKED_CAPSULES();
        lastExpiry = _publishFillers(slots, 2 days);
        wallet.syncCapsules(slots + 1);
        assertEq(wallet.trackedCapsules().length, slots);
        assertEq(wallet.capsuleBacklog(), 0);
    }

    uint256 internal fillerWallets;

    /// @dev Publishes `count` single-observer delay capsules for sweeps, which match no payment, from fresh
    ///      registered wallets other than B and C. Returns the latest expiry among them.
    function _publishFillers(uint256 count, uint64 life) internal returns (uint64 lastExpiry) {
        uint256 perWallet = bulletin.MAX_PUBLISH_PER_DAY();
        uint256 published;
        while (published < count) {
            PolicyWallet publisher =
                _newWallet(makeAddr(string(abi.encode("filler", fillerWallets++))), makeAddr("fillerAgent"));
            for (uint256 n = 0; n < perWallet && published < count; ++n) {
                uint256 id = _publish(
                    publisher, publisher.owner(), uint8(CapsuleAction.SWEEP), Tiers.L2, Flags.ENCODED_CONTENT, life
                );
                lastExpiry = bulletin.getCapsule(id).expiry;
                ++published;
            }
        }
    }

    function _publish(
        PolicyWallet from,
        address fromOwner,
        uint8 action,
        uint8 restriction,
        uint16 features,
        uint64 life
    ) internal returns (uint256) {
        return _publishOn(from, fromOwner, CHANNEL_MEMORY, action, restriction, features, life);
    }

    function _publishOn(
        PolicyWallet from,
        address fromOwner,
        uint8 channel,
        uint8 action,
        uint8 restriction,
        uint16 features,
        uint64 life
    ) internal returns (uint256) {
        vm.prank(fromOwner);
        return from.publishCapsule(FAMILY_MEMORY, channel, features, action, restriction, life, 1);
    }
}
