// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {PolicyWallet} from "../src/PolicyWallet.sol";
import {Mandate} from "../src/lib/AgentVaxTypes.sol";
import {MandateRules} from "../src/lib/MandateRules.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {Payee} from "../src/wallet/WalletTypes.sol";

contract MandateAuthorityTest is Base {

    function test_Mandate_SetByOwner_EmitsHash() public {
        PolicyWallet fresh = _newWallet(owner, agent);
        Mandate memory m = defaultMandate();
        bytes32 missionHash = keccak256(bytes(MISSION));
        bytes32 expected = keccak256(abi.encode(missionHash, m));

        vm.expectEmit(true, true, false, true, address(fresh));
        emit MandateSet(expected, missionHash);
        vm.prank(owner);
        fresh.setMandate(MISSION, m);

        (bytes32 storedMission, bytes32 storedMandate) = fresh.mandateHashes();
        assertEq(storedMission, missionHash);
        assertEq(storedMandate, expected);
        assertTrue(fresh.mandateSet());
        assertEq(fresh.mandate().c1, m.c1);
    }

    function test_Mandate_AgentCannotModify() public {
        (, bytes32 before) = wallet.mandateHashes();
        Mandate memory looser = defaultMandate();
        looser.c1 = 1900 * USD;
        Mandate memory tighter = defaultMandate();
        tighter.c1 = 100 * USD;

        vm.startPrank(agent);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.setMandate(MISSION, tighter);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.proposeMandate(MISSION, looser);
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.proposeAddPayee(keccak256("attacker"), makeAddr("attacker"));
        vm.expectRevert(IPolicyWalletErrors.NotOwner.selector);
        wallet.proposeUnfreeze();
        vm.stopPrank();

        (, bytes32 afterwards) = wallet.mandateHashes();
        assertEq(afterwards, before);
        assertEq(wallet.mandate().c1, 500 * USD);
        assertEq(wallet.changeCount(), 3, "only the three setup payee changes exist");
    }

    function test_Mandate_Expiry_BlocksPayments() public {
        _fund(5000 * USD);
        vm.warp(wallet.mandate().expiry);
        uint256 balanceBefore = token.balanceOf(address(wallet));
        // The intent and attestation are built at expiry, so only the mandate's expiry can block them.
        Signed memory s = _signedPayment(hostingId, 100 * USD);
        vm.expectRevert(IPolicyWalletErrors.MandateExpired.selector);
        _send(s);
        assertEq(token.balanceOf(address(wallet)), balanceBefore);
    }

    function test_NewAddressForKnownPayee_IsNewPayee() public {
        address newAddress = makeAddr("landlord-new-account");
        vm.prank(owner);
        uint256 changeId = wallet.proposeAddPayee(keccak256("landlord"), newAddress);

        // Until Λ passes the new address has no payee id at all.
        uint32 nextId = uint32(wallet.payeeCount() + 1);
        _fund(5000 * USD);
        Signed memory s = _signedPayment(nextId, 100 * USD);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.UnknownPayee.selector, nextId));
        _send(s);

        vm.warp(block.timestamp + wallet.mandate().looseningDelay);
        vm.prank(owner);
        wallet.applyChange(changeId);

        Payee memory oldPayee = wallet.getPayee(landlordId);
        Payee memory newPayee = wallet.getPayee(nextId);
        assertTrue(nextId != landlordId);
        assertEq(newPayee.identityHash, oldPayee.identityHash);
        assertEq(newPayee.account, newAddress);
        assertEq(newPayee.paidCount, 0);
        assertEq(oldPayee.account, landlord, "the known payee keeps its address");
        assertTrue(oldPayee.active);
    }

    /// @dev Reads the compiled ABI, so that a function added later cannot slip past a list of guessed names.
    ///      Every external function must be on the list below, and none may take the shape of a
    ///      generic call (a target address with call data, or a batch of call data). Then a few such calls
    ///      are tried directly, showing that there is no fallback that would accept them either.
    function test_NoArbitraryCall() public {
        // The shape check recognises the usual generic-call signatures and passes the signature-only `bytes`.
        assertTrue(_hasGenericCallShape("execute(address,uint256,bytes)"));
        assertTrue(_hasGenericCallShape("call(address,bytes)"));
        assertTrue(_hasGenericCallShape("multicall(bytes[])"));
        assertFalse(_hasGenericCallShape("submit((uint8),(bytes32,uint8),bytes)"));
        assertFalse(_hasGenericCallShape("proposeAddPayee(bytes32,address)"));

        string memory artifact = vm.readFile("out/PolicyWallet.sol/PolicyWallet.json");
        string[] memory exposed = vm.parseJsonKeys(artifact, ".methodIdentifiers");
        string[] memory allowed = _reviewedFunctions();
        assertEq(exposed.length, allowed.length, "the external interface changed: review it and update the list");
        for (uint256 i = 0; i < exposed.length; ++i) {
            assertTrue(_contains(allowed, exposed[i]), string.concat("not on the reviewed list: ", exposed[i]));
            assertFalse(_hasGenericCallShape(exposed[i]), string.concat("generic call shape: ", exposed[i]));
        }

        _fund(5000 * USD);
        bytes memory transferCall = abi.encodeCall(token.transfer, (agent, 5000 * USD));
        bytes[] memory attempts = new bytes[](6);
        attempts[0] = abi.encodeWithSignature("execute(address,uint256,bytes)", address(token), 0, transferCall);
        attempts[1] = abi.encodeWithSignature("call(address,bytes)", address(token), transferCall);
        attempts[2] = abi.encodeWithSignature("executeCall(address,uint256,bytes)", address(token), 0, transferCall);
        attempts[3] = abi.encodeWithSignature("multicall(bytes[])", new bytes[](0));
        attempts[4] = abi.encodeWithSignature("delegatecall(address,bytes)", address(token), transferCall);
        attempts[5] = transferCall;

        address[2] memory callers = [agent, owner];
        for (uint256 c = 0; c < callers.length; ++c) {
            for (uint256 i = 0; i < attempts.length; ++i) {
                vm.prank(callers[c]);
                (bool ok,) = address(wallet).call(attempts[i]);
                assertFalse(ok, "the wallet must not accept an arbitrary call");
            }
        }
        assertEq(token.balanceOf(address(wallet)), 5000 * USD);
        assertEq(token.balanceOf(agent), 0);
    }

    // ------------------------------------------------------------------ tightening order

    function test_SetMandate_EachLooserField_Reverts() public {
        for (uint256 field = 0; field < FIELD_COUNT; ++field) {
            Mandate memory m = _moved(defaultMandateAtSetup(), field, false);
            vm.prank(owner);
            vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
            wallet.setMandate(MISSION, m);
        }
    }

    function test_SetMandate_EachTighterField_IsImmediate() public {
        for (uint256 field = 0; field < FIELD_COUNT; ++field) {
            Mandate memory m = _moved(wallet.mandate(), field, true);
            _setMandateAs(owner, m);
            (, bytes32 stored) = wallet.mandateHashes();
            assertEq(stored, keccak256(abi.encode(keccak256(bytes(MISSION)), m)));
        }
    }

    function test_SetMandate_MixedUpdate_Reverts() public {
        Mandate memory m = defaultMandateAtSetup();
        m.c1 = 100 * USD; // tighter
        m.reserve = 500 * USD; // looser
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
        wallet.setMandate(MISSION, m);
    }

    function test_SetMandate_ChannelSwap_IsNotTightening() public {
        Mandate memory narrow = defaultMandateAtSetup();
        narrow.channelProfile = 0x03; // owner chat and web page
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
        wallet.setMandate(MISSION, narrow);

        // Set a narrow profile through the time-lock, then try to swap one channel for another directly.
        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, narrow);
        vm.warp(block.timestamp + wallet.mandate().looseningDelay);
        vm.prank(owner);
        wallet.applyChange(changeId);

        Mandate memory swapped = wallet.mandate();
        swapped.channelProfile = 0x05; // owner chat and message: same size, not a superset
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.LooseningNeedsTimelock.selector);
        wallet.setMandate(MISSION, swapped);

        Mandate memory superset = wallet.mandate();
        superset.channelProfile = 0x07;
        _setMandateAs(owner, superset);
        assertEq(wallet.mandate().channelProfile, 0x07);
    }

    function test_SetMandate_Malformed_Reverts() public {
        Mandate memory m = defaultMandateAtSetup();
        m.c1 = m.c2 + 1;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.InvalidMandate.selector);
        wallet.setMandate(MISSION, m);
    }

    function test_ProposeMandate_LooserAppliesOnlyAfterLambda() public {
        Mandate memory looser = defaultMandateAtSetup();
        looser.c1 = 800 * USD;
        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, looser);
        uint64 ready = wallet.changeReadyAt(changeId);
        assertEq(ready, block.timestamp + 24 hours);

        vm.warp(ready - 1);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, changeId, ready));
        wallet.applyChange(changeId);

        vm.warp(ready);
        vm.prank(owner);
        wallet.applyChange(changeId);
        assertEq(wallet.mandate().c1, 800 * USD);
    }

    function test_PendingChange_LongerLambdaDelaysIt_ShorterNeverAdvancesIt() public {
        vm.prank(owner);
        uint256 changeId = wallet.proposeAddPayee(keccak256("supplier"), makeAddr("supplier"));
        uint64 original = wallet.changeReadyAt(changeId);

        Mandate memory longer = wallet.mandate();
        longer.looseningDelay = 48 hours;
        _setMandateAs(owner, longer);
        assertEq(wallet.changeReadyAt(changeId), original + 24 hours, "lengthening Lambda delays pending changes");

        vm.warp(original);
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyWalletErrors.ChangeNotReady.selector, changeId, original + 24 hours)
        );
        wallet.applyChange(changeId);
    }

    // ------------------------------------------------------------------ stale proposals

    function test_PendingMandateChange_AfterTightening_CannotApply() public {
        Mandate memory raiseA = wallet.mandate();
        raiseA.allowanceMax = 20;
        vm.prank(owner);
        uint256 changeId = wallet.proposeMandate(MISSION, raiseA);

        Mandate memory tighter = wallet.mandate();
        tighter.c1 = 400 * USD;
        tighter.reserve = 800 * USD;
        _setMandateAs(owner, tighter);
        (, bytes32 tightened) = wallet.mandateHashes();

        // The proposal is a whole mandate built on the old one. Applying it would undo the tightening.
        vm.warp(block.timestamp + wallet.mandate().looseningDelay);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, changeId));
        wallet.applyChange(changeId);
        (, bytes32 afterwards) = wallet.mandateHashes();
        assertEq(afterwards, tightened);
        assertEq(wallet.mandate().c1, 400 * USD);
        assertEq(wallet.mandate().reserve, 800 * USD);

        // Proposed again on top of the tightened mandate, it applies after Λ and keeps the tightening.
        Mandate memory again = wallet.mandate();
        again.allowanceMax = 20;
        vm.prank(owner);
        uint256 second = wallet.proposeMandate(MISSION, again);
        vm.warp(block.timestamp + wallet.mandate().looseningDelay);
        vm.prank(owner);
        wallet.applyChange(second);
        assertEq(wallet.mandate().allowanceMax, 20);
        assertEq(wallet.mandate().c1, 400 * USD);
        assertEq(wallet.mandate().reserve, 800 * USD);
    }

    function test_StaleUnfreezeProposal_AfterRefreeze_CannotApply() public {
        vm.prank(owner);
        wallet.freeze();
        vm.prank(owner);
        uint256 changeId = wallet.proposeUnfreeze();

        vm.warp(block.timestamp + 1 hours);
        vm.prank(owner);
        wallet.freeze();

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, changeId));
        wallet.applyChange(changeId);
        assertTrue(wallet.frozen());
    }

    function test_StalePayeeProposal_AfterRemovePayee_CannotApply() public {
        vm.prank(owner);
        uint256 changeId = wallet.proposeAddPayee(keccak256("supplier"), makeAddr("supplier"));
        vm.prank(owner);
        wallet.removePayee(hostingId);

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, changeId));
        wallet.applyChange(changeId);
        assertEq(wallet.payeeCount(), 3);
    }

    function test_StaleAgentProposal_AfterRevokeAgent_CannotApply() public {
        vm.prank(owner);
        uint256 changeId = wallet.proposeAgent(makeAddr("newAgent"));
        vm.prank(owner);
        wallet.revokeAgent();

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, changeId));
        wallet.applyChange(changeId);
        assertEq(wallet.agent(), address(0));
    }

    function test_Freeze_InvalidatesEveryPendingLoosening() public {
        vm.startPrank(owner);
        uint256 addPayee = wallet.proposeAddPayee(keccak256("supplier"), makeAddr("supplier"));
        Mandate memory looser = wallet.mandate();
        looser.c1 = 800 * USD;
        uint256 raise = wallet.proposeMandate(MISSION, looser);
        uint256 newGuardian = wallet.proposeGuardian(makeAddr("newGuardian"));
        wallet.freeze();
        uint256 unfreeze = wallet.proposeUnfreeze();
        vm.warp(block.timestamp + 24 hours);

        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, addPayee));
        wallet.applyChange(addPayee);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, raise));
        wallet.applyChange(raise);
        vm.expectRevert(abi.encodeWithSelector(IPolicyWalletErrors.ProposalStale.selector, newGuardian));
        wallet.applyChange(newGuardian);
        // A proposal made after the freeze is not stale.
        wallet.applyChange(unfreeze);
        vm.stopPrank();
        assertFalse(wallet.frozen());
        assertEq(wallet.payeeCount(), 3);
        assertEq(wallet.mandate().c1, 500 * USD);
        assertEq(wallet.guardian(), guardian);
    }

    // ------------------------------------------------------------------ keys and bounds

    function test_Keys_MustBeDistinct_AtDeployment() public {
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        new PolicyWallet(owner, owner, guardian, token, vault, bulletin);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        new PolicyWallet(owner, agent, owner, token, vault, bulletin);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        new PolicyWallet(owner, agent, agent, token, vault, bulletin);
    }

    function test_Keys_MustBeDistinct_WhenChanged() public {
        vm.startPrank(owner);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        wallet.proposeAgent(guardian);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        wallet.proposeAgent(owner);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        wallet.proposeGuardian(agent);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        wallet.proposeGuardian(owner);

        // Two proposals that are each fine alone cannot together make one key both agent and guardian.
        address shared = makeAddr("shared");
        uint256 agentChange = wallet.proposeAgent(shared);
        uint256 guardianChange = wallet.proposeGuardian(shared);
        vm.warp(block.timestamp + 24 hours);
        wallet.applyChange(agentChange);
        vm.expectRevert(IPolicyWalletErrors.KeysNotDistinct.selector);
        wallet.applyChange(guardianChange);
        vm.stopPrank();
        assertEq(wallet.agent(), shared);
        assertEq(wallet.guardian(), guardian);
    }

    function test_SetMandate_DelaysAboveBound_Rejected() public {
        Mandate memory m = wallet.mandate();
        m.delay = MandateRules.MAX_DELAY + 1;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.InvalidMandate.selector);
        wallet.setMandate(MISSION, m);

        m = wallet.mandate();
        m.looseningDelay = MandateRules.MAX_LOOSENING_DELAY + 1;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.InvalidMandate.selector);
        wallet.setMandate(MISSION, m);

        m = wallet.mandate();
        m.pressureHold = MandateRules.MAX_PRESSURE_HOLD + 1;
        vm.prank(owner);
        vm.expectRevert(IPolicyWalletErrors.InvalidMandate.selector);
        wallet.setMandate(MISSION, m);

        // At the bounds the tightening is accepted at once.
        m = wallet.mandate();
        m.delay = MandateRules.MAX_DELAY;
        m.looseningDelay = MandateRules.MAX_LOOSENING_DELAY;
        m.pressureHold = MandateRules.MAX_PRESSURE_HOLD;
        _setMandateAs(owner, m);
        assertEq(wallet.mandate().looseningDelay, MandateRules.MAX_LOOSENING_DELAY);
    }

    // ------------------------------------------------------------------ helpers

    /// @dev Every external function of PolicyWallet: none forwards a call chosen by its caller.
    ///      `submit` and `submitSchedule` take `bytes`, but only as the guardian's signature.
    function _reviewedFunctions() internal pure returns (string[] memory f) {
        string memory intentT = "(uint8,uint32,uint256,uint64,bytes32,uint256)";
        string memory attT = "(bytes32,uint8,uint8,uint16,uint64)";
        string memory termsT = "(uint64,uint64,uint32)";
        string memory mandateT = "(uint256,uint256,uint256,uint256,uint64,uint64,uint64,uint64,uint64,uint64,uint32,"
            "uint8,uint8,uint8,uint8,uint8,uint8,uint256,uint256,uint256,uint256)";
        f = new string[](78);
        uint256 k;
        // constants and immutables
        f[k++] = "ALLOWANCE_UNIT()";
        f[k++] = "ATTESTATION_TYPEHASH()";
        f[k++] = "AUTO_SYNC_CHUNK()";
        f[k++] = "EIP712_NAME()";
        f[k++] = "INTENT_TYPEHASH()";
        f[k++] = "MAX_AGENT_OBLIGATIONS()";
        f[k++] = "MAX_OBLIGATIONS()";
        f[k++] = "MAX_SCHEDULES()";
        f[k++] = "MAX_SPILLED_CAPSULES()";
        f[k++] = "MAX_TRACKED_CAPSULES()";
        f[k++] = "MIN_SCHEDULE_PERIOD()";
        f[k++] = "SCHEDULE_TERMS_TYPEHASH()";
        f[k++] = "VERSION()";
        f[k++] = "owner()";
        f[k++] = "token()";
        f[k++] = "vault()";
        f[k++] = "bulletin()";
        // agent
        f[k++] = string.concat("submit(", intentT, ",", attT, ",bytes)");
        f[k++] = string.concat("submitSchedule(", intentT, ",", termsT, ",", attT, ",bytes)");
        f[k++] = "addObligation(uint32,uint256,uint64)";
        f[k++] = "recordPayeeChangeRequest(bytes32,address,uint16)";
        // anyone
        f[k++] = "executePending(uint256)";
        f[k++] = "runSchedule(uint64)";
        f[k++] = "syncCapsules(uint256)";
        // owner, immediate
        f[k++] = string.concat("setMandate(string,", mandateT, ")");
        f[k++] = "freeze()";
        f[k++] = "removePayee(uint32)";
        f[k++] = "revokeAgent()";
        f[k++] = "approve(uint256)";
        f[k++] = "cancel(uint256)";
        f[k++] = "extendHold(uint256,uint64)";
        f[k++] = "cancelSchedule(uint64)";
        f[k++] = "confirmAttack()";
        f[k++] = "dismissCapsule(uint256)";
        f[k++] = "publishCapsule(uint8,uint8,uint16,uint8,uint8,uint64,uint32)";
        f[k++] = "attestCapsule(uint256)";
        f[k++] = "cancelChange(uint256)";
        // owner, through Λ
        f[k++] = "proposeAddPayee(bytes32,address)";
        f[k++] = string.concat("proposeMandate(string,", mandateT, ")");
        f[k++] = "proposeRemoveObligation(uint64)";
        f[k++] = "proposeAgent(address)";
        f[k++] = "proposeGuardian(address)";
        f[k++] = "proposeUnfreeze()";
        f[k++] = "applyChange(uint256)";
        // views
        f[k++] = "agent()";
        f[k++] = "agentObligationCount()";
        f[k++] = "allowance()";
        f[k++] = "capsuleBacklog()";
        f[k++] = "capsuleCursor()";
        f[k++] = "capsuleDismissed(uint256)";
        f[k++] = "changeCount()";
        f[k++] = "changeReadyAt(uint256)";
        f[k++] = "discretionary(uint64)";
        f[k++] = "eip712Domain()";
        f[k++] = "frozen()";
        f[k++] = "getChange(uint256)";
        f[k++] = "getItem(uint256)";
        f[k++] = "getObligation(uint64)";
        f[k++] = "getPayee(uint32)";
        f[k++] = "getSchedule(uint64)";
        f[k++] = "guardian()";
        f[k++] = string.concat("hashAttestation(", attT, ")");
        f[k++] = string.concat("hashIntent(", intentT, ")");
        f[k++] = string.concat("hashScheduleTerms(", termsT, ")");
        f[k++] = "intentUsed(bytes32)";
        f[k++] = "itemCount()";
        f[k++] = "itemReadyAt(uint256)";
        f[k++] = "mandate()";
        f[k++] = "mandateHashes()";
        f[k++] = "mandateSet()";
        f[k++] = "matchCapsules(uint8,uint16)";
        f[k++] = "nonce()";
        f[k++] = "openObligationIds()";
        f[k++] = "payeeCount()";
        f[k++] = "scheduleCounts()";
        f[k++] = "spentOnDay(uint256)";
        f[k++] = "toppedUpOnDay(uint256)";
        f[k++] = "trackedCapsules()";
        assert(k == f.length);
    }

    function _contains(string[] memory list, string memory item) internal pure returns (bool) {
        bytes32 h = keccak256(bytes(item));
        for (uint256 i = 0; i < list.length; ++i) {
            if (keccak256(bytes(list[i])) == h) return true;
        }
        return false;
    }

    /// @dev True if the signature takes dynamic `bytes` (or `bytes[]`) together with an address, or takes a
    ///      `bytes[]` batch: the shapes of execute(target, value, data), call(target, data) and multicall.
    function _hasGenericCallShape(string memory signature) internal pure returns (bool) {
        bytes memory s = bytes(signature);
        bool takesAddress = _indexOf(s, "address", 0) != type(uint256).max;
        uint256 at = 0;
        while (true) {
            uint256 i = _indexOf(s, "bytes", at);
            if (i == type(uint256).max) return false;
            uint256 next = i + 5;
            bool fixedSize = next < s.length && s[next] >= "0" && s[next] <= "9";
            if (!fixedSize) {
                bool isArray = next < s.length && s[next] == "[";
                if (takesAddress || isArray) return true;
            }
            at = next;
        }
        return false;
    }

    function _indexOf(bytes memory s, bytes memory needle, uint256 from) internal pure returns (uint256) {
        if (s.length < needle.length) return type(uint256).max;
        for (uint256 i = from; i + needle.length <= s.length; ++i) {
            bool same = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (s[i + j] != needle[j]) {
                    same = false;
                    break;
                }
            }
            if (same) return i;
        }
        return type(uint256).max;
    }

    uint256 internal constant FIELD_COUNT = 21;

    /// @dev The mandate as installed in setUp (its expiry is relative to START).
    function defaultMandateAtSetup() internal view returns (Mandate memory) {
        return wallet.mandate();
    }

    /// @dev Moves one field one step in its tightening (`tighter`) or loosening direction.
    function _moved(Mandate memory m, uint256 field, bool tighter) internal pure returns (Mandate memory) {
        if (field == 0) {
            m.reserve = tighter ? m.reserve + 1 : m.reserve - 1;
        } else if (field == 1) {
            m.c1 = tighter ? m.c1 - 1 : m.c1 + 1;
        } else if (field == 2) {
            m.d1 = tighter ? m.d1 - 1 : m.d1 + 1;
        } else if (field == 3) {
            m.c2 = tighter ? m.c2 - 1 : m.c2 + 1;
        } else if (field == 4) {
            m.delay = tighter ? m.delay + 1 : m.delay - 1;
        } else if (field == 5) {
            m.looseningDelay = tighter ? m.looseningDelay + 1 : m.looseningDelay - 1;
        } else if (field == 6) {
            m.pressureHold = tighter ? m.pressureHold + 1 : m.pressureHold - 1;
        } else if (field == 7) {
            m.refillPeriod = tighter ? m.refillPeriod + 1 : m.refillPeriod - 1;
        } else if (field == 8) {
            m.horizon = tighter ? m.horizon + 1 : m.horizon - 1;
        } else if (field == 9) {
            m.expiry = tighter ? m.expiry - 1 : m.expiry + 1;
        } else if (field == 10) {
            m.allowanceMax = tighter ? m.allowanceMax - 1 : m.allowanceMax + 1;
        } else if (field == 11) {
            m.channelProfile = tighter ? m.channelProfile : m.channelProfile & 0x0F;
        } else if (field == 12) {
            m.chargeExternal = tighter ? m.chargeExternal + 1 : m.chargeExternal - 1;
        } else if (field == 13) {
            m.chargeOverHalfD = tighter ? m.chargeOverHalfD + 1 : m.chargeOverHalfD - 1;
        } else if (field == 14) {
            m.chargeAnomaly = tighter ? m.chargeAnomaly + 1 : m.chargeAnomaly - 1;
        } else if (field == 15) {
            m.chargeFirstPayment = tighter ? m.chargeFirstPayment + 1 : m.chargeFirstPayment - 1;
        } else if (field == 16) {
            m.chargePartialCapsule = tighter ? m.chargePartialCapsule + 1 : m.chargePartialCapsule - 1;
        } else if (field == 17) {
            m.feeTopUpCap = tighter ? m.feeTopUpCap - 1 : m.feeTopUpCap + 1;
        } else if (field == 18) {
            m.feeDailyBudget = tighter ? m.feeDailyBudget - 1 : m.feeDailyBudget + 1;
        } else if (field == 19) {
            m.agentBalanceFloor = tighter ? m.agentBalanceFloor - 1 : m.agentBalanceFloor + 1;
        } else {
            m.nativeReserve = tighter ? m.nativeReserve + 1 : m.nativeReserve - 1;
        }
        return m;
    }
}
