// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {MockUSD} from "../src/MockUSD.sol";
import {SavingsVault} from "../src/SavingsVault.sol";
import {ThreatBulletin} from "../src/ThreatBulletin.sol";
import {PolicyWallet} from "../src/PolicyWallet.sol";
import {Attestation, Flags, Intent, Mandate, ScheduleTerms, Task, Tiers} from "../src/lib/AgentVaxTypes.sol";
import {IPolicyWalletEvents} from "../src/interfaces/IPolicyWalletEvents.sol";
import {IPolicyWalletErrors} from "../src/interfaces/IPolicyWalletErrors.sol";
import {Item, ItemStatus} from "../src/wallet/WalletTypes.sol";

/// @notice Shared setup: one wallet with the default mandate and three approved payees
///         (landlord, hosting provider, software vendor) added through the real Λ time-lock.
abstract contract Base is Test, IPolicyWalletEvents {
    uint256 internal constant USD = 1e6;
    uint256 internal constant START = 1_767_225_600; // 1 January 2026, 00:00 UTC
    string internal constant MISSION =
        "Keep 600 in reserve. Pay my landlord and my approved suppliers on time. Pay approved payees up to 500 without asking. Ask me about anyone new.";

    MockUSD internal token;
    SavingsVault internal vault;
    ThreatBulletin internal bulletin;
    PolicyWallet internal wallet;

    address internal owner;
    address internal agent;
    address internal guardian;
    uint256 internal guardianKey;
    address internal registrar;
    address internal aggregator;

    address internal landlord;
    address internal hosting;
    address internal software;
    uint32 internal landlordId;
    uint32 internal hostingId;
    uint32 internal softwareId;

    function setUp() public virtual {
        vm.warp(START);
        owner = makeAddr("owner");
        agent = makeAddr("agent");
        (guardian, guardianKey) = makeAddrAndKey("guardian");
        registrar = makeAddr("registrar");
        aggregator = makeAddr("aggregator");
        landlord = makeAddr("landlord");
        hosting = makeAddr("hosting");
        software = makeAddr("software");

        token = new MockUSD();
        vault = new SavingsVault(token);
        bulletin = new ThreatBulletin(registrar, aggregator);
        wallet = _newWallet(owner, agent);

        vm.prank(owner);
        wallet.setMandate(MISSION, defaultMandate());

        bytes32[] memory ids = new bytes32[](3);
        address[] memory accounts = new address[](3);
        ids[0] = keccak256("landlord");
        ids[1] = keccak256("hosting");
        ids[2] = keccak256("software");
        accounts[0] = landlord;
        accounts[1] = hosting;
        accounts[2] = software;
        uint32[] memory added = _addPayees(wallet, owner, ids, accounts);
        landlordId = added[0];
        hostingId = added[1];
        softwareId = added[2];

        vm.deal(address(wallet), 1 ether);
    }

    // ------------------------------------------------------------------ configuration

    /// @dev Default profile: R 600, c1 500, d1 1000, c2 2000, Δ 1 h, Λ 24 h, Π 60 min, A 10 per 24 h,
    ///      H 30 days, expiry 90 days, all channels, charges 2, 2, 3, 3, 5.
    function defaultMandate() internal view returns (Mandate memory m) {
        m.reserve = 600 * USD;
        m.c1 = 500 * USD;
        m.d1 = 1000 * USD;
        m.c2 = 2000 * USD;
        m.delay = 1 hours;
        m.looseningDelay = 24 hours;
        m.pressureHold = 60 minutes;
        m.refillPeriod = 24 hours;
        m.horizon = 30 days;
        m.expiry = uint64(block.timestamp + 90 days);
        m.allowanceMax = 10;
        m.channelProfile = 0x1F;
        m.chargeExternal = 2;
        m.chargeOverHalfD = 2;
        m.chargeAnomaly = 3;
        m.chargeFirstPayment = 3;
        m.chargePartialCapsule = 5;
        m.feeTopUpCap = 0.01 ether;
        m.feeDailyBudget = 0.03 ether;
        m.agentBalanceFloor = 0.02 ether;
        m.nativeReserve = 0.1 ether;
    }

    function _newWallet(address walletOwner, address walletAgent) internal returns (PolicyWallet w) {
        w = new PolicyWallet(walletOwner, walletAgent, guardian, token, vault, bulletin);
        vm.prank(registrar);
        bulletin.setRegistered(address(w), true);
    }

    /// @dev Proposes every payee, waits Λ once, then applies them all. The real time-lock, no shortcut.
    function _addPayees(PolicyWallet w, address walletOwner, bytes32[] memory ids, address[] memory accounts)
        internal
        returns (uint32[] memory payeeIds)
    {
        uint256[] memory changes = new uint256[](ids.length);
        vm.startPrank(walletOwner);
        for (uint256 i = 0; i < ids.length; ++i) {
            changes[i] = w.proposeAddPayee(ids[i], accounts[i]);
        }
        vm.warp(block.timestamp + w.mandate().looseningDelay);
        payeeIds = new uint32[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            w.applyChange(changes[i]);
            payeeIds[i] = uint32(w.payeeCount());
        }
        vm.stopPrank();
    }

    function _fund(uint256 amount) internal {
        token.mint(address(wallet), amount);
    }

    // ------------------------------------------------------------------ intents

    function _intent(Task task, uint32 payeeId, uint256 amount) internal view returns (Intent memory i) {
        i.task = uint8(task);
        i.payeeId = payeeId;
        i.amount = amount;
        i.purposeHash = keccak256("purpose");
        i.nonce = wallet.nonce();
    }

    function _payment(uint32 payeeId, uint256 amount) internal view returns (Intent memory) {
        return _intent(Task.PAYMENT, payeeId, amount);
    }

    function _attestation(Intent memory i, uint8 band, uint8 source, uint16 flags)
        internal
        view
        returns (Attestation memory a)
    {
        a.intentHash = wallet.hashIntent(i);
        a.band = band;
        a.source = source;
        a.flags = flags;
        a.validUntil = uint64(block.timestamp + 10 minutes);
    }

    function _sign(Attestation memory a, uint256 key) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, wallet.hashAttestation(a));
        return abi.encodePacked(r, s, v);
    }

    /// @dev An intent with its guardian attestation and signature, ready to send. Building it makes view calls,
    ///      so build it before `vm.expectRevert` and send it after.
    struct Signed {
        Intent intent;
        Attestation att;
        bytes sig;
    }

    function _signed(Intent memory i, uint8 band, uint8 source, uint16 flags) internal view returns (Signed memory s) {
        s.intent = i;
        s.att = _attestation(i, band, source, flags);
        s.sig = _sign(s.att, guardianKey);
    }

    function _signedPayment(uint32 payeeId, uint256 amount) internal view returns (Signed memory) {
        return _signed(_payment(payeeId, amount), 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
    }

    function _send(Signed memory s) internal returns (uint256) {
        vm.prank(agent);
        return wallet.submit(s.intent, s.att, s.sig);
    }

    /// @dev Submits `i` as the agent with a guardian attestation of the given band, source and flags.
    function _submit(Intent memory i, uint8 band, uint8 source, uint16 flags) internal returns (uint256 itemId) {
        Attestation memory a = _attestation(i, band, source, flags);
        bytes memory sig = _sign(a, guardianKey);
        vm.prank(agent);
        return wallet.submit(i, a, sig);
    }

    /// @dev A clean request: band low, owner instruction, known payee identity.
    function _submitClean(Intent memory i) internal returns (uint256) {
        return _submit(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
    }

    function _pay(uint32 payeeId, uint256 amount) internal returns (uint256) {
        return _submitClean(_payment(payeeId, amount));
    }

    function _scheduleTerms(uint64 period, uint64 firstDue, uint32 maxRuns)
        internal
        pure
        returns (ScheduleTerms memory t)
    {
        t.period = period;
        t.firstDue = firstDue;
        t.maxRuns = maxRuns;
    }

    function _submitSchedule(uint32 payeeId, uint256 amount, ScheduleTerms memory terms)
        internal
        returns (uint256 itemId)
    {
        Intent memory i = _intent(Task.SCHEDULE_CREATE, payeeId, amount);
        i.purposeHash = wallet.hashScheduleTerms(terms);
        Attestation memory a = _attestation(i, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
        bytes memory sig = _sign(a, guardianKey);
        vm.prank(agent);
        return wallet.submitSchedule(i, terms, a, sig);
    }

    function _addObligation(uint32 payeeId, uint256 amount, uint64 due) internal returns (uint64) {
        vm.prank(agent);
        return wallet.addObligation(payeeId, amount, due);
    }

    // ------------------------------------------------------------------ inspection

    /// @dev The (tier, decidingCheck, capsuleId) of the last `Decision` event in `logs`.
    function _lastDecision(Vm.Log[] memory logs)
        internal
        pure
        returns (uint8 tier, uint8 check, uint256 capsuleId)
    {
        bytes32 topic = Decision.selector;
        bool found;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == topic) {
                (tier, check, capsuleId) = abi.decode(logs[i].data, (uint8, uint8, uint256));
                found = true;
            }
        }
        require(found, "no Decision event");
    }

    function _status(uint256 itemId) internal view returns (ItemStatus) {
        return wallet.getItem(itemId).status;
    }

    function _setMandateAs(address caller, Mandate memory m) internal {
        vm.prank(caller);
        wallet.setMandate(MISSION, m);
    }
}
