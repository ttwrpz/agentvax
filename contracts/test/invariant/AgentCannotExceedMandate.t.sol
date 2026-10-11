// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Base} from "../Base.t.sol";
import {MockUSD} from "../../src/MockUSD.sol";
import {SavingsVault} from "../../src/SavingsVault.sol";
import {PolicyWallet} from "../../src/PolicyWallet.sol";
import {Attestation, Flags, Intent, Mandate, ScheduleTerms, Task, Tiers} from "../../src/lib/AgentVaxTypes.sol";
import {Item, ItemStatus, Obligation, Payee} from "../../src/wallet/WalletTypes.sol";

/// @notice Drives the agent key and the guardian key with arbitrary inputs, plus the calls anyone may make
///         and the passage of time. The wallet's owner never acts. Every call is checked against the mandate
///         by ghost accounting split by asset. A breach is recorded, not reverted, because the
///         invariant runner ignores reverting handler calls.
contract MandateHandler is Test {
    bytes32 private constant TRANSFER_TOPIC = keccak256("Transfer(address,address,uint256)");
    uint256 private constant USD = 1e6;
    string private constant MISSION = "fuzzed";

    PolicyWallet public immutable wallet;
    MockUSD public immutable token;
    SavingsVault public immutable vault;
    PolicyWallet public immutable publisher;
    address public immutable publisherOwner;
    address public immutable agent;
    address public immutable guardian;
    uint256 private immutable guardianKey;

    /// @dev The mandate as installed at setup. The owner never changes it afterwards.
    Mandate private m;
    /// @dev Accounts of the payees that were active at setup.
    mapping(address account => bool) public isActivePayee;

    /// @notice MockUSD paid at L1 (same transaction, or a schedule run) on each day index.
    mapping(uint256 day => uint256) public ghostL1ByDay;
    /// @notice Native token sent by fee top-ups on each day index.
    mapping(uint256 day => uint256) public ghostNativeByDay;
    /// @notice Every MockUSD unit that left the wallet.
    uint256 public ghostTokenOut;
    /// @notice Every native unit that left the wallet.
    uint256 public ghostNativeOut;

    /// @notice Number of breaches seen, and the first one.
    uint256 public breaches;
    string public firstBreach;

    /// @notice Fuzzed handler calls that completed.
    uint256 public calls;
    /// @notice How often value actually moved, to show the run exercised the value paths.
    uint256 public l1Payments;
    uint256 public pendingExecutions;
    uint256 public scheduleRuns;
    uint256 public sweeps;
    uint256 public topUps;

    enum Path {
        SUBMIT,
        EXECUTE_PENDING,
        RUN_SCHEDULE,
        OTHER
    }

    struct Snapshot {
        uint256 tokenBalance;
        uint256 nativeBalance;
        uint256 agentNative;
        uint256 discretionary; // D with no obligation left out, for sweeps
        uint256 discretionaryForPayment; // D leaving out the obligation the payment settles, if any
        uint256 allowance;
        uint256 day;
    }

    /// @dev What the mandate's charges say an L1 payment must cost at least, known before the call.
    struct PaymentFacts {
        bool payeeKnown;
        uint32 paidCount;
        uint256 maxPaid;
    }

    bytes32 private constant ALLOWANCE_CHARGED_TOPIC = keccak256("AllowanceCharged(bytes32,uint256,uint256)");
    uint256 private constant ALLOWANCE_UNIT = 1e6;

    modifier counted() {
        ++calls;
        _;
    }

    constructor(PolicyWallet wallet_, uint256 guardianKey_, PolicyWallet publisher_, address publisherOwner_) {
        wallet = wallet_;
        token = MockUSD(address(wallet_.token()));
        vault = SavingsVault(address(wallet_.vault()));
        publisher = publisher_;
        publisherOwner = publisherOwner_;
        agent = wallet_.agent();
        guardian = wallet_.guardian();
        guardianKey = guardianKey_;
        m = wallet_.mandate();
        uint256 n = wallet_.payeeCount();
        for (uint32 id = 1; id <= n; ++id) {
            Payee memory p = wallet_.getPayee(id);
            if (p.active) isActivePayee[p.account] = true;
        }
    }

    // ------------------------------------------------------------------ agent and guardian

    /// @notice A PAYMENT intent with any payee id, amount and obligation reference, attested with any band,
    ///         source and flags.
    function submitPayment(
        uint256 payeeSeed,
        uint256 amountSeed,
        uint256 obligationSeed,
        uint8 band,
        uint8 source,
        uint16 flags
    ) external counted {
        Intent memory i = _intent(Task.PAYMENT, _payeeId(payeeSeed), _amount(amountSeed, 3 * m.c2));
        _bindObligation(i, obligationSeed);
        ScheduleTerms memory noTerms;
        _submit(i, noTerms, band, source, flags);
    }

    /// @notice A SCHEDULE_CREATE intent with arbitrary terms. Sometimes the signed hash does not match them.
    function submitSchedule(
        uint256 payeeSeed,
        uint256 amountSeed,
        uint64 period,
        uint64 firstDueOffset,
        uint32 maxRuns,
        bool mismatch,
        uint8 band,
        uint16 flags
    ) external counted {
        Intent memory i = _intent(Task.SCHEDULE_CREATE, _payeeId(payeeSeed), _amount(amountSeed, 2 * m.c1));
        ScheduleTerms memory terms = ScheduleTerms({
            period: uint64(_bound(period, 0, 40 days)),
            firstDue: uint64(block.timestamp + _bound(firstDueOffset, 0, 10 days)),
            maxRuns: uint32(_bound(maxRuns, 0, 6))
        });
        i.purposeHash = mismatch ? keccak256(abi.encode(period, maxRuns)) : wallet.hashScheduleTerms(terms);
        _submit(i, terms, band, 0, flags);
    }

    /// @notice A SWEEP intent for any amount.
    function submitSweep(uint256 amountSeed, uint8 band, uint8 source, uint16 flags) external counted {
        ScheduleTerms memory noTerms;
        _submit(_intent(Task.SWEEP, 0, _amount(amountSeed, 12_000 * USD)), noTerms, band, source, flags);
    }

    /// @notice A FEE_TOPUP intent asking for any native amount.
    function submitTopUp(uint256 amountSeed, uint8 band, uint8 source, uint16 flags) external counted {
        ScheduleTerms memory noTerms;
        _submit(_intent(Task.FEE_TOPUP, 0, _bound(amountSeed, 1, 2 ether)), noTerms, band, source, flags);
    }

    /// @notice The agent registers a bill, which can only lower D.
    function addObligation(uint256 payeeSeed, uint256 amountSeed, uint64 dueOffset) external counted {
        uint32 payeeId = _payeeId(payeeSeed);
        uint256 amount = _amount(amountSeed, 3000 * USD);
        uint64 due = uint64(block.timestamp + _bound(dueOffset, 0, 60 days));
        Snapshot memory s = _snapshot();
        vm.recordLogs();
        vm.prank(agent);
        try wallet.addObligation(payeeId, amount, due) {} catch {}
        _check(s, Path.OTHER, false, vm.getRecordedLogs());
    }

    /// @notice The agent or the guardian key tries to approve an owner-approval item.
    function keyHolderApproves(uint256 itemSeed, bool asGuardian) external counted {
        uint256 count = wallet.itemCount();
        if (count == 0) return;
        uint256 itemId = _bound(itemSeed, 1, count);
        vm.prank(asGuardian ? guardian : agent);
        try wallet.approve(itemId) {
            _breach("a key holder approved an item");
        } catch {}
    }

    /// @notice The agent or the guardian key tries to loosen the mandate, directly or through Λ.
    function keyHolderLoosens(uint256 c1Seed, bool asGuardian, bool viaTimelock) external counted {
        Mandate memory looser = m;
        looser.c1 = _bound(c1Seed, m.c1 + 1, m.c2);
        looser.reserve = 0;
        vm.prank(asGuardian ? guardian : agent);
        if (viaTimelock) {
            try wallet.proposeMandate(MISSION, looser) returns (uint256) {
                _breach("a key holder proposed a mandate");
            } catch {}
        } else {
            try wallet.setMandate(MISSION, looser) {
                _breach("a key holder set the mandate");
            } catch {}
        }
    }

    /// @notice The agent spends native token elsewhere, so that top-ups can be asked for again.
    function agentSpendsNative(uint256 amountSeed) external counted {
        vm.deal(agent, _bound(amountSeed, 0, agent.balance));
    }

    /// @notice A calm request (band low, owner instruction, known payee identity) through the same checked
    ///         path as the fuzzed submissions. Not a fuzz target: setUp and the coverage test call it so that
    ///         every run starts from a value movement the checks have seen.
    function seedSubmit(Task task, uint32 payeeId, uint256 amount) external {
        ScheduleTerms memory noTerms;
        _submit(_intent(task, payeeId, amount), noTerms, 0, 0, Flags.KNOWN_PAYEE_IDENTITY);
    }

    // ------------------------------------------------------------------ anyone

    /// @notice Anyone executes any item.
    function executePending(uint256 itemSeed) external counted {
        uint256 count = wallet.itemCount();
        if (count == 0) return;
        uint256 itemId = _bound(itemSeed, 1, count);
        Item memory before = wallet.getItem(itemId);
        Snapshot memory s = _snapshot();
        vm.recordLogs();
        bool ok;
        try wallet.executePending(itemId) {
            ok = true;
        } catch {}
        if (ok) {
            ++pendingExecutions;
            if (before.tier != Tiers.L2) _breach("an owner-approval item executed without the owner");
            if (before.status != ItemStatus.QUEUED) _breach("an item executed that was not queued");
            if (block.timestamp < uint256(before.queuedAt) + m.delay) _breach("a queued item executed before delta");
            if (before.req.task == uint8(Task.PAYMENT) && before.req.amount > m.c2) {
                _breach("a queued payment above c2 executed");
            }
        }
        _check(s, Path.EXECUTE_PENDING, ok, vm.getRecordedLogs());
    }

    /// @notice Anyone runs any schedule.
    function runSchedule(uint256 scheduleSeed) external counted {
        (uint64 created,) = wallet.scheduleCounts();
        if (created == 0) return;
        uint64 id = uint64(_bound(scheduleSeed, 1, created));
        Snapshot memory s = _snapshot();
        s.discretionaryForPayment = wallet.discretionary(wallet.getSchedule(id).obligationId);
        vm.recordLogs();
        bool ran;
        try wallet.runSchedule(id) returns (bool r) {
            ran = r;
        } catch {}
        if (ran) ++scheduleRuns;
        _check(s, Path.RUN_SCHEDULE, ran, vm.getRecordedLogs());
    }

    /// @notice Anyone syncs capsules.
    function syncCapsules(uint256 maxCount) external counted {
        Snapshot memory s = _snapshot();
        vm.recordLogs();
        try wallet.syncCapsules(_bound(maxCount, 0, 20)) {} catch {}
        _check(s, Path.OTHER, false, vm.getRecordedLogs());
    }

    /// @notice Another registered wallet publishes a capsule with any valid or invalid fields.
    function publishCapsule(
        uint8 family,
        uint8 channel,
        uint16 features,
        uint8 action,
        uint8 restriction,
        uint64 lifetime
    ) external counted {
        vm.prank(publisherOwner);
        try publisher.publishCapsule(
            uint8(_bound(family, 0, 6)),
            uint8(_bound(channel, 0, 5)),
            features & 0x1FF,
            uint8(_bound(action, 0, 5)),
            uint8(_bound(restriction, 0, 4)),
            uint64(_bound(lifetime, 0, 8 days)),
            1
        ) returns (
            uint256
        ) {}
            catch {}
    }

    /// @notice Time passes.
    function warp(uint256 secondsSeed) external counted {
        vm.warp(block.timestamp + _bound(secondsSeed, 0, 26 hours));
    }

    // ------------------------------------------------------------------ checks

    function _submit(Intent memory i, ScheduleTerms memory terms, uint8 band, uint8 source, uint16 flags) private {
        Attestation memory a;
        a.intentHash = wallet.hashIntent(i);
        a.band = _band(band);
        a.source = _source(source);
        a.flags = _flags(flags);
        a.validUntil = uint64(block.timestamp + 10 minutes);
        (uint8 v, bytes32 r, bytes32 sv) = vm.sign(guardianKey, wallet.hashAttestation(a));
        bytes memory sig = abi.encodePacked(r, sv, v);

        Snapshot memory s = _snapshot();
        PaymentFacts memory facts;
        if (i.task == uint8(Task.PAYMENT)) {
            s.discretionaryForPayment = wallet.discretionary(i.scheduleId);
            if (i.payeeId != 0 && i.payeeId <= wallet.payeeCount()) {
                Payee memory p = wallet.getPayee(i.payeeId);
                facts = PaymentFacts({payeeKnown: true, paidCount: p.paidCount, maxPaid: p.maxPaid});
            }
        }
        vm.recordLogs();
        vm.prank(agent);
        if (i.task == uint8(Task.SCHEDULE_CREATE)) {
            try wallet.submitSchedule(i, terms, a, sig) returns (uint256) {} catch {}
        } else {
            try wallet.submit(i, a, sig) returns (uint256) {} catch {}
        }
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 paid = _check(s, Path.SUBMIT, true, logs);
        if (paid > 0) _checkL1Payment(i, a, s, facts, logs);
    }

    /// @dev A payment that executed in the same transaction: it must have been L1 on every question. Band low,
    ///      no pressure flag, within D, and the allowance before the call covered a charge that is at least
    ///      what the mandate's charges add up to for this request.
    function _checkL1Payment(
        Intent memory i,
        Attestation memory a,
        Snapshot memory s,
        PaymentFacts memory facts,
        Vm.Log[] memory logs
    ) private {
        if (a.band != 0) _breach("an L1 payment had a band above low");
        if (a.flags & Flags.PRESSURE != 0) _breach("an L1 payment carried a pressure flag");
        if (i.amount > s.discretionaryForPayment) _breach("an L1 payment exceeded D");
        if (!facts.payeeKnown) _breach("an L1 payment went to an unknown payee id");

        uint256 minimum;
        if (a.source == 1) minimum += m.chargeExternal;
        if (i.amount > s.discretionaryForPayment / 2) minimum += m.chargeOverHalfD;
        if (facts.paidCount == 0) minimum += m.chargeFirstPayment;
        else if (i.amount > facts.maxPaid) minimum += m.chargeAnomaly;

        bool found;
        for (uint256 k = 0; k < logs.length; ++k) {
            if (logs[k].emitter != address(wallet) || logs[k].topics[0] != ALLOWANCE_CHARGED_TOPIC) continue;
            (uint256 charge,) = abi.decode(logs[k].data, (uint256, uint256));
            found = true;
            if (charge > s.allowance) _breach("an L1 payment was charged more allowance than there was");
            if (charge < minimum * ALLOWANCE_UNIT) _breach("an L1 payment was charged less than the mandate says");
        }
        if (!found) _breach("an L1 payment was not charged to the allowance");
    }

    /// @dev Checks every MockUSD and native outflow of the call that just ran against the mandate.
    /// @return toPayees MockUSD paid to payees in the call.
    function _check(Snapshot memory s, Path path, bool mayMove, Vm.Log[] memory logs)
        private
        returns (uint256 toPayees)
    {
        uint256 out;
        for (uint256 k = 0; k < logs.length; ++k) {
            Vm.Log memory log = logs[k];
            if (log.emitter != address(token) || log.topics.length != 3 || log.topics[0] != TRANSFER_TOPIC) continue;
            if (address(uint160(uint256(log.topics[1]))) != address(wallet)) continue;
            address to = address(uint160(uint256(log.topics[2])));
            uint256 value = abi.decode(log.data, (uint256));
            out += value;
            if (!mayMove) _breach("MockUSD left through a path that moves no value");
            if (to == address(vault)) {
                ++sweeps;
                if (value > s.discretionary) _breach("a sweep exceeded D");
            } else if (isActivePayee[to]) {
                toPayees += value;
                _checkPayeeTransfer(path, value, s);
            } else {
                _breach("MockUSD went to an address that is neither an active payee nor the vault");
            }
        }
        ghostTokenOut += out;

        uint256 tokenNow = token.balanceOf(address(wallet));
        if (s.tokenBalance - tokenNow != out) _breach("MockUSD left the wallet without a transfer event");
        if (out > 0 && tokenNow < m.reserve) _breach("an outflow took the balance below the reserve");

        uint256 nativeNow = address(wallet).balance;
        if (nativeNow < s.nativeBalance) {
            uint256 sent = s.nativeBalance - nativeNow;
            ++topUps;
            ghostNativeOut += sent;
            ghostNativeByDay[s.day] += sent;
            if (agent.balance != s.agentNative + sent) _breach("native token went somewhere other than the agent");
            if (sent > m.feeTopUpCap) _breach("a top-up exceeded the per-call cap");
            if (ghostNativeByDay[s.day] > m.feeDailyBudget) _breach("top-ups exceeded the daily budget");
            if (nativeNow < m.nativeReserve) _breach("a top-up broke the native reserve");
        }
    }

    function _checkPayeeTransfer(Path path, uint256 value, Snapshot memory s) private {
        if (path == Path.SUBMIT || path == Path.RUN_SCHEDULE) {
            if (path == Path.SUBMIT) ++l1Payments;
            if (value > m.c1) _breach("a same-transaction payment exceeded c1");
            if (value > s.discretionaryForPayment) _breach("a same-transaction payment exceeded D");
            ghostL1ByDay[s.day] += value;
            if (ghostL1ByDay[s.day] > m.d1) _breach("same-transaction payments exceeded d1 in a day");
        } else if (path == Path.EXECUTE_PENDING) {
            if (value > m.c2) _breach("a queued payment exceeded c2");
        } else {
            _breach("a payee was paid outside a payment path");
        }
    }

    function _snapshot() private view returns (Snapshot memory s) {
        s.tokenBalance = token.balanceOf(address(wallet));
        s.nativeBalance = address(wallet).balance;
        s.agentNative = agent.balance;
        s.discretionary = wallet.discretionary(0);
        s.discretionaryForPayment = s.discretionary;
        s.allowance = wallet.allowance();
        s.day = block.timestamp / 1 days;
    }

    function _breach(string memory what) private {
        if (breaches == 0) firstBreach = what;
        ++breaches;
    }

    // ------------------------------------------------------------------ input shaping

    function _intent(Task task, uint32 payeeId, uint256 amount) private view returns (Intent memory i) {
        i.task = uint8(task);
        i.payeeId = payeeId;
        i.amount = amount;
        i.purposeHash = keccak256(abi.encode(amount, block.timestamp));
        i.nonce = wallet.nonce();
    }

    /// @dev Usually an existing payee id (one of them removed). One time in four any id from 0 (none) to one
    ///      past the last.
    function _payeeId(uint256 seed) private view returns (uint32) {
        uint256 n = wallet.payeeCount();
        return uint32(seed % 4 == 0 ? _bound(seed / 4, 0, n + 1) : _bound(seed / 4, 1, n));
    }

    /// @dev Mostly band low, otherwise medium or high. The largest seed gives the out-of-range value 3.
    function _band(uint8 seed) private pure returns (uint8) {
        if (seed == type(uint8).max) return 3;
        uint8 k = seed % 6;
        return k < 4 ? 0 : k - 3;
    }

    /// @dev Mostly owner instruction, otherwise external content. The largest seed gives the out-of-range value 2.
    function _source(uint8 seed) private pure returns (uint8) {
        if (seed == type(uint8).max) return 2;
        return seed % 3 < 2 ? 0 : 1;
    }

    /// @dev Any combination of the eight flags. Three times in four the pressure flags are left out, so that
    ///      requests the guardian calls calm, which are the ones that can execute at L1, are common.
    function _flags(uint16 seed) private pure returns (uint16) {
        uint16 f = seed & Flags.ALL;
        return (seed >> 8) % 4 != 0 ? f & ~Flags.PRESSURE : f;
    }

    /// @dev Amounts spread over the interesting ranges: up to c1 (most often), up to c2, up to `max`, and around
    ///      the discretionary amount D, from half of it to c1 above it. Sweeps near D drive D down, and payments
    ///      near D then probe its boundary while D is below c1. A zero seed gives the invalid amount 0.
    function _amount(uint256 seed, uint256 max) private view returns (uint256) {
        if (seed == 0) return 0;
        uint256 range = seed % 5;
        if (range == 4) {
            uint256 d = wallet.discretionary(0);
            return _bound(seed / 5, d / 2 > 0 ? d / 2 : 1, d + m.c1);
        }
        uint256 cap = range < 2 ? m.c1 : range == 2 ? m.c2 : max;
        return _bound(seed / 5, 1, cap);
    }

    /// @dev Half the time no obligation reference. Otherwise either an open obligation, paid with its own
    ///      payee and amount, or any id with whatever payee and amount the intent already has.
    function _bindObligation(Intent memory i, uint256 seed) private view {
        uint256 kind = seed % 4;
        if (kind < 2) return;
        uint64[] memory open = wallet.openObligationIds();
        if (kind == 2 && open.length > 0) {
            uint64 id = open[(seed / 4) % open.length];
            Obligation memory o = wallet.getObligation(id);
            i.scheduleId = id;
            i.payeeId = o.payeeId;
            i.amount = o.amount;
        } else {
            i.scheduleId = uint64(_bound(seed / 4, 0, 40));
        }
    }
}

/// @notice The agent and guardian keys, driven arbitrarily, can never move value beyond the mandate.
/// @dev Setup is the only time the owner acts: three payees through Λ (from `Base`), one of them then
///      removed, the wallet funded, and one bill registered.
contract AgentCannotExceedMandateTest is Base {
    MandateHandler internal handler;
    uint256 internal startTokenBalance;
    uint256 internal startNativeBalance;
    bytes32 internal startMandateHash;
    uint256 internal startPayeeCount;
    uint256 internal startChangeCount;

    function setUp() public override {
        super.setUp();
        _fund(10_000 * USD);
        vm.startPrank(owner);
        wallet.removePayee(softwareId);
        wallet.addObligation(landlordId, 1200 * USD, uint64(block.timestamp + 20 days));
        vm.stopPrank();

        address publisherOwner = makeAddr("publisherOwner");
        PolicyWallet publisher = _newWallet(publisherOwner, makeAddr("publisherAgent"));
        handler = new MandateHandler(wallet, guardianKey, publisher, publisherOwner);

        startTokenBalance = token.balanceOf(address(wallet));
        startNativeBalance = address(wallet).balance;
        (, startMandateHash) = wallet.mandateHashes();
        startPayeeCount = wallet.payeeCount();
        startChangeCount = wallet.changeCount();

        // A deterministic first action: one calm L1 payment through the handler's checked path, so that every
        // run starts with a value movement the checks have seen.
        handler.seedSubmit(Task.PAYMENT, hostingId, 100 * USD);
        require(handler.l1Payments() == 1, "the seed payment must execute at L1");

        bytes4[] memory selectors = new bytes4[](13);
        selectors[0] = MandateHandler.submitPayment.selector;
        selectors[1] = MandateHandler.submitSchedule.selector;
        selectors[2] = MandateHandler.submitSweep.selector;
        selectors[3] = MandateHandler.submitTopUp.selector;
        selectors[4] = MandateHandler.addObligation.selector;
        selectors[5] = MandateHandler.keyHolderApproves.selector;
        selectors[6] = MandateHandler.keyHolderLoosens.selector;
        selectors[7] = MandateHandler.agentSpendsNative.selector;
        selectors[8] = MandateHandler.executePending.selector;
        selectors[9] = MandateHandler.runSchedule.selector;
        selectors[10] = MandateHandler.syncCapsules.selector;
        selectors[11] = MandateHandler.publishCapsule.selector;
        selectors[12] = MandateHandler.warp.selector;
        targetContract(address(handler));
        targetSelector(StdInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @dev Guards against a vacuous run. The fuzzer must have driven the handler and the seeded L1 payment
    ///      from setUp must still be on record. A fuzzed value movement is not guaranteed in every run, since a
    ///      short sequence may miss one, so `test_Handler_ChecksEveryValuePath` covers each value path.
    function afterInvariant() public view {
        assertGt(handler.calls(), 0, "the fuzzer never called the handler");
        assertGe(handler.l1Payments(), 1, "the seeded L1 payment was not checked");
    }

    /// @dev Drives every value-moving path once with chosen inputs and shows that each reached the checks
    ///      without a breach: an L1 payment, a queued payment executed after Δ, a sweep, a fee top-up and a
    ///      schedule run.
    function test_Handler_ChecksEveryValuePath() public {
        handler.seedSubmit(Task.PAYMENT, hostingId, 900 * USD); // above c1: queued
        handler.seedSubmit(Task.SWEEP, 0, 1000 * USD);
        handler.seedSubmit(Task.FEE_TOPUP, 0, 0.01 ether);
        // Landlord, 100 per run, daily from an hour from now, three runs.
        handler.submitSchedule(5, 5 * 100 * USD, 1 days, 1 hours, 3, false, 0, 0);
        assertEq(wallet.getSchedule(1).amount, 100 * USD);
        handler.warp(1 hours);
        handler.executePending(1);
        handler.runSchedule(1);

        assertEq(handler.breaches(), 0, handler.firstBreach());
        assertEq(handler.l1Payments(), 1, "the seeded payment");
        assertEq(handler.pendingExecutions(), 1);
        assertEq(handler.sweeps(), 1);
        assertEq(handler.topUps(), 1);
        assertEq(handler.scheduleRuns(), 1);
        assertEq(token.balanceOf(address(wallet)), startTokenBalance - handler.ghostTokenOut());
    }

    function invariant_AgentCannotExceedMandate() public view {
        assertEq(handler.breaches(), 0, handler.firstBreach());

        // Every unit that left is accounted for by a checked outflow, and the floors hold.
        assertEq(token.balanceOf(address(wallet)), startTokenBalance - handler.ghostTokenOut());
        assertEq(address(wallet).balance, startNativeBalance - handler.ghostNativeOut());
        assertGe(token.balanceOf(address(wallet)), wallet.mandate().reserve);
        assertGe(address(wallet).balance, wallet.mandate().nativeReserve);

        // Nothing about authority was loosened or changed.
        (, bytes32 mandateHash) = wallet.mandateHashes();
        assertEq(mandateHash, startMandateHash);
        assertEq(wallet.payeeCount(), startPayeeCount);
        assertFalse(wallet.getPayee(softwareId).active);
        assertEq(wallet.changeCount(), startChangeCount);
        assertEq(wallet.agent(), agent);
        assertEq(wallet.guardian(), guardian);
        assertFalse(wallet.frozen());
        for (uint256 id = 1; id <= wallet.itemCount(); ++id) {
            Item memory it = wallet.getItem(id);
            assertTrue(it.status != ItemStatus.APPROVED, "no item is approved without the owner");
        }
    }
}
