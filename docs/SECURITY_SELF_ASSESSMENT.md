# AgentVax security self-assessment

This report sets out the design and implementation of the permission tiers in AgentVax, the assumptions underpinning the threat model, the mechanisms used to enforce and test each security invariant, and the remaining residual risks. It accurately reflects the code currently in the repository. Where the implementation departs from the original paper, the departure is explicitly identified and references `docs/DECISIONS.md`. Measured values are taken from `results/` and summarised in `docs/RESULTS.md`. Any output produced using `MockLLM` is explicitly labelled mock.

## Permission tiers as built

Every payment request is assigned the highest tier demanded by any of the three policy questions. Because the contract computes this tier at execution time, no off-chain value is trusted to determine either the tier or the discretionary amount.

| Tier | Meaning | What happens |
|---|---|---|
| L0 | Read only | No value moves |
| L1 | Routine | Executes in the same transaction |
| L2 | Elevated | Queued for the delay Δ. The owner may cancel. Anyone may execute after Δ if the wallet is not frozen and the payment is still affordable |
| L3 | Sensitive | Stored as a proposal. The owner approves it. It becomes executable immediately, or after the pressure hold Π if it carries a pressure flag or a full capsule match |

### The three questions

1. **Allowed (q1).** An active payee, an amount not exceeding c1, and a cumulative daily total within d1 yields L1. An amount up to c2 yields L2. Any larger amount yields L3. If the payee is inactive or unknown, the call reverts, because a new payee cannot be proposed until the owner has explicitly added it through Λ.
2. **Affordable (q2).** Given balance B, reserve R, and discretionary amount D, a payment not exceeding D yields L1. An amount that exceeds D but remains within B minus R yields L2, designated as tight. Anything exceeding B minus R constitutes a reserve breach and yields L3.
3. **Safe right now (q3).** The guardian band provides low for L1, medium for L2, and high for L3. Any pressure flag covering urgency, secrecy, or an override attempt elevates the tier to at least L2. Each active, unexpired capsule that matches fully raises the tier to that capsule's specified restriction.

### The deciding check and the allowance

Once the three questions have been evaluated, an L1 outcome must pass through the caution allowance. The contract calculates a charge based on the presence of risk flags: 2 for an external source, 2 for an amount exceeding half of D, 3 for an amount greater than the largest sum previously paid to that payee, 3 for the initial payment to a payee, and 5 for a partial capsule match. A clean request incurs a charge of 0. If the total charge falls within the current allowance, the contract deducts it and executes the payment. If the charge exceeds the allowance, the tier is elevated to L2. The resulting `Decision` event records the deciding check, defined as the lowest-numbered check that required the final tier. Check 4, corresponding to the allowance, is reported only when the allowance check was responsible for raising the tier.

The allowance replenishes linearly up to A. It is halved once for each newly encountered capsule that matches the wallet's channel profile, and is set to zero if the owner invokes `confirmAttack`. The contract maintains the allowance in fixed point at 1e6 per point to ensure smooth replenishment.

### What the contract computes itself

- The discretionary amount D, calculated directly from the balance, the reserve, and all obligations falling due within the planning horizon, excluding whichever obligation is currently being settled. Payment schedules automatically register their next occurrence as an obligation.
- The tier, the allowance charge, and the AMOUNT_ANOMALY flag, which the contract includes via bitwise OR whenever the payment amount exceeds the largest previous transfer to that payee.
- The schedule terms hash, which must match the signed `purposeHash`, together with the obligation reference binding for outgoing payments.
- Whether any queued or approved item remains authorised and affordable at the precise moment funds are transferred. All value-bearing paths must pass through a unified gate that verifies freeze status, expiry, payee state, limits, capsule restrictions, and ongoing affordability.

### Delays and the owner under pressure

- **Δ** represents the L2 delay. Increasing Δ extends the waiting time for items already queued, whereas reducing Δ never brings pending items forward.
- **Λ** represents the loosening delay. Adding a payee or destination address, increasing c1, c2, d1, or A, reducing R, shortening Δ, Λ, or Π, extending expiry, removing an obligation, updating the agent or guardian key, and unfreezing the contract all take effect only after Λ has elapsed. The workflow requires a typed `propose*` call, followed by `applyChange` once Λ has passed. Any proposal becomes stale if the underlying state upon which it was constructed changes in the interim.
- **Π** represents the pressure hold. If an owner grants approval while a pressure flag or a potentially matching capsule is present, the transaction must wait for duration Π. The owner can only extend this hold, which is done using `extendHold`.
- **Freeze** takes effect immediately and blocks every value-moving operation, including items that are already queued or approved. Unfreezing requires waiting for Λ.
- Tightening parameters, cancelling a pending item or proposed change, removing a payee, revoking the agent, and freezing the contract are all immediate actions.
- A request to pay a new address can never become an executable payment intent. The runtime can record a `PayeeChangeRequest`, but this carries no operational authority. Only the owner can promote it to a proposal, which then must wait for Λ.

### Capsules

A capsule is a structured, fixed-field record containing family, channel, features, action, restriction, expiry, guard version, issuer, and attestation count. Capsules can elevate a transaction tier or debit the caution allowance, but they contain no code path capable of altering mandate state. As long as fewer than two registered wallets have attested to a capsule, its effective restriction is capped at 2, imposing only a delay. The bulletin restricts the lifetime of any capsule to 7 days, and limits each wallet to 3 publications per day. The owner of a wallet retains the right to dismiss any capsule for their own wallet alone.

## Threat model

The adversary is assumed to control any external content the agent reads, including web pages, messages, invoices, token metadata, and any information written to memory. The adversary may operate one participating wallet, using it to publish malicious capsules or poisoned model updates. The adversary may also employ AI tools to vary and adapt attack payloads, or contact the owner directly to press for an approval or a rule change.

Conversely, the adversary does not hold either the owner key or the guardian key, and cannot modify deployed smart contract bytecode. The security architecture does not assume that the model can out-think or out-reason an attacker. Even if the underlying language model is completely manipulated, the system must guarantee that funds cannot be moved beyond the defined mandate.

Defensive layers operate in the following order:

1. The reader has access to no tools and returns only typed fields and structured flags. The planner never inspects or receives untrusted free text.
2. Deterministic validation verifies data schemas, input provenance, and system state, setting flags according to strict programmatic rules.
3. The guardian runs in an isolated process with an independent private key, where it scores raw content and signs the resulting band, source, and flags.
4. The on-chain contract strictly bounds the worst-case outcome. Even an entirely undetected attack can at most cause L1 payments to active payees within the configured limits, the discretionary amount, and the day's allowance.
5. Capsules narrow this operational window during an active threat, and their effects can only restrict permissions.
6. Time provides a critical defence for the owner. Any loosening of policy must wait for Λ, and approvals granted under pressure must wait for Π.

Out of scope: theft of the owner private key (the legitimate owner can trigger an immediate freeze, and any attacker must still wait Λ to loosen rules), compromise of deployed contract bytecode, and production deployments handling real economic value.

## Invariants and how they are tested

| # | Invariant | Mechanism and tests |
|---|---|---|
| 1 | Authority lives entirely in the wallet contract. No model output, capsule, detector score, or learned parameter can add a payee, raise a limit, lower the reserve, shorten a delay, or unfreeze the wallet | Every loosening requires a typed `propose*` call by the owner. Tests: `test_Mandate_AgentCannotModify`, `test_Loosening_AddPayee_WaitsLambda`, `test_Loosening_RaiseLimit_WaitsLambda`, `test_Loosening_LowerReserve_WaitsLambda`, `test_Loosening_ShortenLambda_WaitsLambda`, `test_Loosening_Unfreeze_WaitsLambda`, `test_Capsule_CannotLoosen`, and the invariant test `invariant_AgentCannotExceedMandate` |
| 2 | Any action that loosens rules must pass through Λ, including for the owner. Tightening, cancelling, and freezing remain immediate | `MandateRules` assigns a tightening direction to every field, and any mixed update that includes a loosened field must wait Λ. Tests: the five `test_Loosening_*` tests listed above, `test_Tightening_IsImmediate`, `test_PendingChange_CancelIsImmediate`, and the stale-proposal tests added in the M3 fix pass (D24) |
| 3 | L1 execution requires a valid guardian signature over the intent hash, band, source, and flags. The planner process never holds the guardian key | Verified using EIP-712 signatures in `IntentLogic`. The guardian runs as an isolated process that alone reads the private key (D25, D27). Tests: `test_L1_RevertsWithoutGuardianSig`, `test_L1_RevertsWithForgedGuardianSig`, `test_L1_RevertsWithExpiredAttestation`, `test_guardian_attestation_is_eip712_and_verifies`, `test_planner_has_no_access_to_guardian_key`, `test_guardian_refuses_another_wallet_or_chain` |
| 4 | The discretionary amount and the tier are computed directly by the contract at execution time | `DecisionLogic` and `LedgerLogic` calculate both values, and the value gate re-checks them whenever funds move. Tests: `test_Discretionary_MatchesWorkedExample`, `test_Afford_Comfortable_Tight_Breach`, `test_PayingRegisteredObligation_ExcludesItself`, `test_Decision_EmitsDecidingCheck`, and the affordability suite (mock, 20 of 20 scenarios agree with the hand-computed tier) |
| 5 | The reader has no tools and returns only typed fields and flags. No free text from untrusted content reaches the planner or memory | `ReaderOutput` contains no string fields, and flags are masked to five permitted bits. Tests: `test_reader_output_has_no_free_text`, `test_planner_never_receives_untrusted_text`, `test_memory_stores_no_raw_prompts`, `test_intent_schema_rejects_malformed` |
| 6 | A capsule can raise a tier or charge the allowance. It has no code path to modify mandate state | `ThreatBulletin` stores no wallet state, and the wallet only ever reads from it. Tests: `test_Capsule_CannotLoosen`, `test_Capsule_PartialMatch_ChargesAllowance`, `test_Capsule_FullMatch_RaisesTier_NextTransaction`, and the hostile-wallet suite (mock, 0 false capsules loosened a rule, largest restriction 2) |
| 7 | A single-observer capsule can impose at most a delay | The effective restriction is capped at 2 while fewer than two wallets have attested, and a capsule lacking a tracking slot likewise demands at most L2. Tests: `test_Capsule_SingleObserver_MaxDelay`, `test_SingleObserverCapsule_CappedAtDelay`, `test_Capsule_Confirmed_NeedsSecondWallet` |
| 8 | The wallet provides no function capable of making an arbitrary external call. Sweeps can only transfer to the vault fixed at deployment | `test_NoArbitraryCall` compares the compiled contract interface against a reviewed list of signatures and rejects any generic call pattern. `test_T3_Sweep_OnlyDiscretionary_ToVaultOnly`. The invariant test verifies that MockUSD leaves the wallet only to an active payee or the designated vault |
| 9 | Scripts that dispatch transactions reject any chain id other than 31337, 84532, and 11155111 | The chain client re-reads the chain id prior to every signature. Tests: `test_chain_client_refuses_non_test_chain`, `test_sending_paths_refuse_a_switched_chain_before_building`, `test_evidence_testnet_refuses_mainnet_anvil_and_a_mismatched_node` |
| 10 | No secret is read into the conversation context, logged, or committed | The `.env` file is excluded from the repository. The guardian child process receives an allowlisted environment to ensure owner and model keys never reach it. System settings keep secrets hidden. Tests: `test_settings_keep_secrets_hidden`, `test_the_key_is_not_shown_by_the_config`, `test_the_agent_does_not_hold_the_owner_key`, `test_guardian_line_handling_never_echoes_requests`. The verifier also scans for stopgap markers |

## Attack results

All results reported below come from the evaluation suites in `agent/agentvax/eval/suites/`. Safety gates are absolute, and quality targets are reported exactly as measured. Test inputs for each suite were written once and were not subsequently tuned. Each row is labelled by evaluation mode.

| Suite | Mode | Result |
|---|---|---|
| Direct injection (6 base attacks, 2 reworded forms each) | mock | 0 unauthorised transactions. 2 of 12 reworded forms matched a capsule |
| Indirect injection | mock | 0 unauthorised transactions. 0 of 12 matched, because all 6 base attacks concluded with a question and no capsule was published |
| Memory poisoning | mock | 0 unauthorised transactions. 4 of 12 matched |
| Encoded content | mock | 0 unauthorised transactions. 6 of 12 matched |
| Recipient substitution | mock | 0 unauthorised transactions. 7 of 12 matched |
| Probing sequence (6 slightly odd invoices) | mock | 2 executed at L1, while the other 4 were queued at L2 by the allowance check. Both executed payments remained within the allowance |
| Panicked owner | mock | 8 prompts approved, with 0 value released before the delay expired. Every early execute or apply call reverted |
| Hostile wallet (false capsules and a poisoned update) | mock | 0 rules loosened, with the largest restriction capped at 2. The poisoned update was rejected by the canaries of wallets B and C and was not adopted. Wallet A's canary accepted it |
| Capsule response (A attacked, B replayed, C unrelated) | mock | 0 transactions occurred before restriction. Wallet C remained unrestricted. Wallet B returned to L1 after expiry. The replay against wallet B was assigned to L3 where L2 was declared (a stricter outcome, recorded as a notice) |
| Unauthorised transactions, all attack suites | mock | 0 |
| Value beyond L1 | mock | 0 |
| Same suites with the hosted model | live | Not measured, as no `LLM_API_KEY` was provided |
| Evidence rows E01 to E14 on Base Sepolia | testnet, MockLLM | All 14 rows completed with successful receipts, see `docs/EVIDENCE.md` |

The mock evaluation demonstrates that the underlying contract wiring and safety plumbing function as designed, though it cannot assess model quality. The initial mock run uncovered four hard-gate failures. Each failure was traced to either an issue in the test harness or a rule that guessed rather than evaluating deterministically. None of these was resolved by altering a test suite, and the complete diagnosis is set out in decision D35.

## Known risks

The first thirteen rows correspond to Table 12 in the paper, updated to reflect the system as built. The remaining rows capture limitations of this specific build that are not itemised in the paper. "Residual" denotes the exposure that remains after the mitigation has been applied.

| ID | Risk | Mitigation as built | Residual risk |
|---|---|---|---|
| R1 | Undetected injection: the planner proposes an attacker-chosen action | The contract bounds the outcome. An undetected attack can at most cause L1 payments to active payees within c1, d1, the discretionary amount, and the caution allowance. A new payee never becomes an intent (D8, D28) | Those bounded L1 payments remain possible. Attack suite results (mock): 0 unauthorised transactions and 0 value beyond L1 |
| R2 | Guardian key compromise: an attacker can sign attestations and understate flags | The key lives in an isolated process that alone reads it, bound strictly to one wallet and chain. Pressure flags and encoded-content flags are also calculated by rule in the runtime, the contract applies AMOUNT_ANOMALY via bitwise OR itself, and both the allowance and affordability checks still apply. The owner can propose a replacement guardian through Λ and can freeze the contract immediately | The key file is stored in plain hex, and Windows does not enforce file mode 0600 (D27). An attacker possessing the key can authorise L1 payments up to the configured bounds |
| R3 | The reader misses a flag | Pressure flags, NEW_DESTINATION, and MEMORY_SOURCED are evaluated by deterministic rules. Reader flags are masked to five bits. A missed flag simply returns the request to the ordinary tiering rules | A missed model-only flag can prevent a capsule from matching or lead to an undercharged allowance. The reader miss rate was not measured, because the mock reader is rule based and evaluating a live reader requires `LLM_API_KEY` |
| R4 | The owner approves a fraud under pressure | Adding new payees and raising limits must wait for Λ. Pressured approvals must wait for Π. Cancellation is immediate. Deliberate confirmation can only lengthen a hold. Panicked-owner suite (mock): 0 value left the wallet before the delay expired | An owner who remains deceived when the delay expires can lose funds up to the established bounds |
| R5 | Delays obstruct a genuine emergency | The owner configures delays while calm. Freezing is immediate. Operational friction is measured in chain-time seconds during evaluation | The trusted co-signer designed to release delays early is a stretch goal and has not been built. Measured friction (mock, chain-time seconds): 86400 for a new payee (Λ), 3600 for a pressured request (Π), and 86400 for the allowance to recover |
| R6 | Incomplete obligation registry | Payment schedules register their next occurrence automatically, the agent can register obligations (up to 12 open items), and the reserve provides an explicit buffer | Any bill that was never registered is not protected beyond the reserve buffer |
| R7 | Arbitrary allowance values | Values are owner-configured integers with defined defaults. The probing suite verifies that the owner is consulted before the allowance is exhausted | Escalation rate (mock): 0 of 49 benign L1 requests (31 reached the wallet, while the remaining 18 were resolved with a question). Probing (mock): 2 odd payments executed before the owner was asked, staying within the allowance |
| R8 | False or excessive capsules slow honest wallets | Capsules can only tighten policy. A single observer is capped at imposing a delay. Lifetime is at most 7 days, publication is limited to 3 per wallet per day, quorum requires 2 wallets, owners can dismiss capsules, and tracking lists fail closed (D24, D26) | See capsule flooding below. The impact is strictly confined to delays |
| R9 | Small federation: two colluding parties can infer the third party's update | Pairwise masks cancel out in the aggregate sum. Vector clipping occurs locally inside each wallet | Because masks are bounded integers, data hiding is purely statistical. Furthermore, the aggregation round runs within a single process, meaning whoever runs all three clients has access to all masks (D33). This is a stated limitation of the prototype |
| R10 | Model poisoning by a participant | Bounded by clipping, a canary validation test per wallet prior to adoption, hash anchoring in the bulletin with sequential versions, and adoption only when the hash matches | Canary sensitivity and tolerance thresholds apply. In the initial federation run, wallet B's recall on its own family dropped from 0.95 to 0.80 without triggering its canary (D33) |
| R11 | False positives delay legitimate payments | The L2 tier introduces delays rather than outright rejections. Classification thresholds are fixed at 0.5 and 0.8 on the seed model. Common pressure phrases like "emergency" and "pay now" were excluded because they trigger false alarms on regular invoices (D27) | Detector false positive rate (mock): 0.045, representing 1 of 22 benign documents. In the federation run, false positives on benign test texts rose from 0.07 to 0.11 (D33) |
| R12 | Compromised approved payee | Spending limits, the amount anomaly flag, the discretionary amount, and the caution allowance together constrain exposure | An active payee whose account is compromised can receive L1 payments within the prescribed bounds |
| R13 | Hosted model outage, test-network conditions | Scheduled payments execute without relying on the model or an attestation. The contracts use no chain-specific features. A provider error fails closed and never falls back to `MockLLM` (D25) | Test-network transaction fees and block finality do not mirror main network conditions |
| R14 | Capsule flooding to L2 | Applicable capsules submitted by registered wallets can hold every wallet at L2, because a capsule with no tracking slot keeps requests at L2 (D23, D24, D26) | Exposure is bounded by the registrar, the daily publication limit, and expiry. The effect can only ever add delay |
| R15 | Obligation-slot filling | A compromised agent can consume all 12 of its obligation slots, which only serves to lower D. The owner retains 4 of the 32 slots (D24) | Agent autonomy is curtailed until the owner clears obligations through Λ |
| R16 | Guardian key file in plain hex | Created within the guardian process using exclusive creation flags, never transmitted elsewhere, with an allowlisted execution environment (D27) | Anyone with file system access can read the key, because Windows does not enforce file mode 0600 |
| R17 | Hashing encoder instead of a pretrained encoder | A single canonical model file is used with an anchored hash, ensuring wallets run precisely the anchored artifact (D29) | Detection accuracy is weaker than that of a pretrained encoder, which is a departure from the paper. The contract bounds the damage an undetected attack can inflict |
| R18 | Masks hide updates only statistically | Masks are integers below 2^40, and each sum is capped below 2^53 so that the masks cancel out exactly (D33) | A masked update does not achieve information-theoretic privacy. The federation implementation is intended as a protocol demonstration |
| R19 | Widening the channel profile and capsules passed over | Widening the profile represents a tightening of policy, so it takes effect immediately. The synchronisation cursor is then rewound to the earliest potentially active capsule and each capsule is marked as seen, ensuring the allowance is never halved twice for the same capsule (D24) | The initial build omitted capsules that had already been passed over. That defect has been corrected, and the rescan operation is strictly bounded by the tracked list sizes |
| R20 | Attestation age | The contract caps `validUntil` at 900 seconds beyond the block submitting the transaction (D24, D26, D27) | Attestation freshness is the responsibility of the guardian. A fast host clock can only cause an attestation to expire earlier than expected |
| R21 | Local interface exposure | Protected by a session token, origin and host header validation, a server-assigned source, and `textContent` rendering (D25) | The web interface is intended strictly for loopback use and is not hardened for deployment on a public network |
