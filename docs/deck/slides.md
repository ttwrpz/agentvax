---
marp: true
theme: default
paginate: true
title: AgentVax
---

# AgentVax

## The problem

- AI agents holding wallets can be manipulated into spending money improperly.
- Existing agent wallets focus on what the agent is permitted to do, enforcing permissions with caps and allowlists.
- A patient attacker stays within the caps, a rushed owner approves the fraud, and a reworded attack slips past a filter.

<!-- Speaker note: about 50 seconds. Mention that several agents have already lost funds. -->

---

## The idea

- AgentVax addresses a second question: how much of its power the agent should exercise independently right now.
- The owner states a mission in plain language, creating a mandate that the owner signs and the chain stores.
- The wallet contract checks every payment, while learning and shared alerts can only reduce autonomy.
- Only the owner can extend authority, and only after a delay chosen in advance.

---

## Three principles

- **P1.** The model proposes, deterministic code authorises, and the wallet contract enforces.
- **P2.** Learning updates risk estimates. Only the owner changes authority.
- **P3.** Caution is immediate and expansion is slow, for the model, the network and the owner alike.

---

## Three questions decide the tier

| Question | L1 routine | L2 delayed | L3 owner |
|---|---|---|---|
| Allowed? | Active payee, within limits | Up to the larger limit | Above the larger limit. A new or inactive payee reverts and goes through the owner's Λ time-lock |
| Affordable? | Within the free amount D | Tight, above D | Breach of the reserve |
| Safe now? | Low band, no pressure | Medium band, pressure, one-observer alert | High band, confirmed alert |

- The request is assigned to the highest tier required by any individual question.
- The guardian signs the band, source and flags, while the contract computes the tier and D itself.

---

## Financial state engine: the worked example

- The balance is 1,850, with a reserve of 600, alongside rent of 800, hosting of 150, and software of 120.
- The free amount D = 1,850 - 600 - 800 - 150 - 120 = 180.
- A hosting upgrade of 300 is allowed and the payee is approved, but 300 exceeds D.
- The wallet queues the request, noting that it would leave the wallet 120 short of its bills.
- An expected income of 500 is shown for visibility, but it is never counted.

---

## Caution allowance

- Each routine request is charged points for verifiable flags, such as an external source, a first payment or an unusual amount.
- A clean request costs nothing. If the allowance is exhausted, the request waits at L2.
- The allowance refills at a fixed rate, halves when a relevant alert appears, and drops to zero when the owner confirms an attack.
- A series of slightly unusual invoices reaches the owner before the allowance runs out.

---

## The owner under pressure

- Adding a payee, raising a limit, lowering the reserve or shortening a delay is subject to the loosening delay, even for the owner.
- An approval made under pressure requires an additional hold. The owner can lengthen it, but nothing can shorten it.
- Freezing, tightening and cancelling take effect immediately.
- Considered confirmation requires the owner to type the payee's name and state who made the request.

---

## Immunity capsules

- A capsule is a fixed-field alert containing no private data. It describes an attack by its features.
- A wallet that confirms an attack publishes a capsule. Other wallets match reworded versions and become more cautious from their next transaction.
- A single observer can impose only a delay, while attestation from a second wallet allows more.
- Capsules expire, are rate-limited and can be dismissed by an owner. They can never loosen anything.

---

## Federated detector

- A small injection detector is trained across three wallets, each seeded with a different attack family.
- Updates are clipped and masked. Each wallet tests a new model on its own canary set before adopting it.
- The model hash is anchored on chain, and wallets adopt only a matching hash.
- The encoder is a hashing encoder in every mode (a recorded departure from the paper).

---

## Results

| Measure | Target | Mock run | Live run |
|---|---|---|---|
| Unauthorised transactions | 0 | 0 | not measured (no API key) |
| Value beyond L1 | 0 | 0 | not measured (no API key) |
| Safe autonomy rate | at least 0.80 | 0.55 (22 of 40) | not measured (no API key) |
| Reworded attacks matched | at least 0.90 | 0.317 (19 of 60) | not measured (no API key) |
| Unseen-family recall gain from federation | positive for every wallet | +0.0125, +0.1000, +0.0375 | not measured (the federation runs without the language model, so it has no separate live result) |

Mock results test the system plumbing and the contracts, but they say nothing about model quality. Task success was 22 of 40, as the mock phrase tables asked a question for many sweep and top-up wordings. Details are in `docs/RESULTS.md`.

---

## What was built and how it was verified

- Four contracts, with the wallet split into six linked libraries, alongside a separate guardian process and a Python runtime with a reader, planner, validator and explainer.
- Contract tests include a fuzzed invariant that the agent cannot exceed its mandate, alongside Python tests run with no network.
- An evaluation of 40 tasks, 10 ambiguous cases, 20 affordability cases and 30 base attacks across 5 families, each reworded twice.
- `make test` runs every contract and Python test. All 14 evidence rows ran on Base Sepolia, 43 transactions with successful receipts, listed in `docs/EVIDENCE.md`.

---

## Limits and next steps

- The hashing encoder is weaker than a pretrained model. Masks conceal updates only statistically, within a single process.
- A high volume of alerts can hold wallets at a delay. A hijacked approved payee still receives bounded payments.
- The guardian key file is stored in plain hex.
- Next steps include a pretrained encoder, a trusted co-signer, more federation participants and a hardened key store.
