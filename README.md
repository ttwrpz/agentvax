# AgentVax

AgentVax is an AI wallet agent for test networks. The owner states a mission in plain language, which becomes a mandate signed by the owner and stored on chain. For every payment, the wallet contract asks three questions: is it allowed, can the owner afford it, and is it safe right now. A daily caution allowance limits how many borderline payments can pass without asking the owner. When one wallet is attacked, it can publish an immunity capsule, a fixed-field alert containing no private data, so that other wallets become more cautious at once. A small injection detector is trained jointly across three wallets with federated learning. Everything uses valueless test tokens on test networks.

## Principles

- **P1.** The model proposes, deterministic code authorises, and the wallet contract enforces.
- **P2.** Learning changes risk estimates. Only the owner changes authority.
- **P3.** Caution is immediate and expansion is slow, for the model, the network and the owner alike.

In practice, this means that no model output, capsule or learned value can add a payee, raise a limit, lower the reserve or shorten a delay. Anything that loosens authority must wait for the loosening delay, including when requested by the owner. Tightening, cancelling and freezing take effect immediately.

## Architecture

### Contracts

The Foundry project in `contracts/` holds four contracts.

- `PolicyWallet` is deployed as one wallet per owner. It holds the mandate, the payees, obligations and schedules, the caution allowance and pending items. It is the only place where authority lives. It has no function that makes an arbitrary call, and it can sweep only to the vault fixed at deployment.
- `ThreatBulletin` is the shared registry of immunity capsules and anchored detector model versions.
- `SavingsVault` keeps a separate balance for each wallet and lets only that wallet's owner withdraw.
- `MockUSD` is a six-decimal test token with no value.

Written as a single unit, the wallet would exceed the 24,576 byte contract limit. Its logic is therefore split into six linked external libraries that operate on the wallet's storage (decision D23). The value gate, which is the one place that decides and then moves value, remains in `PolicyWallet.sol`.

| Library | Concern |
|---|---|
| `AuthorityLogic` | Mandate, payees and the time-lock |
| `DecisionLogic` | The three questions and the allowance charges |
| `ItemLogic` | The L2 queue, L3 approval and holds |
| `LedgerLogic` | Obligations, schedules and the discretionary amount |
| `CapsuleLogic` | Capsule tracking and matching |
| `IntentLogic` | EIP-712 hashing and the guardian signature check |

Every deployment therefore deploys and links these libraries. The Python deployer in `agent/agentvax/chain/deploy.py` handles this and checks every receipt.

### Agent runtime

The Python package `agentvax` in `agent/` contains the runtime. The main modules are:

- `reader`, a quarantined model role with no tools. It turns untrusted content into typed fields and flags, producing no free-text output.
- `planner`, the privileged model role. It never sees untrusted free text and emits either an intent or one question code.
- `validator` and `pressure`, deterministic code for schema, provenance and state checks, as well as the fixed phrase lists.
- `chain`, the web3 client and deployer. It refuses any chain id that is not a test network.
- `explain`, which turns the `Decision` event into one sentence from `strings.json`.
- `memory`, `mission`, `capsules`, `confirmation` and `owner_tools`, for structured memory, the mission to mandate step, capsule drafts, considered confirmation and owner workflows.
- `fed` and `detector`, for the hashing-encoder detector and the Flower federation with clipping, masks and canaries.
- `eval`, `vaxlab` and `harness`, the evaluation runner, the attack suites and test doubles such as `MockLLM`.
- `api`, a FastAPI app and one static page. Every sentence the user reads is in `agent/agentvax/api/static/strings.json`.

### The guardian is a separate process

The guardian runs as its own process with `python -m agentvax.guardian.service` and communicates using line-delimited JSON over standard input and output. It is the only code that ever reads the guardian key. It scores raw untrusted content with the detector, determines the risk band, the source and the pressure flags itself, and signs an EIP-712 attestation. The planner process never holds the guardian key.

### How a payment travels

```
 owner instruction            untrusted content (invoice, page, message)
        |                                  |
        |                           [ reader: no tools ]
        |                                  | typed fields and flags
        v                                  v
   [ planner ] -----> intent draft <-------+
        |
   [ validator + pressure rules ]
        |                                  raw content
        |                                      |
        |                              [ guardian process ]
        |                         detector band, source, flags,
        |                           signs EIP-712 attestation
        v                                      |
   agent session key: submit(intent, attestation, signature)
        |
        v
   [ PolicyWallet ]  allowed? affordable? safe now?  then allowance
        |
        +--> L1 executes now
        +--> L2 queued for the delay, owner may cancel
        +--> L3 stored, owner approves, held if pressure or capsule
        |
   Decision event --> [ explain ] --> one sentence for the owner
```

The contract recomputes the discretionary amount and the tier at execution time. It trusts no off-chain number for them.

## Setup

Prerequisites:

- Python 3.12 and `uv`
- Foundry (`forge`, `anvil`, `cast`) on your path
- GNU `make` and a POSIX shell. On Windows, use Git Bash.

Then run:

```
make setup
```

This creates `.venv`, installs the `agentvax` package with its development tools, and builds the contracts. On Windows, it also writes a small launcher at `.venv/bin/python` so that every command works the same way. Because the Foundry libraries are committed as plain files, no network access is needed to build.

Copy `.env.example` to `.env` and fill in only what you need. The scripts load `.env` themselves.

| Key | Needed for |
|---|---|
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL` | The live evaluation and the hosted interface. Also set `LLM_BASE_URL` for the OpenAI-compatible endpoint |
| `TESTNET_CHAIN_ID` | The test network, 84532 for Base Sepolia or 11155111 for Sepolia |
| `TESTNET_RPC_URL` | The public test network endpoint |
| `OWNER_PRIVATE_KEY` | A brand-new key that has never held anything of value, funded from a faucet |
| `EXPLORER_URL` | Optional, for explorer links in the evidence document |

Never commit `.env`. It is ignored by the repository and contains secrets. Use only keys that have never held anything of value.

## Deployment

### Local demonstration

The local demonstration needs no keys and no network access.

```
python -m agentvax.api.demo
```

It starts its own Anvil instance, deploys the stack with the demo profile, and starts one guardian process per wallet. It sets up wallets A, B and C from `agent/agentvax/api/data/demo_wallets.json`, with A in the state of the worked example, and it runs federation, anchoring and hash-gated adoption of the detector model through the same local stack as the evaluation. It then serves the interface at `http://127.0.0.1:8765/`. Everything on the page is labelled `mock` because it uses `MockLLM`. This shows that the plumbing and the contracts work, while saying nothing about model quality. The demonstration stops Anvil and the guardian when you stop the server. Use `--port` to change the port.

The page shows the chat, the mandate, the financial state, the allowance meter, pending items, payees, and the action log. Countdowns run in real time, so with the demo profile you can watch a delay finish.

### Hosted interface

`make ui` runs `python -m agentvax.api.app`, which serves wallet A of the test-network deployment made by `make evidence`, using the hosted model. It has no import path to the mock model. It refuses to start without that deployment, its key store under `secrets/evidence/` and the anchored detector model.

### Test network deployment and evidence

```
make evidence
```

This runs `python -m agentvax.evidence.run --network testnet`. It needs `TESTNET_RPC_URL` and `OWNER_PRIVATE_KEY` in `.env`. It deploys the contracts to Base Sepolia (chain id 84532) or Sepolia (chain id 11155111), creates wallets A, B and C, funds helper keys from the owner key, and performs the fourteen evidenced actions, E01 to E14. It writes `deployments/testnet.json`, `evidence/hashes.json` and `docs/EVIDENCE.md`. If a row cannot be produced, the run fails and reports which one.

Permitted chain ids are 31337 (Anvil), 84532 (Base Sepolia) and 11155111 (Sepolia). Every script that sends a transaction refuses anything else, and the chain client re-checks the chain id before every signature. Never point any of this at a main network.

The evidence run uses the demo profile so that it finishes in minutes. The profile is chosen at deployment and recorded in `deployments/testnet.json`.

| Setting | Default profile | Demo profile |
|---|---|---|
| L2 delay (Δ) | 1 hour | 60 seconds |
| Loosening delay (Λ) | 24 hours | 300 seconds |
| Pressure hold (Π) | 60 minutes | 120 seconds |
| Allowance refill | A per 24 hours | A per 600 seconds |

The reserve, per-payment limit, daily limit, L2 limit and allowance size are the same in both profiles. Profiles live in `agent/agentvax/profiles/` and are never written into code.

## Tests

```
make test
```

This runs `forge test` in `contracts/` followed by `pytest` on `agent/tests/`. The suites need no network and call no hosted model.

The Foundry tests cover:

- the four tasks (payment, schedule, sweep, fee top-up)
- the three questions and the guardian signature checks
- the discretionary amount and the affordability cases
- the caution allowance, its charges, refill, halving and `confirmAttack`
- the owner time-lock, stale proposals and the tightening order of every mandate field
- the owner under pressure, with holds and cancelling
- capsules, attestations, the publish limit and fail-closed behaviour on a full list
- `test_NoArbitraryCall`, which compares the compiled interface with a reviewed list of signatures
- the invariant test `invariant_AgentCannotExceedMandate`, in which a fuzzer drives the agent and guardian keys arbitrarily and the test asserts that value never leaves the wallet beyond what L1 permits without an owner action

The Python tests cover the chain client and deployer, the guardian process and its protocol, the detector, the pressure rules, the boundaries between reader, planner and validator (including a test that untrusted text cannot reach the planner), memory, the mission step, explanations, confirmation, capsules, federation, the evaluation harness, the interface and end-to-end runs on a local Anvil with `MockLLM`.

## Evaluation

```
make eval-mock
make eval-live
```

`make eval-mock` runs `python -m agentvax.eval.run --mode mock --out results`. It starts its own Anvil, uses `MockLLM` and needs no network. `make eval-live` does the same with the hosted model and needs `LLM_API_KEY`.

The suites comprise the task suite (40 instructions), the ambiguous suite (10), affordability (20), attacks (5 families, 30 base attacks, each in 2 reworded forms), probing, the panicked owner, the hostile wallet and capsule response. Suite inputs are data files in `agent/agentvax/eval/suites/`. They were written once and are not tuned after seeing results.

Outputs go to `results/`:

- `summary.mock.json` and `summary.live.json`, each with a `mode` field set truthfully
- `eval_ledger.<mode>.jsonl`, a per-case record with transactions, events and verdicts
- `federation.json`, from `python -m agentvax.fed.run --out results`

Results from `MockLLM` are always labelled `mock`. They show that the plumbing and the contracts work, while saying nothing about model quality. Only the live summary describes a language model. Safety gates (no unauthorised transaction, no value beyond L1, nothing loosened) are absolute. Quality targets are reported as measured, even when below target, in `docs/RESULTS.md`.

## Repository layout

```
contracts/     Foundry project: src/, test/, script/
agent/         Python package "agentvax" and agent/tests/
docs/          DECISIONS, RESULTS, SECURITY_SELF_ASSESSMENT, DEMO_SCRIPT, deck/ and the evidence document
paper/         the v4 papers (LaTeX and PDF)
results/       summary.mock.json, summary.live.json, federation.json, evaluation ledger
deployments/   testnet.json
evidence/      hashes.json
```

`docs/DECISIONS.md` records every design choice and each departure from the paper.

## Limitations

The full self-assessment is in `docs/SECURITY_SELF_ASSESSMENT.md`. The main limitations are as follows.

- The detector uses a hashing encoder in every mode, not a pretrained embedding model. This departs from the paper and is recorded in decision D29. The contract bounds what any undetected attack can do.
- The guardian key file is plain hex, and Windows does not enforce the file mode.
- Federation runs as a protocol demonstration in one process, with three clients. Masks hide updates only statistically, and whoever runs all three clients holds all masks (D33).
- Enough applicable capsules can hold every wallet at L2, and an agent can fill the obligation slots it is allowed. Both only make the wallet more cautious (D23, D24).
- Test-network conditions are not representative of a main network, and nothing here is for use with real funds.
- A trusted co-signer has not been built.
