# Sentinel — Build Roadmap

> Free, non-custodial wallet-security tool. Revoke risky token approvals and
> detect/reset malicious **EIP-7702 delegations** — the fresh attack surface
> revoke.cash structurally can't address.

**Why this product (one line):** for a two-builder team with no network, the
bottleneck is trust + distribution, not building. Security tooling is the one
category fundable on **merit** (grants/hackathons), its output is fear-driven and
shareable so it spreads without an audience, it never touches funds (no custody/
legal wall), and the EIP-7702 gap is currently unowned.

**Honest ceiling:** a grant-funded salary now, with ~12% odds of a low-seven-figure
acqui-hire (comps: Wallet Guard → Consensys, Pocket Universe → Kerberus). Wealth
comes later from a B2B threat-data API + the dataset we accumulate — never from a
consumer fee. The build was never the hard part; distribution is.

---

## Phase 0 — Spike  ✅ DONE (this commit)

**Goal:** prove the two load-bearing facts cheaply — (a) a clean, testable risk
engine, and (b) we can detect a 7702 delegation from a real on-chain read.

- [x] Pure, dependency-free **risk engine** (`src/core/risk.ts`) — classifies every
      approval into critical/high/medium/low with a plain-language reason, and scores
      the wallet 0–100. 12 rules, fully unit-tested.
- [x] **EIP-7702 delegation detector** (`src/core/delegation.ts`) — parses
      `eth_getCode` (`0xef0100 || <delegate>`), flags known sweepers. The wedge.
- [x] **Live on-chain read** (`src/chain/`) — raw JSON-RPC over `fetch`, zero deps;
      `--live <addr>` detects real delegations (verified live against mainnet).
- [x] Realistic **fixture wallet** + terminal **report renderer**.
- [x] **22 passing tests** (`node --test`), no external dependencies, runs on Node ≥22.6.

**Advance metric:** ✅ `npm test` green + a real on-chain delegation detected.

---

## Phase 1 — Revoke MVP (web app)  — 3–6 weeks

**Goal:** a hosted web app: connect a wallet (read-only), see ranked approvals +
any 7702 delegation, and **revoke** in a transaction the user signs.

- [ ] Next.js + wagmi/viem frontend; wallet connect (read-only).
- [ ] **Live approval enumeration**: `eth_getLogs` for `Approval`/`ApprovalForAll`
      + Permit2, fold to current allowances (port the engine — it's already done).
- [ ] **Revoke flow**: client-side, deterministic `approve(spender,0)` /
      `setApprovalForAll(false)` / 7702 reset-to-zero — user signs, we hold no keys.
- [ ] Spender-reputation list (seed from Scam Sniffer's free feed) + the shareable
      "scary summary" card (the growth loop).
- [ ] Frame every output as a **risk signal, not a verdict**; no-warranty ToS.
- **Funding milestone:** submit to an **ETHGlobal** security/wallet bounty
      ($2K–$20K, stackable). **Advance when:** live, and revokes real approvals.

## Phase 2 — Simulation extension  — 3–5 months

**Goal:** a browser extension that simulates a pending tx and warns *before* signing.

- [ ] Decode/classify pending tx (drain, setApprovalForAll, permit, 7702 auth).
- [ ] Self-host an Anvil/reth fork for simulation (not Tenderly's paid API).
- [ ] **Security-of-the-security-tool is priority #1**: reproducible + signed builds
      with published hashes, full open-source, a paid audit before shipping.
- **Funding:** EF ESP security RFP + repeat Optimism RetroPGF on accrued usage.

## Phase 3 — B2B threat-data API  — months 12–24

**Goal:** productize the dataset — the only path that builds equity.

- [ ] Metered REST risk API + open npm SDK + drainer-address feed.
- [ ] Behavioral/heuristic detection that generalizes (survives address rotation).
- **The free tool is the data-collection funnel; the data is the asset.**

## Phase 4 — Outcome

- Acqui-hire (team + users + dataset + a wallet relationship), or compounding API ARR.

---

## What Claude builds vs. what we own

- **Claude builds:** all the engineering above — engine, indexer, revoke flows,
  extension plumbing, the API. (Phase 0 is already done.)
- **We own (the part Claude can't):** the risk methodology (which signals earn
  trust), the curated spender/sweeper dataset, and **distribution** (winning the
  first grant, the first 1,000 users). That's the whole game.

## Run it

```sh
npm test            # 22 tests, no install needed (Node ≥22.6)
npm run scan        # offline demo on the sample wallet
node src/cli/scan.ts --live 0xYourAddress   # real on-chain 7702 check
```
