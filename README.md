# 🛡 Sentinel

**Free, non-custodial wallet-security tool.** See everything that can drain your
wallet — risky token approvals and malicious **EIP-7702 delegations** — and revoke
it yourself. Sentinel holds no keys, moves no funds, takes no fee.

> **v0.1 (Phase 0 spike).** The risk engine, the EIP-7702 detector, tests, and a
> live on-chain delegation check all work today. The web app (revoke flow) is
> Phase 1 — see [`ROADMAP.md`](./ROADMAP.md).

## What works now

- **Risk engine** — classifies every approval (unlimited allowance, flagged/drainer
  spender, collection-wide NFT approval, stale grants, …) into critical/high/medium/
  low with a plain-language reason, and scores the wallet 0–100. Pure & unit-tested.
- **EIP-7702 delegation detector** — the wedge revoke.cash can't do. Reads an
  account's on-chain code (`0xef0100 || delegate`) and flags known sweepers.
- **Live mode** — a real `eth_getCode` read against mainnet.

## Run it (no install — needs Node ≥ 22.6)

```sh
npm test                                    # 22 tests, zero dependencies
npm run scan                                # offline demo on a realistic sample wallet
node src/cli/scan.ts --live 0xYourAddress   # real on-chain EIP-7702 delegation check
```

## Live web app — read real approvals

The EIP-7702 delegation check works with no key. To read a wallet's **real approvals**,
add a free [Etherscan API key](https://etherscan.io/myapikey) (anonymous public RPCs
cap the full-history query — see [`docs/APPROVAL-DATA.md`](./docs/APPROVAL-DATA.md)):

```sh
cp .env.example .env        # then put your key in ETHERSCAN_KEY
export $(grep -v '^#' .env | xargs)   # or just inline it on the next line
ETHERSCAN_KEY=your_key PORT=7702 npm run web
```

Open **http://localhost:7702**, paste an address (or connect a wallet, read-only),
and scan. Discovery runs through Etherscan v2; current allowances are verified with
keyless `eth_call`. Verified live against mainnet.

## Layout

```
src/
  core/        # pure, dependency-free logic (the product's brain)
    types.ts        risk.ts        delegation.ts    report.ts
    risk.test.ts    delegation.test.ts
  chain/       # live on-chain reads (raw JSON-RPC over fetch, no deps)
    rpc.ts          scan.ts
  fixtures/    # realistic sample wallet for the offline demo
  cli/         # the v1 entry point
```

**Design rule:** the data source (live RPC, fixture, future indexer) is swappable;
the pure risk engine never changes. Non-custodial is the brand, not an apology.

MIT licensed. Not financial or security advice — Sentinel shows risk *signals*.
