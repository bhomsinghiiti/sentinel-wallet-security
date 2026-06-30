# 🛡 Sentinel

**See everything that can drain your wallet — and shut it off in one click.**

Sentinel scans an Ethereum wallet for the things attackers actually use to steal funds —
risky token **approvals**, hidden **Permit2** allowances, and malicious **EIP-7702
delegations** — ranks them by real dollars at risk, and lets you revoke each one in a
transaction *you* sign. It's free, open-source, and **non-custodial: it holds no keys and
never moves your money.**

> Why this matters: in 2025, approval/permit-signature phishing drove a large share of
> seven-figure wallet thefts, and the post-Pectra **EIP-7702 "sweeper" delegation** became a
> live attack family — one victim reportedly lost **$1.54M** from a single malicious
> delegation. Most approval tools can't even see a 7702 delegation. Sentinel does.

```text
  🛡  SENTINEL — wallet risk scan
  0x9C8f…A31b0

  Risk score: 100/100 · CRITICAL   |   At risk: $96,404   |   2 critical, 2 high, 2 med, 1 low
  ────────────────────────────────────────────────────────────────
  CRITICAL  ACCOUNT → CrimeEnjoyor sweeper        [EIP-7702 delegation]
            Your account is delegated to a known sweeper — funds that arrive can be
            auto-forwarded to an attacker. Reset the delegation to the zero address.
  CRITICAL  USDC    → Fake Permit2 (phishing)     [Unlimited]
            The spender is a known wallet drainer. Your USDC can be taken at any moment.
  HIGH      BAYC    → Unverified marketplace       [ALL NFTs]   setApprovalForAll to an unverified contract.
  HIGH      WETH    → 0x4ae1…90bd                  [Unlimited]  Untouched 412 days, unknown contract.
  MEDIUM    USDT    → 1inch Router v5              [Unlimited]  Routine, but capping limits damage.
  LOW       wstETH  → Lido Withdrawal              [8.4]        Healthy approval.
  ────────────────────────────────────────────────────────────────
  Read-only & non-custodial. Every revoke is a tx you sign yourself.
```

## What makes it trustworthy (not just another scanner)

- **It doesn't cry wolf.** A curated allowlist + [GoPlus](https://gopluslabs.io) reputation
  mean blue-chip protocols (Uniswap, Aave, CoW, 1inch) read **MEDIUM "routine"**, not a wall
  of false CRITICALs. CRITICAL is reserved for *confirmed* danger.
- **It catches real bad actors.** Live GoPlus checks flag known drainer / phishing /
  sanctioned spenders, and honeypot tokens — not just fixtures.
- **Real dollars at risk.** Value = `balanceOf × price` ([DefiLlama](https://defillama.com),
  with a confidence guard to ignore fake spam-token liquidity).
- **The EIP-7702 wedge.** Detects account-level delegations (`eth_getCode` → `0xef0100…`)
  that token-approval tools structurally can't.
- **One-click revoke.** Builds `approve(spender,0)` / `setApprovalForAll(false)` calldata;
  you sign it in your own wallet.

## Quickstart

Needs **Node ≥ 22.6** (runs TypeScript directly — no build, no dependencies).

```sh
npm test                                    # 28 tests, zero dependencies
npm run scan                                # offline demo (the output above)
node src/cli/scan.ts --live 0xYourAddress   # real on-chain EIP-7702 delegation check
```

### Live web app (read real approvals)

The EIP-7702 check is keyless. To read a wallet's **real approvals**, add a free
[Etherscan API key](https://etherscan.io/myapikey) (anonymous RPCs cap the full-history
query — see [`docs/APPROVAL-DATA.md`](./docs/APPROVAL-DATA.md)):

```sh
cp .env.example .env        # put your key in ETHERSCAN_KEY
ETHERSCAN_KEY=your_key PORT=7702 npm run web
```

Open **http://localhost:7702**, paste an address (or connect a wallet, read-only), and scan.
Discovery runs through Etherscan v2; current allowances are verified with keyless `eth_call`;
reputation (GoPlus) and prices (DefiLlama) need **no key**. Verified live against mainnet.

## How it works

```
discover (Etherscan v2 logs)  →  verify current allowance (eth_call)
   →  enrich: allowlist + GoPlus reputation + DefiLlama price  →  rank  →  revoke (you sign)
```

The data source is swappable; the pure, unit-tested risk engine (`src/core/risk.ts`) never
changes. **Non-custodial is the design, not a footnote** — Sentinel never holds keys, never
moves funds, and takes no fee. See [`ROADMAP.md`](./ROADMAP.md) for what's next
(Multicall3 batching, Permit2 inner-allowance enumeration, a browser extension).

## Layout

```
src/core/    risk.ts · delegation.ts · revoke.ts · allowlist.ts · types.ts   (pure, tested)
src/chain/   etherscan.ts · approvals.ts · reputation.ts · prices.ts · rpc.ts (live reads)
src/web/     server.ts        # the local web app
src/cli/     scan.ts          # CLI entry
```

MIT licensed. Not financial or security advice — Sentinel surfaces risk *signals*; always
verify before you sign.
