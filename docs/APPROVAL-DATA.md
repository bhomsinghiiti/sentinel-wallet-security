# How Sentinel reads a wallet's approvals (the data layer)

Verified mid-2026, first-hand (tested against a real wallet) + research-confirmed.

## The model in one line

Approvals are **public on-chain event logs** your past transactions emitted. Reading
them is **read-only** — we never ask the user to grant us anything. It's a two-phase job:

1. **Discover** candidate approvals from event logs.
2. **Verify** the *current* allowance with a view call (events are a history of
   changes, not live state — an old approval may already be spent or revoked).

## Why you can't do discovery on free public RPCs (verified)

A `eth_getLogs` query from block 0 filtered only by the `Approval` topic + owner
(no contract address) is pathological — the node must scan ~22M blocks with no
per-contract bloom index. Every free RPC rejects it. **Tested against a real wallet:**

| RPC | Result |
|---|---|
| PublicNode | `exceed maximum block range: 50000` |
| Ankr | `must authenticate with an API key` |
| llamarpc | rate-limited |
| Cloudflare | `Internal error` (hard 128-block window) |

Documented caps: Alchemy/Infura cap at **10,000 logs** (or Alchemy 2,000-block range);
geth ships a hard `--rpc.rangelimit`; nodes enforce a ~10s timeout. Adding a contract
address makes it tractable; omitting it (which is what "all approvals for a wallet"
needs) makes it fail. **Conclusion: discovery needs an indexed API with a key.**

## The production stack (what revoke.cash / Rabby-class tools use)

### Phase 1 — discover (free key)
- **Etherscan API v2** — `?chainid=1&module=logs&action=getLogs`, free key, 5 calls/s,
  100k/day, 1,000 records/call (paginate). One key works across 60+ chains.
  - ERC-20 `Approval` topic0: `0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925`
  - `ApprovalForAll` topic0: `0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31`
  - owner is indexed `topic1` (`0x` + 24 zeros + address).
- **Or Moralis** — `GET /api/v2.2/wallets/{address}/approvals?chain=eth` returns
  spender + token + value + `usd_at_risk` **enriched in one call** (40k CU/day free).
- **Or Covalent/GoldRush** — `/v1/eth-mainnet/approvals/{address}/` (one-time ~25k credits).

### Phase 2 — verify current state (free key)
- **Alchemy** free tier (300M compute units/mo — effectively unlimited here).
- For each discovered `(token, spender)`: `eth_call` `allowance(owner, spender)`
  (ERC-20) or `isApprovedForAll(owner, operator)` (NFT). Drop zero/false.
- Batch all reads through **Multicall3** (`0xcA11bde05977b3631167028862bE2a173976CA11`,
  `aggregate3` with `allowFailure`).

### Recommendation for us (2-person, ~$0)
**Etherscan v2 (discover) + Alchemy (verify).** NOT a self-hosted indexer — it needs an
archive node + ongoing ops to rebuild what these give free. (Caveat: Nov-2025 Etherscan
dropped free L2s — mainnet `chainid=1` still free; use Alchemy/Moralis for L2s.)

## Two things a real tool must handle that v0.1 doesn't yet

1. **Permit2** (`0x000000000022D473030F116dDEE9F6B43aC78BA3`) — a two-layer model. The
   token approves *Permit2* (a normal Approval), then Permit2 holds per-dApp allowances
   in its **own storage** (amount + expiration + nonce), invisible to `token.allowance()`.
   Must be read separately: `allowance(user, token, spender)` on Permit2, and discovered
   from Permit2's own `Approval`/`Permit`/`Lockdown` events. A plain ERC-20 scan misses
   real exposure here.
2. **EIP-7702 clearing UX** — detection is reliable on any RPC (`eth_getCode` →
   `0xef0100 || delegate`, keyless). But the *clear* action (a type-`0x04` SetCode auth
   to `address(0)`) usually must originate **inside the wallet app** — plan to hand off.

## EIP-7702 detection (what v0.1 already does, confirmed reliable)

`eth_getCode(addr, "latest")` returns the 23-byte `0xef0100 || <20-byte delegate>` for a
delegated EOA, `0x` for a clean one. `eth_getCode` is a core JSON-RPC method on every
provider incl. keyless free RPCs — which is why Sentinel's delegation check works today
with no key. >90% of observed 2025 7702 delegations were drainer-linked.

## What v0.1 does today vs. Phase 1

- **Today:** live 7702 detection (keyless ✓); approval discovery via raw `eth_getLogs`
  (works only with an `ALCHEMY_KEY` and a light wallet; otherwise honestly shows
  "couldn't read — add a key").
- **Phase 1:** swap discovery to **Etherscan v2 / Moralis**, add **Permit2**, batch
  verification via **Multicall3**, hand off 7702 clear to the wallet.
