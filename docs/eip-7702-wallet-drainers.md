# EIP-7702 wallet drainers: what they are, how to check, and how to fix it

> A plain-English guide to the newest way wallets get drained — and the one-line
> on-chain check that tells you if you're exposed. Written alongside
> [Sentinel](../README.md), an open-source tool that detects this automatically.

## TL;DR

- Since Ethereum's **Pectra upgrade (May 2025)**, a normal wallet (an EOA) can **delegate
  its code** to a smart contract via **EIP-7702**. This is a genuinely useful feature —
  it's what makes "smart accounts" work.
- Attackers abused it immediately. If you sign a malicious 7702 authorization (usually from
  a phishing site), your **own address starts running the attacker's code**, and any funds
  that land in it can be **swept out automatically — with no further signature from you**.
- **The check is trivial and you can do it right now:** look at your account's on-chain code
  with `eth_getCode`. If it starts with `0xef0100`, your account is delegated, and the next
  20 bytes are the contract it's delegated to.
- **Most approval tools (including revoke.cash) can't remove a malicious 7702 delegation** —
  it lives at the *account* level, not the *token-approval* level, and most wallets don't yet
  expose a way for an external dapp to reset it.

## What EIP-7702 actually does

Before Pectra, an Ethereum address was either a **smart contract** (has code) or a
**regular wallet / EOA** (no code, controlled by a private key). EIP-7702 lets an EOA point
to a contract's code and *run it* — so your wallet can batch transactions, pay gas in tokens,
set spending rules, and so on. Good feature.

On-chain, a delegated account's code is exactly **23 bytes**:

```
0xef0100 || <20-byte address of the contract you delegated to>
```

The `0xef0100` prefix is a fixed marker (it can never execute as real bytecode, by design).
Everything after it is the **delegate** — the contract now acting on your account's behalf.

## How the attack works

1. You land on a phishing site (fake airdrop, fake "claim," fake wallet upgrade prompt).
2. It asks you to sign — but the signature is a **type-`0x04` SetCode authorization** that
   delegates your account to the attacker's "sweeper" contract.
3. From that moment, your address runs the sweeper's code. Any ETH or tokens that arrive
   (or that it can pull) are **auto-forwarded to the attacker** — no further approval needed.

One copy-paste sweeper family (nicknamed **"CrimeEnjoyor"**) accounted for the overwhelming
majority of malicious delegations seen in the wild after Pectra. Reported losses include a
single victim who lost **~$1.54M** in an August 2025 incident; verified aggregate losses in
2025 were on the order of **~$12M across ~15,000 wallets** (smaller than some viral headlines
claimed, but a real and growing attack surface).

## How to check your own wallet (do this now)

Any Ethereum RPC supports `eth_getCode` — no special access, no API key:

```js
// returns "0x" for a normal wallet, or "0xef0100…<delegate>" if delegated
const code = await provider.send("eth_getCode", [yourAddress, "latest"]);
const delegated = code.toLowerCase().startsWith("0xef0100");
const delegate = delegated ? "0x" + code.slice(8) : null;
```

Or just scan your address with [Sentinel](../README.md) (`node src/cli/scan.ts --live 0xYourAddress`),
which does this check and cross-references the delegate against known-sweeper reputation.

**If `delegated` is `false`:** you're not affected by 7702 delegation (you can still have risky
token approvals — that's a separate check).

**If `delegated` is `true`:** identify the delegate. If it's your wallet provider's
smart-account implementation (MetaMask, Ambire, etc.), it's expected and fine. If you don't
recognize it — especially if a reputation feed flags it — treat it as compromised.

## How to fix a malicious delegation

You **revoke a delegation by re-delegating to the zero address** (`0x000…000`) with another
type-`0x04` authorization. After that, `eth_getCode` returns `0x` again and your account is a
plain EOA once more.

The catch — and the reason this is the dangerous gap:

- **It must be done from the wallet itself.** Most wallets don't yet let an external dapp
  build a 7702 reset, so "click revoke on a website" often won't work for delegations the way
  it does for token approvals.
- **If your private key is compromised** (not just tricked into one signature), resetting
  isn't enough — the attacker can re-delegate. In that case, **move your assets to a fresh
  wallet.**

## Why approval tools miss this

Tools like revoke.cash are built around **token approvals** — `Approval` / `ApprovalForAll`
events and `allowance()` state. A 7702 delegation is a different mechanism entirely: it's
account-level code, discovered via `eth_getCode`, not via approval events. That's why a tool
can show "you have no risky approvals" and still miss that your **entire account** is
delegated to a drainer. Checking both is the point.

## The takeaway

EIP-7702 is a good upgrade with a sharp edge: one bad signature can hand your whole account
to an attacker, and the standard "revoke your approvals" advice doesn't cover it. The check is
one `eth_getCode` call away — run it on your wallet, and on any wallet you're about to fund.

---

*Part of [Sentinel](../README.md) — a free, open-source, non-custodial wallet-security tool.
Not financial or security advice; verify before you sign.*
