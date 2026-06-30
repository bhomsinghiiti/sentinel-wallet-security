// Revoke calldata builder — pure, dependency-free. Produces the transaction a user
// signs in their own wallet to kill an approval. Sentinel never signs or holds keys;
// it only hands the wallet the exact (to, data) to submit.
//
// Selectors are the well-known canonical ones:
//   approve(address,uint256)        = 0x095ea7b3   → set ERC-20 allowance to 0
//   setApprovalForAll(address,bool) = 0xa22cb465   → revoke NFT operator
// Permit2 and EIP-7702 delegation revokes must originate inside the wallet app
// (most wallets don't let an external dapp build them yet) → returned as null.

import type { Approval } from "./types.ts";

export interface RevokeTx {
  to: string; // contract to call (the token / collection)
  data: string; // ABI-encoded calldata
  description: string; // plain-language summary for the confirm screen
}

function pad32(value: string): string {
  return value.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

/** Build the revoke transaction for an approval, or null if it must be done in-wallet. */
export function buildRevoke(a: Approval): RevokeTx | null {
  if (!a.token || !/^0x[0-9a-fA-F]{40}$/.test(a.token)) return null;

  if (a.kind === "erc20" || a.kind === "erc20-permit") {
    // approve(spender, 0)
    return {
      to: a.token,
      data: "0x095ea7b3" + pad32(a.spender.address) + pad32("0"),
      description: `Set ${a.asset} allowance for ${a.spender.label ?? a.spender.address} to 0`,
    };
  }

  if (a.kind === "nft") {
    // setApprovalForAll(operator, false)
    return {
      to: a.token,
      data: "0xa22cb465" + pad32(a.spender.address) + pad32("0"),
      description: `Revoke ${a.asset} collection approval for ${a.spender.label ?? a.spender.address}`,
    };
  }

  // Permit2 inner allowances + EIP-7702 delegation resets happen in the wallet.
  return null;
}
