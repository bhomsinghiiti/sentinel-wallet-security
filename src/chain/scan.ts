// Live scan layer. v1 does the genuinely-real, dependency-free part: read the
// account's on-chain code and detect an EIP-7702 delegation. Approval enumeration
// (eth_getLogs + allowance folding via viem) is the next phase — the architecture
// keeps it behind this same function so the engine/report never change.

import { getCode } from "./rpc.ts";
import { detectDelegation } from "../core/delegation.ts";
import type { DelegationStatus } from "../core/types.ts";

export interface LiveScan {
  address: string;
  delegation: DelegationStatus;
  /** Raw eth_getCode result, for transparency/debugging. */
  rawCode: string;
}

/** Query chain for an address's delegation status (real on-chain read). */
export async function liveScan(address: string, rpcs?: string[]): Promise<LiveScan> {
  const rawCode = await getCode(address, rpcs);
  const delegation = detectDelegation(rawCode);
  return { address, delegation, rawCode };
}
