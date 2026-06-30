import { test } from "node:test";
import assert from "node:assert/strict";
import { detectDelegation, DEFAULT_INTEL } from "./delegation.ts";

test("plain EOA (no code) → not delegated", () => {
  assert.deepEqual(detectDelegation("0x"), { delegated: false, malicious: false });
  assert.deepEqual(detectDelegation(""), { delegated: false, malicious: false });
  assert.deepEqual(detectDelegation(null), { delegated: false, malicious: false });
});

test("ordinary contract code → not a 7702 delegation", () => {
  const r = detectDelegation("0x6080604052348015600f57600080fd5b50");
  assert.equal(r.delegated, false);
});

test("7702 delegation to a known sweeper → malicious", () => {
  const sweeper = Object.keys(DEFAULT_INTEL.knownSweepers)[0]; // 0x3d47…002f
  const code = "0xef0100" + sweeper.slice(2);
  const r = detectDelegation(code);
  assert.equal(r.delegated, true);
  assert.equal(r.malicious, true);
  assert.equal(r.delegate, sweeper);
  assert.match(r.delegateLabel ?? "", /sweeper/i);
});

test("7702 delegation to an unknown contract → delegated but not flagged", () => {
  const code = "0xef0100" + "00112233445566778899aabbccddeeff00112233";
  const r = detectDelegation(code);
  assert.equal(r.delegated, true);
  assert.equal(r.malicious, false);
  assert.equal(r.delegate, "0x00112233445566778899aabbccddeeff00112233");
});

test("case-insensitive: uppercase code still parses", () => {
  const code = "0xEF0100" + "00112233445566778899AABBCCDDEEFF00112233";
  const r = detectDelegation(code);
  assert.equal(r.delegated, true);
});
