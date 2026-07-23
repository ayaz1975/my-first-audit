# IdleCDO — Same-Block Guard Bypass Enables Atomic Yield Theft

**Severity:** High / Critical
**Report type:** Smart Contract
**Target:** `src/IdleCDOTranche.sol` (harness `IdleCDOMini` reproduces IdleCDO deposit/withdraw + the original same-block guard)
**Status:** Educational / research — reproduced on an isolated harness, not submitted to a live program.

## Summary

IdleCDO's same-block guard is stored in a single global slot as `keccak256(tx.origin, block.number)`. Because the slot only remembers the *last* depositor of a block, an earlier depositor's guard entry can be overwritten by a second deposit in the same block. Combined with a share-price increase during `harvest`, an attacker can deposit and withdraw within one block and withdraw **more than deposited**, stealing yield that belongs to honest liquidity providers.

## Impact

- Attacker withdraws **more than deposited** in a single block (9000 in → 9180 out).
- The extra 180 is yield that belonged to honest LPs (victim yield drops from 200 to 20).
- The attack is **atomic** and flash-loan compatible, making it **risk-free**.

## Root Cause

On deposit, `_updateCallerBlock` writes `keccak256(tx.origin, block.number)` into a single global slot `_lastCallerBlock`; on withdraw, `_checkSameBlock` compares it. Two weaknesses:

1. **Single global slot** — a second depositor (helper EOA) overwrites the first depositor's entry, so the first depositor is no longer guarded.
2. **`tx.origin` binding** — depositing and withdrawing from different origins (a relayer) also bypasses the check.

## Steps to Reproduce

1. Attacker deposits capital (just-in-time) right before `harvest`.
2. `harvest` raises the tranche share price in the same block.
3. A helper EOA deposits, overwriting the global guard slot.
4. Attacker withdraws in the same block — the guard no longer matches, so there is no revert.
5. Attacker receives more than deposited; the difference is stolen from honest LPs.

## Proof of Concept

See `test/IdleCDOSameBlockProfitPoC.t.sol`:
- `test_Exploit_BypassPlusPriceJump_RealProfitInOneBlock` — proves 9000 in → 9180 out.
- `test_Guard_ActiveBlocksAtomicSandwich` — control test: without the bypass the guard reverts with `SameBlock`, isolating the exact root cause.

```bash
forge test --match-path test/IdleCDOSameBlockProfitPoC.t.sol -vvv
```

## Recommendation

Replace the single global `_lastCallerBlock` with a per-user mapping keyed by `msg.sender`:

```solidity
mapping(address => uint256) private lastDepositBlock;
```

A per-user entry prevents a second depositor from overwriting another user's guard, and using `msg.sender` instead of `tx.origin` closes the relayer bypass.ы