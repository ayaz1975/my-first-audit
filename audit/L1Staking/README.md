# L1Staking audit PoCs

Foundry harness that drives the **real, unmodified** `L1Staking` contract from
[`graphprotocol/contracts`](https://github.com/graphprotocol/contracts)
(`packages/contracts/contracts/staking/L1Staking.sol`, Solidity 0.7.6) to test
six hypotheses about its L2-transfer paths
(`transferStakeToL2` / `transferDelegationToL2` and their token-lock variants).

The contract's logic is never altered. State that production sets via the
(proxy-only) initializer is injected with `vm.store` at slots taken from
`forge inspect ... storageLayout`. `forge-std` (Solidity 0.8) is incompatible
with the `^0.7.6` pragma, so the `Vm` cheatcode interface is declared by hand in
each test.

## Run

```bash
cd audit/L1Staking
./vendor.sh      # one-time: clones graphprotocol/contracts + OpenZeppelin v3.4.2 into ./vendor
forge test -vv
```

Expected: **47 tests pass** across 6 suites.

## What each suite checks

| File | Hypothesis | Verdict |
|------|------------|---------|
| `test/L1StakingReentrancy.t.sol` | #12 — reentrancy / CEI violation on the L2 bridge call | **disproven** — CEI (`tokensStaked` zeroed before the external call) + indexer derived from `msg.sender`; an adversarial gateway cannot double-spend |
| `test/L1StakingDelegationRounding.t.sol` | #4 — share rounding in `_transferDelegationToL2` | **disproven** — exact token conservation; per-exit loss < 1 wei; residual dust < (#delegators) wei, swept by the last delegator; no theft, no profitable farming |
| `test/L1StakingDelegationRoundingCycles.t.sol` | #4 (part 2) — rounding over full `delegate()` → `transferDelegationToL2()` round trips | **disproven** — both divisions floor *against* the exiting user; 200 cycles cost the attacker 249 wei and gave the honest whale exactly 249 wei; pool can never be bricked with `shares == 0 && tokens > 0`; conservation is exact to the wei |
| `test/L1StakingMinimumStake.t.sol` | #2 — minimum-stake threshold asymmetry | **disproven** — L2 indexer always created with ≥ minimum (INV-1); L1 never left with `0 < stake < minimum` (INV-2); the small-`_amount` subsequent transfers are safe |
| `test/L1StakingLockedDelegation.t.sol` | #5 — `transferLockedDelegationToL2`: reentrancy via `pullETH`, spoofing the ETH balance check, replay | **disproven** for third parties — the CEI violation is unexploitable (`_delegator` is `msg.sender`; `delegation.shares != 0` blocks replay); the balance check is a same-tx *delta* with strict equality, so it cannot be satisfied by pre-existing, nested, or absent ETH. **Two trust/robustness notes reported**: a compromised transfer tool can redirect the L2 beneficiary (governor-set, proven in `test_R9`), and ETH force-sent into L1Staking is permanently stuck (no withdrawal path exists) |
| `test/L1StakingLockedStake.t.sol` | #6 — `transferLockedStakeToL2`: the indexer-stake twin | **disproven** — the stake path is decremental and intentionally re-callable, so it has no idempotency guard; safety comes instead from `SafeMath.sub`, the minimum-stake invariant and the allocation-capacity check, all re-evaluated on fresh state per call. `tokensAllocated` / `tokensLocked` are never mutated. CEI vs the bridge is proven directly: a reentrant gateway observes the *already-decremented* stake. **Better than the delegation path**: the L2 beneficiary is pinned on the first transfer, so a tool compromised later cannot redirect. **One informational finding**: no `_amount != 0` check, so a zero-amount transfer buys an empty L2 ticket and burns ETH (self-griefing only) |

Each suite includes control/non-vacuity checks proving the code path is really
exercised (e.g. the reentrant call is actually made and reverts with
`tokensStaked == 0`; dust is genuinely swept then bounded).

## Layout

```
audit/L1Staking/
├── foundry.toml          # isolated project, remaps @gp / @graphprotocol/interfaces / @openzeppelin
├── remappings.txt        # same remappings (for editors/tooling)
├── vendor.sh             # fetches the exact dependencies into ./vendor (gitignored)
├── .gitignore            # ignores vendor/, out/, cache/
├── src/                  # empty (tests define their own helper contracts inline)
└── test/
    ├── L1StakingReentrancy.t.sol
    ├── L1StakingDelegationRounding.t.sol
    ├── L1StakingDelegationRoundingCycles.t.sol
    ├── L1StakingLockedDelegation.t.sol
    ├── L1StakingLockedStake.t.sol
    └── L1StakingMinimumStake.t.sol
```

### Note on the "Cycles" suite

`L1StakingDelegationRoundingCycles.t.sol` is the only suite that also drives
`StakingExtension.delegate()`. It does so through the **real** production path:
`extensionImpl` and `GraphUpgradeable.IMPLEMENTATION_SLOT` are written with
`vm.store`, so a call to `delegate()` on the `L1Staking` address hits the real
assembly `fallback()` and `delegatecall`s the real `StakingExtension` — exactly
as it happens behind the proxy on mainnet.

Delegation rewards (`pool.tokens` credited **without** minting shares) are
injected with `vm.store` rather than dragged in via `RewardsManager` +
allocation closing. This is the only mechanism that moves the pool's exchange
rate off 1:1, and without it the floor divisions would never truncate and every
rounding test would be vacuous.
