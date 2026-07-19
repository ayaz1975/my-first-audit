# L1Staking audit PoCs

Foundry harness that drives the **real, unmodified** `L1Staking` contract from
[`graphprotocol/contracts`](https://github.com/graphprotocol/contracts)
(`packages/contracts/contracts/staking/L1Staking.sol`, Solidity 0.7.6) to test
three hypotheses about its L2-transfer path
(`transferStakeToL2` / `transferDelegationToL2`).

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

Expected: **15 tests pass** across 3 suites.

## What each suite checks

| File | Hypothesis | Verdict |
|------|------------|---------|
| `test/L1StakingReentrancy.t.sol` | #12 — reentrancy / CEI violation on the L2 bridge call | **disproven** — CEI (`tokensStaked` zeroed before the external call) + indexer derived from `msg.sender`; an adversarial gateway cannot double-spend |
| `test/L1StakingDelegationRounding.t.sol` | #4 — share rounding in `_transferDelegationToL2` | **disproven** — exact token conservation; per-exit loss < 1 wei; residual dust < (#delegators) wei, swept by the last delegator; no theft, no profitable farming |
| `test/L1StakingMinimumStake.t.sol` | #2 — minimum-stake threshold asymmetry | **disproven** — L2 indexer always created with ≥ minimum (INV-1); L1 never left with `0 < stake < minimum` (INV-2); the small-`_amount` subsequent transfers are safe |

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
    └── L1StakingMinimumStake.t.sol
```
