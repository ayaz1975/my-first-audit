# Smart Contract Security — Audit Practice

Hands-on smart contract vulnerability research and Proof-of-Concept exploits,
written in Solidity and tested with [Foundry](https://getfoundry.sh/).

For each vulnerability class I take a real (or realistic) contract, reproduce the
bug, and write a Foundry test that **proves** the exploit — the way a security
researcher demonstrates a finding.

> ⚠️ **Educational / research only.** All targets are public, already-audited, or
> retired contracts. No live vulnerability is disclosed here. Responsible
> disclosure is always followed for real bug bounties.

## Vulnerability classes covered

| # | Vulnerability | Target | PoC test |
|---|---------------|--------|----------|
| 1 | Access Control (missing owner check) | `Bank.sol` | `test/BankHack.t.sol` |
| 2 | Reentrancy (Checks-Effects-Interactions) | `WETH9Vulnerable` | `test/WETH9Drain.t.sol` |
| 3 | Integer Overflow (`batchTransfer`, real 2018 hack) | `BecToken` | `test/BecHack.t.sol` |
| 4 | Owner over-privilege / centralization | `ERC20Token` | `test/ERC20TokenHack.t.sol` |
| 5 | Same-block guard bypass, chained to Critical | `IdleCDO` | `test/IdleCDOSameBlockProfitPoC.t.sol` |

## Highlight — chaining two issues into a Critical

In the `IdleCDO` study I combined two lower-severity issues:
- a **same-block guard bypass** (single global slot + `tx.origin`), and
- a **share-price jump** on `harvest`

into a single-block attack where the attacker withdraws **more than deposited**
(9000 in → 9180 out), stealing yield from an honest LP. A control test proves the
guard blocks the attack when it is *not* bypassed, isolating the exact root cause.

## Tools
- **Foundry** (`forge`) — testing and exploit PoCs
- **Solidity**, `vm.prank` / `vm.deal` / `deployCode`, fork testing

## Run
```bash
forge install
forge test -vvv
```

## About
Aspiring smart contract security researcher / white-hat auditor. Learning in public.
