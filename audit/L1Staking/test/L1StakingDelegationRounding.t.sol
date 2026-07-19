// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.7.6;
pragma abicoder v2;

// ---------------------------------------------------------------------------
// HYPOTHESIS #4: share rounding in L1Staking._transferDelegationToL2.
//
//   uint256 tokensToSend = delegation.shares.mul(pool.tokens).div(pool.shares);
//   pool.tokens  = pool.tokens.sub(tokensToSend);
//   pool.shares  = pool.shares.sub(delegation.shares);
//   delegation.shares = 0;
//
// We drive the REAL, UNMODIFIED L1Staking and the REAL DelegationPool /
// Delegation structs (state injected via vm.store at slots taken from
// `forge inspect storageLayout`; no L1Staking logic is altered).
//
// Checks, per delegator transfer and in aggregate:
//   (1) A delegator can never receive MORE than their fair share  -> no theft.
//   (2) A delegator's rounding loss is < 1 token base-unit (wei)   -> negligible.
//   (3) Token conservation is EXACT: sum(sent) + remaining == initial.
//   (4) Draining every delegator sends out exactly the initial pool tokens,
//       i.e. no tokens are destroyed and none are created.
//   (5) The residual "dust" that can be swept by the last delegator is
//       bounded by (#delegators) wei and cannot be farmed for profit.
// ---------------------------------------------------------------------------

import { L1Staking } from "@gp/staking/L1Staking.sol";
import { Controller } from "@gp/governance/Controller.sol";

interface Vm {
    function store(address account, bytes32 slot, bytes32 value) external;
    function load(address account, bytes32 slot) external view returns (bytes32);
    function prank(address sender) external;
}

contract RealL1Staking is L1Staking {}

contract MockGRT {
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}

// Records how many tokens L1Staking hands to the bridge on each transfer.
contract RecordingGateway {
    uint256 public totalTokens;
    function outboundTransfer(
        address,
        address,
        uint256 amount,
        uint256,
        uint256,
        bytes calldata
    ) external payable returns (bytes memory) {
        totalTokens += amount;
        return "";
    }
}

contract L1StakingDelegationRoundingTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    uint256 constant SLOT_CONTROLLER = 0;
    uint256 constant SLOT_DELEGATION_POOLS = 20;
    uint256 constant SLOT_INDEXER_TRANSFERRED = 76;

    address constant INDEXER = address(0x1DECE);
    address constant L2BEN = address(0xB0B);
    address constant L2_INDEXER = address(0x1D5E7); // indexerTransferredToL2 target

    Controller controller;
    MockGRT grt;
    RecordingGateway gw;
    RealL1Staking staking;

    function setUp() public {
        controller = new Controller();
        controller.setPaused(false);
        grt = new MockGRT();
        gw = new RecordingGateway();
        controller.setContractProxy(keccak256("GraphToken"), address(grt));
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(gw));

        staking = new RealL1Staking();
        vm.store(address(staking), bytes32(SLOT_CONTROLLER), bytes32(uint256(address(controller))));
        // Mark the indexer as already transferred to L2 (precondition).
        vm.store(address(staking), _indexerTransferredSlot(INDEXER), bytes32(uint256(L2_INDEXER)));
    }

    // ---- storage-slot helpers for the real DelegationPool layout ----
    function _poolBase(address indexer) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(indexer, SLOT_DELEGATION_POOLS)));
    }
    function _poolTokensSlot(address indexer) internal pure returns (bytes32) {
        return bytes32(_poolBase(indexer) + 2);
    }
    function _poolSharesSlot(address indexer) internal pure returns (bytes32) {
        return bytes32(_poolBase(indexer) + 3);
    }
    function _delegationSharesSlot(address indexer, address delegator) internal pure returns (bytes32) {
        uint256 delegatorsMapSlot = _poolBase(indexer) + 4;
        return keccak256(abi.encode(delegator, delegatorsMapSlot)); // Delegation.shares at offset 0
    }
    function _indexerTransferredSlot(address indexer) internal pure returns (bytes32) {
        return keccak256(abi.encode(indexer, SLOT_INDEXER_TRANSFERRED));
    }

    function _setPool(uint256 tokens, uint256 shares) internal {
        vm.store(address(staking), _poolTokensSlot(INDEXER), bytes32(tokens));
        vm.store(address(staking), _poolSharesSlot(INDEXER), bytes32(shares));
    }
    function _setDelegatorShares(address delegator, uint256 shares) internal {
        vm.store(address(staking), _delegationSharesSlot(INDEXER, delegator), bytes32(shares));
    }
    function _poolTokens() internal view returns (uint256) {
        return uint256(vm.load(address(staking), _poolTokensSlot(INDEXER)));
    }
    function _poolShares() internal view returns (uint256) {
        return uint256(vm.load(address(staking), _poolSharesSlot(INDEXER)));
    }

    function _delegator(uint256 i) internal pure returns (address) {
        return address(uint160(0x100000 + i));
    }

    // Runs a full scenario: `n` delegators with the given share amounts, an
    // initial pool of (initialTokens, initialShares). Transfers every delegator
    // in order and enforces all rounding invariants. Returns total dust swept
    // relative to exact proportional payouts.
    function _runScenario(
        uint256 initialTokens,
        uint256 initialShares,
        uint256[] memory shares
    ) internal returns (uint256 totalSent, uint256 sumFloorFairFirstRate) {
        _setPool(initialTokens, initialShares);
        for (uint256 i = 0; i < shares.length; i++) {
            _setDelegatorShares(_delegator(i), shares[i]);
        }

        uint256 sentBefore = gw.totalTokens();
        uint256 cumulativeSent = 0;

        for (uint256 i = 0; i < shares.length; i++) {
            uint256 tokensBefore = _poolTokens();
            uint256 sharesBefore = _poolShares();

            uint256 gwBefore = gw.totalTokens();
            vm.prank(_delegator(i));
            staking.transferDelegationToL2(INDEXER, L2BEN, 0, 0, 0);
            uint256 sent = gw.totalTokens() - gwBefore;

            // (1) NO THEFT: tokensToSend <= fair share at transfer time.
            //     sent <= shares_i * tokensBefore / sharesBefore, checked
            //     cross-multiplied to avoid its own rounding.
            require(
                sent * sharesBefore <= shares[i] * tokensBefore,
                "THEFT: received more than fair share"
            );
            // (2) LOSS BOUNDED: fair - sent < 1 token unit (wei), i.e. the
            //     truncated remainder is strictly less than sharesBefore.
            require(
                (shares[i] * tokensBefore) - (sent * sharesBefore) < sharesBefore,
                "loss exceeds 1 wei"
            );
            // Contract must compute exactly floor(shares*tokens/shares).
            require(sent == (shares[i] * tokensBefore) / sharesBefore, "not floor division");

            // (3) EXACT CONSERVATION at every step.
            cumulativeSent += sent;
            require(_poolTokens() == initialTokens - cumulativeSent, "conservation broken");
            require(_poolShares() == sharesBefore - shares[i], "share accounting broken");
        }

        totalSent = gw.totalTokens() - sentBefore;
        sumFloorFairFirstRate = 0; // (unused placeholder kept for signature clarity)
    }

    // -------------------------------------------------------------------
    // Scenario A: tiny, adversarially-chosen numbers to MAXIMISE relative
    // rounding error. Pool 100 units / 7 shares; delegators 3,3,1 shares.
    // Fair payouts (of 100): 42.857, 42.857, 14.285. Floor forces visible
    // dust that the last delegator ends up sweeping.
    // -------------------------------------------------------------------
    function test_A_tinyExaggeratedRoundingIsSafe() public {
        uint256[] memory shares = new uint256[](3);
        shares[0] = 3;
        shares[1] = 3;
        shares[2] = 1;

        (uint256 totalSent, ) = _runScenario(100, 7, shares);

        // (4) Draining everyone sends EXACTLY the initial pool: nothing lost,
        //     nothing minted. All "dust" was internal redistribution.
        require(totalSent == 100, "full drain must send exactly initial tokens");
        require(_poolTokens() == 0, "pool must be empty after full drain");
        require(_poolShares() == 0, "pool shares must be zero after full drain");
    }

    // -------------------------------------------------------------------
    // Scenario B: realistic 18-decimal scale with a coprime rate so every
    // delegator truncates. 1,000,000 GRT over 999,983 shares, 50 delegators.
    // Shows the aggregate dust is at most (#delegators) wei == economically
    // zero, and conservation holds exactly.
    // -------------------------------------------------------------------
    function test_B_realisticScaleDustIsNegligible() public {
        uint256 n = 50;
        uint256[] memory shares = new uint256[](n);
        uint256 totalShares = 0;
        for (uint256 i = 0; i < n; i++) {
            // Irregular share sizes so divisions rarely land exact.
            shares[i] = 17371 + i * 911;
            totalShares += shares[i];
        }
        uint256 initialTokens = 1_000_000 ether; // 1e24 wei

        (uint256 totalSent, ) = _runScenario(initialTokens, totalShares, shares);

        // (4)+(5): exact conservation; the last delegator sweeps the residual,
        // so the whole pool leaves and the total residual "dust" that was ever
        // redistributed is < n wei -> < 50e-18 GRT. Not economically significant.
        require(totalSent == initialTokens, "full drain must conserve tokens exactly");
        require(_poolTokens() == 0, "pool empty after full drain");
    }

    // -------------------------------------------------------------------
    // Scenario C: attacker tries to FARM dust. A whale delegator leaves LAST
    // to sweep everyone else's rounding remainders. We prove the sweep the
    // attacker gains is bounded by (#victims) wei and is dwarfed to zero.
    // The attacker can never receive more than the pool actually holds.
    // -------------------------------------------------------------------
    function test_C_dustFarmingYieldsNoProfit() public {
        uint256 nVictims = 100;
        uint256[] memory shares = new uint256[](nVictims + 1);
        uint256 totalShares = 0;
        for (uint256 i = 0; i < nVictims; i++) {
            shares[i] = 1000 + i; // small victims, each truncates a sub-wei bit
            totalShares += shares[i];
        }
        // Attacker is the LAST to transfer and owns a large share.
        uint256 attackerShares = 500_000;
        shares[nVictims] = attackerShares;
        totalShares += attackerShares;

        uint256 initialTokens = 3_141_592_653_589_793 ether / 1e9; // arbitrary, coprime-ish

        _setPool(initialTokens, totalShares);
        for (uint256 i = 0; i < shares.length; i++) {
            _setDelegatorShares(_delegator(i), shares[i]);
        }

        // What the attacker would get with EXACT proportional math, pre-rounding,
        // against the ORIGINAL pool (their honest entitlement).
        uint256 attackerFairOriginal = (attackerShares * initialTokens) / totalShares;

        // Transfer all victims first.
        for (uint256 i = 0; i < nVictims; i++) {
            vm.prank(_delegator(i));
            staking.transferDelegationToL2(INDEXER, L2BEN, 0, 0, 0);
        }
        // Attacker transfers last and sweeps whatever remains.
        uint256 gwBefore = gw.totalTokens();
        vm.prank(_delegator(nVictims));
        staking.transferDelegationToL2(INDEXER, L2BEN, 0, 0, 0);
        uint256 attackerGot = gw.totalTokens() - gwBefore;

        // The attacker's "extra" over their original fair entitlement is the
        // accumulated dust: it must be < nVictims wei. That is the entire
        // theoretical prize, independent of scale -> economically zero, and
        // far below the gas the victims/attacker paid.
        require(attackerGot >= attackerFairOriginal, "sweeper should get >= fair (dust flows up)");
        // Non-vacuous: with 100 truncating victims some dust really IS swept...
        require(attackerGot - attackerFairOriginal > 0, "expected some dust to be swept");
        // ...yet the whole prize is still < nVictims wei -> economically zero.
        require(
            attackerGot - attackerFairOriginal < nVictims,
            "PROFIT: sweep exceeds bounded dust"
        );
        // And the sweep never exceeds what the pool physically held.
        require(_poolTokens() == 0 && _poolShares() == 0, "pool fully drained");
    }
}
