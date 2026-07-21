// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.7.6;
pragma abicoder v2;

// ---------------------------------------------------------------------------
// HYPOTHESIS #4 (part 2): rounding in L1Staking._transferDelegationToL2, driven
// through FULL ROUND TRIPS of the REAL protocol code:
//
//   StakingExtension._delegate:
//       shares = delegatedTokens.mul(pool.shares).div(pool.tokens)   // floor
//       pool.tokens += delegatedTokens;  pool.shares += shares
//
//   L1Staking._transferDelegationToL2:
//       tokensToSend = delegation.shares.mul(pool.tokens).div(pool.shares) // floor
//       pool.tokens -= tokensToSend;     pool.shares -= delegation.shares
//
// Nothing is reimplemented: `delegate()` is called on the real L1Staking
// address and reaches the real StakingExtension through the real assembly
// fallback (delegatecall), exactly as in production behind the proxy.
//
// Questions answered (one test each):
//   Q1 can rounding make a delegator lose funds?            -> testFuzz_Q1_*
//   Q2 can repeated migrations accumulate dust?             -> test_Q2_*
//   Q3 can another user capture the accumulated dust?       -> test_Q3_*
//   Q4 can repeated migrations be economically profitable?  -> test_Q4_*
//   Q5 is delegated stake conserved across migrations?      -> testFuzz_Q5_*, test_Q5_*
//   extra: can the pool be bricked by leftover dust
//          (shares == 0 while tokens > 0 => delegate() reverts "!shares")?
//                                                           -> testFuzz_X_*
// ---------------------------------------------------------------------------

import { L1Staking } from "@gp/staking/L1Staking.sol";
import { StakingExtension } from "@gp/staking/StakingExtension.sol";
import { Controller } from "@gp/governance/Controller.sol";

interface Vm {
    function store(address account, bytes32 slot, bytes32 value) external;
    function load(address account, bytes32 slot) external view returns (bytes32);
    function prank(address sender) external;
    function assume(bool condition) external;
    function expectRevert(bytes calldata revertData) external;
}

// The real contracts, deployed as-is (no logic overrides).
contract RealL1Staking is L1Staking {}
contract RealStakingExtension is StakingExtension {}

interface IDelegate {
    function delegate(address indexer, uint256 tokens) external returns (uint256);
}

// GraphToken stub: only the calls the delegation path actually makes.
contract MockGRT {
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return true;
    }
    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
    function burn(uint256) external {}
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

contract L1StakingDelegationRoundingCyclesTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    /// Measured quantities, emitted so `forge test -vvv` shows the real numbers.
    event Measured(string what, uint256 value);

    // Slots from `forge inspect L1Staking storageLayout`.
    uint256 constant SLOT_CONTROLLER = 0;
    uint256 constant SLOT_STAKES = 14;
    uint256 constant SLOT_DELEGATION_POOLS = 20;
    uint256 constant SLOT_EXTENSION_IMPL = 25;
    uint256 constant SLOT_INDEXER_TRANSFERRED = 76;
    // GraphUpgradeable.IMPLEMENTATION_SLOT (the fallback requires it != 0).
    bytes32 constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    uint256 constant MINIMUM_DELEGATION = 1e18; // StakingExtension constant

    address constant INDEXER = address(0x1DECE);
    address constant L2BEN = address(0xB0B);
    address constant L2_INDEXER = address(0x1D5E7);
    address constant WHALE = address(0xFEEDBEEF);
    address constant ATTACKER = address(0xA77ACC);

    Controller controller;
    MockGRT grt;
    RecordingGateway gw;
    RealL1Staking staking;
    RealStakingExtension ext;

    function setUp() public {
        controller = new Controller();
        controller.setPaused(false);
        grt = new MockGRT();
        gw = new RecordingGateway();
        controller.setContractProxy(keccak256("GraphToken"), address(grt));
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(gw));

        staking = new RealL1Staking();
        ext = new RealStakingExtension();

        vm.store(address(staking), bytes32(SLOT_CONTROLLER), bytes32(uint256(address(controller))));
        // Wire the extension exactly like Staking.setExtensionImpl would.
        vm.store(address(staking), bytes32(SLOT_EXTENSION_IMPL), bytes32(uint256(address(ext))));
        // The fallback refuses to run unless it believes it is behind a proxy.
        vm.store(address(staking), IMPLEMENTATION_SLOT, bytes32(uint256(address(ext))));
        // Indexer has already (partially) transferred to L2: required by
        // _transferDelegationToL2, while a non-zero tokensStaked keeps
        // _delegate's "!stake" check satisfied (partial transfer scenario).
        vm.store(address(staking), _indexerTransferredSlot(INDEXER), bytes32(uint256(L2_INDEXER)));
        vm.store(address(staking), _stakeTokensStakedSlot(INDEXER), bytes32(uint256(100_000 ether)));
    }

    // ---------------- storage helpers (real layouts) ----------------
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
        return keccak256(abi.encode(delegator, _poolBase(indexer) + 4));
    }
    function _indexerTransferredSlot(address indexer) internal pure returns (bytes32) {
        return keccak256(abi.encode(indexer, SLOT_INDEXER_TRANSFERRED));
    }
    function _stakeTokensStakedSlot(address indexer) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode(indexer, SLOT_STAKES))));
    }

    function _poolTokens() internal view returns (uint256) {
        return uint256(vm.load(address(staking), _poolTokensSlot(INDEXER)));
    }
    function _poolShares() internal view returns (uint256) {
        return uint256(vm.load(address(staking), _poolSharesSlot(INDEXER)));
    }
    function _sharesOf(address delegator) internal view returns (uint256) {
        return uint256(vm.load(address(staking), _delegationSharesSlot(INDEXER, delegator)));
    }
    function _setPool(uint256 tokens, uint256 shares) internal {
        vm.store(address(staking), _poolTokensSlot(INDEXER), bytes32(tokens));
        vm.store(address(staking), _poolSharesSlot(INDEXER), bytes32(shares));
    }
    function _setDelegatorShares(address delegator, uint256 shares) internal {
        vm.store(address(staking), _delegationSharesSlot(INDEXER, delegator), bytes32(shares));
    }

    // Delegation rewards are credited to pool.tokens WITHOUT minting shares
    // (StakingExtension._collectDelegationRewards). That is the only way the
    // exchange rate ever leaves 1:1, and it is what makes the floor division
    // in _transferDelegationToL2 actually truncate. We inject that state
    // directly instead of dragging in RewardsManager + allocation closing.
    function _accrueDelegationRewards(uint256 amount) internal {
        _setPool(_poolTokens() + amount, _poolShares());
    }

    function _delegate(address who, uint256 tokens) internal returns (uint256) {
        vm.prank(who);
        return IDelegate(address(staking)).delegate(INDEXER, tokens);
    }

    function _migrate(address who) internal returns (uint256 sent) {
        uint256 before = gw.totalTokens();
        vm.prank(who);
        staking.transferDelegationToL2(INDEXER, L2BEN, 0, 0, 0);
        sent = gw.totalTokens() - before;
    }

    function _delegator(uint256 i) internal pure returns (address) {
        return address(uint160(0x100000 + i));
    }

    // ===================================================================
    // Q1 + Q5 (fuzzed): for ANY reachable pool state and ANY split of the
    // shares between three delegators, each exit
    //   * pays exactly floor(shares * tokens / poolShares),
    //   * never pays MORE than the exact entitlement (no theft), and
    //   * under-pays by strictly less than 1 token base-unit (1 wei),
    // and token accounting is conserved exactly at every step.
    // ===================================================================
    function testFuzz_Q1_Q5_lossBelowOneWeiAndExactConservation(
        uint64 tokensSeed,
        uint40 s0Seed,
        uint40 s1Seed,
        uint40 s2Seed
    ) public {
        uint256[] memory shares = new uint256[](3);
        shares[0] = uint256(s0Seed) + 1;
        shares[1] = uint256(s1Seed) + 1;
        shares[2] = uint256(s2Seed) + 1;
        uint256 totalShares = shares[0] + shares[1] + shares[2];
        uint256 initialTokens = uint256(tokensSeed) + 1; // 1 .. ~1.8e19 wei

        _setPool(initialTokens, totalShares);
        for (uint256 i = 0; i < 3; i++) {
            _setDelegatorShares(_delegator(i), shares[i]);
        }

        uint256 cumulativeSent = 0;
        for (uint256 i = 0; i < 3; i++) {
            uint256 tokensBefore = _poolTokens();
            uint256 sharesBefore = _poolShares();

            uint256 sent = _migrate(_delegator(i));

            // (a) exactly floor division - the contract does what we think.
            require(sent == (shares[i] * tokensBefore) / sharesBefore, "not floor division");
            // (b) NO THEFT: never more than the exact entitlement.
            require(sent * sharesBefore <= shares[i] * tokensBefore, "received more than fair share");
            // (c) LOSS < 1 wei: the truncated remainder is < sharesBefore.
            require(
                (shares[i] * tokensBefore) - (sent * sharesBefore) < sharesBefore,
                "loss >= 1 wei"
            );
            // (d) EXACT CONSERVATION at every step.
            cumulativeSent += sent;
            require(_poolTokens() == initialTokens - cumulativeSent, "tokens not conserved");
            require(_poolShares() == sharesBefore - shares[i], "shares not conserved");
            require(_sharesOf(_delegator(i)) == 0, "delegation not zeroed");
        }

        // (e) After the last exit the pool is EXACTLY empty: sum(paid out) is
        //     bit-for-bit the initial pool. No token is created or destroyed.
        require(cumulativeSent == initialTokens, "full drain must equal initial tokens");
        require(_poolTokens() == 0 && _poolShares() == 0, "pool must end empty");
    }

    // ===================================================================
    // EXTRA (fuzzed): the only rounding state that could actually hurt is
    // pool.shares == 0 while pool.tokens > 0 -- then _delegate computes
    // shares = tokens * 0 / dust = 0 and reverts "!shares", bricking the pool
    // forever. Prove it is UNREACHABLE: whoever exits last holds 100% of the
    // shares, so their division is exact and drains the pool to zero.
    // Non-vacuous: we then successfully delegate into the drained pool.
    // ===================================================================
    function testFuzz_X_poolCannotBeBrickedByDust(
        uint64 tokensSeed,
        uint40 s0Seed,
        uint40 s1Seed,
        uint40 s2Seed,
        uint8 orderSeed
    ) public {
        uint256[] memory shares = new uint256[](3);
        shares[0] = uint256(s0Seed) + 1;
        shares[1] = uint256(s1Seed) + 1;
        shares[2] = uint256(s2Seed) + 1;
        _setPool(uint256(tokensSeed) + 1, shares[0] + shares[1] + shares[2]);
        for (uint256 i = 0; i < 3; i++) {
            _setDelegatorShares(_delegator(i), shares[i]);
        }

        // Exit in an arbitrary (fuzzed) order.
        uint256[6] memory perms = [uint256(12), 21, 102, 120, 201, 210];
        uint256 p = perms[orderSeed % 6];
        uint256[3] memory order = [p / 100, (p / 10) % 10, p % 10];
        for (uint256 i = 0; i < 3; i++) {
            _migrate(_delegator(order[i]));
        }

        // Whatever the order, the pool ends at (0, 0): never (0 shares, >0 tokens).
        require(_poolShares() == 0, "shares must be zero");
        require(_poolTokens() == 0, "BRICKED: dust left with zero shares");

        // Non-vacuity: the emptied pool is still usable by a fresh delegator.
        uint256 minted = _delegate(WHALE, 10 ether);
        require(minted == 10 ether, "fresh pool must mint 1:1");
    }

    // ===================================================================
    // Q2 + Q4: repeated migration cycles through the REAL delegate() path.
    // The attacker loops delegate() -> transferDelegationToL2() 200 times,
    // trying to farm rounding. Measured per cycle and in aggregate.
    // ===================================================================
    function test_Q2_Q4_repeatedCyclesAccumulateNoDustAndNoProfit() public {
        // Honest whale delegates, then the pool accrues delegation rewards, so
        // the exchange rate is NOT 1:1 and both divisions really truncate.
        _delegate(WHALE, 1_000_000 ether);
        _accrueDelegationRewards(333_333_333_333_333_333_333_333); // ~333_333.33 GRT

        uint256 whaleShares = _sharesOf(WHALE);
        uint256 rateBefore = (_poolTokens() * 1e18) / _poolShares();
        uint256 whaleClaimBefore = (whaleShares * _poolTokens()) / _poolShares();

        uint256 cycles = 200;
        uint256 totalIn = 0;
        uint256 totalOut = 0;
        uint256 cyclesThatTruncated = 0;

        for (uint256 i = 0; i < cycles; i++) {
            // Vary the amount so divisions land on many different remainders.
            uint256 amount = MINIMUM_DELEGATION + (i * 7_919_191_919);
            uint256 poolTokensPre = _poolTokens();
            uint256 poolSharesPre = _poolShares();

            uint256 minted = _delegate(ATTACKER, amount);
            // delegate() also floors: the attacker is short-changed on entry.
            require(minted == (amount * poolSharesPre) / poolTokensPre, "delegate not floor");

            uint256 out = _migrate(ATTACKER);

            // (Q4) A single cycle can NEVER return more than it cost.
            require(out <= amount, "PROFIT: cycle returned more than deposited");
            if (out < amount) cyclesThatTruncated++;

            totalIn += amount;
            totalOut += out;

            // (Q2) The pool never grows an unbacked balance: every wei the
            // attacker leaves behind immediately raises the value of the
            // remaining (whale) shares -- it is redistributed, not stranded.
            require(_sharesOf(ATTACKER) == 0, "attacker shares must be zero");
            require(_poolShares() == whaleShares, "only whale shares must remain");
        }

        // (Q4) Aggregate: strictly loss-making, and the total loss is bounded
        // by ~2 wei per cycle (one floor on entry + one floor on exit).
        require(totalOut < totalIn, "PROFIT: cycling was not loss-making");
        require(totalIn - totalOut <= 2 * cycles, "loss should be bounded by 2 wei/cycle");
        // Non-vacuity: truncation really happened on essentially every cycle.
        require(cyclesThatTruncated > cycles / 2, "test vacuous: no truncation observed");

        // (Q2) "Accumulated dust" = the value transferred to the whale. It is
        // bounded by the attacker's total loss, i.e. < 2 wei per cycle, and it
        // is NOT an unclaimable balance: the rate only moved up.
        uint256 rateAfter = (_poolTokens() * 1e18) / _poolShares();
        require(rateAfter >= rateBefore, "rate must not decrease");
        uint256 whaleClaimAfter = (whaleShares * _poolTokens()) / _poolShares();
        require(whaleClaimAfter >= whaleClaimBefore, "honest delegator must not lose");
        require(
            whaleClaimAfter - whaleClaimBefore <= 2 * cycles,
            "dust gain must stay bounded by the attacker's loss"
        );

        emit Measured("cycles", cycles);
        emit Measured("attacker total in (wei)", totalIn);
        emit Measured("attacker total out (wei)", totalOut);
        emit Measured("attacker net LOSS (wei)", totalIn - totalOut);
        emit Measured("cycles that truncated", cyclesThatTruncated);
        emit Measured("whale dust gain (wei)", whaleClaimAfter - whaleClaimBefore);
    }

    // ===================================================================
    // Q3: can another user capture the accumulated dust? Yes -- and that is
    // the whole prize. The last delegator standing sweeps everything left in
    // the pool. We show the sweep is exact (pool ends empty) and that the
    // captured surplus is bounded by the losses of the delegators before them
    // (sub-wei each), i.e. economically zero and never taken from anyone's
    // principal.
    // ===================================================================
    function test_Q3_lastDelegatorSweepsDustButItIsBounded() public {
        _delegate(WHALE, 1_000_000 ether);
        _accrueDelegationRewards(777_777_777_777_777_777_777_777);

        uint256 nVictims = 100;
        uint256 victimsIn = 0;
        uint256 victimsOut = 0;
        for (uint256 i = 0; i < nVictims; i++) {
            uint256 amount = MINIMUM_DELEGATION + i * 1_234_567_891;
            _delegate(_delegator(i), amount);
            victimsIn += amount;
        }

        uint256 whaleShares = _sharesOf(WHALE);
        uint256 whaleClaimBeforeExits = (whaleShares * _poolTokens()) / _poolShares();

        for (uint256 i = 0; i < nVictims; i++) {
            victimsOut += _migrate(_delegator(i));
        }

        // The whale exits LAST and sweeps whatever the floors left behind.
        uint256 whaleGot = _migrate(WHALE);

        // The sweep is exact: the pool is drained to zero, nothing stranded.
        require(_poolTokens() == 0 && _poolShares() == 0, "pool must be fully drained");

        // The surplus the sweeper captured is exactly (what the victims failed
        // to withdraw) and is bounded by 1 wei per victim exit.
        require(whaleGot >= whaleClaimBeforeExits, "sweeper must not lose");
        uint256 surplus = whaleGot - whaleClaimBeforeExits;
        // Non-vacuity: dust was genuinely produced and genuinely captured.
        require(surplus > 0, "test vacuous: no dust was swept");
        require(surplus <= nVictims, "surplus must be bounded by #exits (wei)");
        // Victims never got more than they put in, so no principal was stolen
        // from the sweeper either.
        require(victimsOut <= victimsIn, "victims must not extract more than deposited");

        emit Measured("victims", nVictims);
        emit Measured("dust captured by sweeper (wei)", surplus);
        emit Measured("victims total in (wei)", victimsIn);
        emit Measured("victims total out (wei)", victimsOut);
        emit Measured("victims aggregate loss (wei)", victimsIn - victimsOut);
    }

    // ===================================================================
    // Q5: end-to-end conservation over a mixed sequence of real delegate()
    // calls, accrued rewards and migrations:
    //     sum(delegated) + sum(rewards) == sum(sent to bridge)
    // exactly, once everybody has migrated. Not one wei is created or lost.
    // ===================================================================
    function test_Q5_endToEndConservationOfDelegatedStake() public {
        uint256 totalDelegated = 0;
        uint256 totalRewards = 0;

        totalDelegated += 500_000 ether;
        _delegate(WHALE, 500_000 ether);

        _accrueDelegationRewards(123_456_789_012_345_678_901);
        totalRewards += 123_456_789_012_345_678_901;

        uint256 n = 25;
        for (uint256 i = 0; i < n; i++) {
            uint256 amount = MINIMUM_DELEGATION + i * 999_999_937;
            _delegate(_delegator(i), amount);
            totalDelegated += amount;

            // Interleave rewards and exits with new delegations.
            if (i % 5 == 4) {
                _accrueDelegationRewards(31_415_926_535_897_932);
                totalRewards += 31_415_926_535_897_932;
            }
            if (i % 3 == 2) {
                _migrate(_delegator(i - 2));
            }
            // Running invariant: the pool holds exactly what came in minus
            // what was bridged out.
            require(
                _poolTokens() == totalDelegated + totalRewards - gw.totalTokens(),
                "running conservation broken"
            );
        }

        // Everyone still holding shares migrates.
        for (uint256 i = 0; i < n; i++) {
            if (_sharesOf(_delegator(i)) != 0) _migrate(_delegator(i));
        }
        _migrate(WHALE);

        require(_poolShares() == 0 && _poolTokens() == 0, "pool must end empty");
        require(
            gw.totalTokens() == totalDelegated + totalRewards,
            "CONSERVATION BROKEN: bridged total != delegated + rewards"
        );
    }
}
