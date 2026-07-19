// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.7.6;
pragma abicoder v2;

// ---------------------------------------------------------------------------
// HYPOTHESIS #2: minimum-stake threshold in L1Staking._transferStakeToL2.
//
// The check is asymmetric:
//   * FIRST transfer (indexerTransferredToL2 == 0):
//         require(_amount >= __minimumIndexerStake, "!minimumIndexerStake sent");
//   * ALWAYS after the sub:
//         require(tokensStaked == 0 || tokensStaked >= __minimumIndexerStake,
//                 "!minimumIndexerStake remaining");
//   * SUBSEQUENT transfers put NO lower bound on _amount.
//
// Two protocol invariants must hold:
//   INV-1 (L2 side):  the L2 indexer is created with >= minimumIndexerStake
//                     (the first bridged amount).
//   INV-2 (L1 side):  the L1 indexer is never left with 0 < stake < minimum.
//
// Driven against the REAL, UNMODIFIED L1Staking (state injected via vm.store
// at slots from `forge inspect storageLayout`; no contract logic changed).
// ---------------------------------------------------------------------------

import { L1Staking } from "@gp/staking/L1Staking.sol";
import { Controller } from "@gp/governance/Controller.sol";

interface Vm {
    function store(address account, bytes32 slot, bytes32 value) external;
    function load(address account, bytes32 slot) external view returns (bytes32);
}

contract RealL1Staking is L1Staking {}

contract MockGRT {
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}

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

// Acts as the indexer (msg.sender) and reports revert reasons instead of
// bubbling them, so boundary cases can be asserted.
contract IndexerActor {
    RealL1Staking public staking;
    function setStaking(RealL1Staking s) external {
        staking = s;
    }
    function transfer(address beneficiary, uint256 amount)
        external
        returns (bool ok, string memory reason)
    {
        try staking.transferStakeToL2(beneficiary, amount, 0, 0, 0) {
            return (true, "");
        } catch Error(string memory r) {
            return (false, r);
        } catch {
            return (false, "<non-string revert>");
        }
    }
}

contract L1StakingMinimumStakeTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    uint256 constant SLOT_CONTROLLER = 0;
    uint256 constant SLOT_MIN_STAKE = 12;
    uint256 constant SLOT_STAKES_MAP = 14;
    uint256 constant SLOT_INDEXER_TRANSFERRED = 76;

    uint256 constant MIN = 100_000 ether;
    address constant BEN1 = address(0xB0B1);
    address constant BEN2 = address(0xB0B2);

    Controller controller;
    MockGRT grt;
    RecordingGateway gw;

    function setUp() public {
        controller = new Controller();
        controller.setPaused(false);
        grt = new MockGRT();
        gw = new RecordingGateway();
        controller.setContractProxy(keccak256("GraphToken"), address(grt));
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(gw));
    }

    // ---- storage helpers ----
    function _stakeBase(address indexer) internal pure returns (bytes32) {
        return keccak256(abi.encode(indexer, SLOT_STAKES_MAP));
    }
    function _indexerTransferredSlot(address indexer) internal pure returns (bytes32) {
        return keccak256(abi.encode(indexer, SLOT_INDEXER_TRANSFERRED));
    }
    function _setTokensStaked(RealL1Staking s, address indexer, uint256 v) internal {
        vm.store(address(s), _stakeBase(indexer), bytes32(v)); // Indexer.tokensStaked (offset 0)
    }
    function _tokensStaked(RealL1Staking s, address indexer) internal view returns (uint256) {
        return uint256(vm.load(address(s), _stakeBase(indexer)));
    }
    function _transferredTo(RealL1Staking s, address indexer) internal view returns (address) {
        return address(uint160(uint256(vm.load(address(s), _indexerTransferredSlot(indexer)))));
    }

    // Fresh real L1Staking + a fresh indexer actor with `initialStake`.
    function _fresh(uint256 initialStake) internal returns (RealL1Staking s, IndexerActor actor) {
        s = new RealL1Staking();
        vm.store(address(s), bytes32(SLOT_CONTROLLER), bytes32(uint256(address(controller))));
        vm.store(address(s), bytes32(SLOT_MIN_STAKE), bytes32(MIN));
        actor = new IndexerActor();
        actor.setStaking(s);
        _setTokensStaked(s, address(actor), initialStake);
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    // ===================================================================
    // FIRST-TRANSFER boundary
    // ===================================================================

    // First transfer below the minimum must revert, and must NOT persist the
    // indexerTransferredToL2 marker (whole tx reverts).
    function test_first_belowMinimum_reverts() public {
        (RealL1Staking s, IndexerActor actor) = _fresh(10 * MIN);
        (bool ok, string memory reason) = actor.transfer(BEN1, MIN - 1);
        require(!ok, "VIOLATION: first sub-minimum transfer accepted");
        require(_eq(reason, "!minimumIndexerStake sent"), "unexpected revert reason");
        require(_transferredTo(s, address(actor)) == address(0), "marker leaked on revert");
        require(gw.totalTokens() == 0, "nothing should be bridged");
    }

    // First transfer of exactly the minimum, moving the whole stake, succeeds:
    // L2 gets exactly MIN (INV-1), L1 left at 0 (INV-2 satisfied via ==0).
    function test_first_exactMinimum_fullExit_ok() public {
        (RealL1Staking s, IndexerActor actor) = _fresh(MIN);
        uint256 before = gw.totalTokens();
        (bool ok, ) = actor.transfer(BEN1, MIN);
        require(ok, "exact-minimum full exit should succeed");
        require(gw.totalTokens() - before == MIN, "INV-1: L2 must receive >= MIN");
        require(_tokensStaked(s, address(actor)) == 0, "L1 fully exited");
        require(_transferredTo(s, address(actor)) == BEN1, "marker must be set");
    }

    // First transfer that would leave 0 < remaining < MIN must revert.
    function test_first_leavesSubMinimumRemaining_reverts() public {
        // stake between MIN and 2*MIN so sending MIN leaves a sub-minimum tail.
        (RealL1Staking s, IndexerActor actor) = _fresh(MIN + (MIN / 2));
        (bool ok, string memory reason) = actor.transfer(BEN1, MIN);
        require(!ok, "VIOLATION: left L1 indexer below minimum");
        require(_eq(reason, "!minimumIndexerStake remaining"), "unexpected revert reason");
        require(gw.totalTokens() == 0, "nothing bridged on revert");
    }

    // First transfer >= MIN leaving remaining >= MIN succeeds.
    function test_first_validSplit_ok() public {
        (RealL1Staking s, IndexerActor actor) = _fresh(3 * MIN);
        uint256 before = gw.totalTokens();
        (bool ok, ) = actor.transfer(BEN1, MIN);
        require(ok, "valid split should succeed");
        require(gw.totalTokens() - before == MIN, "INV-1 holds on first transfer");
        require(_tokensStaked(s, address(actor)) == 2 * MIN, "INV-2: remaining >= MIN");
    }

    // ===================================================================
    // SUBSEQUENT-TRANSFER asymmetry (the crux of the hypothesis)
    // ===================================================================

    // After a valid first transfer, a SUBSEQUENT transfer may be arbitrarily
    // small (no `_amount >= MIN` guard) — as long as the remaining check holds.
    // This is safe: L2 was already funded with >= MIN by the first message.
    function test_subsequent_tinyAmount_ok_butL2AlreadyFunded() public {
        (RealL1Staking s, IndexerActor actor) = _fresh(3 * MIN);
        uint256 start = gw.totalTokens();

        (bool ok1, ) = actor.transfer(BEN1, MIN); // first: L2 created with MIN
        require(ok1, "first transfer failed");

        (bool ok2, ) = actor.transfer(BEN1, 1 wei); // subsequent: tiny top-up allowed
        require(ok2, "tiny subsequent transfer should be allowed");

        // INV-1 was established by the FIRST message (>= MIN); tiny top-ups only
        // ever ADD to an already-viable L2 indexer, never create a sub-min one.
        require(gw.totalTokens() - start == MIN + 1, "bridged first-MIN then +1");
        require(_tokensStaked(s, address(actor)) == 2 * MIN - 1, "INV-2: remaining still >= MIN");
    }

    // A subsequent transfer that would drop remaining into (0, MIN) still reverts:
    // the "remaining" guard applies to EVERY transfer, not just the first.
    function test_subsequent_leavesSubMinimum_reverts() public {
        (RealL1Staking s, IndexerActor actor) = _fresh(3 * MIN);
        (bool ok1, ) = actor.transfer(BEN1, MIN); // remaining 2*MIN
        require(ok1, "first transfer failed");

        // Sending MIN+1 now would leave MIN-1 (0 < rem < MIN) -> revert.
        (bool ok2, string memory reason) = actor.transfer(BEN1, MIN + 1);
        require(!ok2, "VIOLATION: subsequent transfer left sub-minimum stake");
        require(_eq(reason, "!minimumIndexerStake remaining"), "unexpected revert reason");
        require(_tokensStaked(s, address(actor)) == 2 * MIN, "state unchanged after revert");
    }

    // Subsequent transfers can walk the stake down to exactly 0 (full exit).
    function test_subsequent_downToZero_ok() public {
        (RealL1Staking s, IndexerActor actor) = _fresh(3 * MIN);
        bool a;
        (a, ) = actor.transfer(BEN1, MIN); require(a, "t1"); // remaining 2*MIN
        (a, ) = actor.transfer(BEN1, MIN); require(a, "t2"); // remaining MIN
        (a, ) = actor.transfer(BEN1, MIN); require(a, "t3"); // remaining 0 (allocated==0)
        require(_tokensStaked(s, address(actor)) == 0, "fully exited");
    }

    // ===================================================================
    // Other guards around the threshold
    // ===================================================================

    // Cannot redirect to a different L2 beneficiary on a later transfer.
    function test_subsequent_differentBeneficiary_reverts() public {
        (, IndexerActor actor) = _fresh(3 * MIN);
        (bool first, ) = actor.transfer(BEN1, MIN);
        require(first, "first");
        (bool ok, string memory reason) = actor.transfer(BEN2, MIN);
        require(!ok, "VIOLATION: beneficiary switch allowed");
        require(_eq(reason, "l2Beneficiary != previous"), "unexpected revert reason");
    }

    // Amount exceeding the whole stake reverts via SafeMath (cannot over-transfer),
    // so INV-2 can never be sidestepped by underflow.
    function test_amountExceedsStake_reverts() public {
        (, IndexerActor actor) = _fresh(2 * MIN);
        (bool ok, ) = actor.transfer(BEN1, 2 * MIN + 1);
        require(!ok, "VIOLATION: transferred more than staked");
        require(gw.totalTokens() == 0, "nothing bridged");
    }

    // An indexer stuck below a (raised) minimum cannot even start a transfer:
    // this is a lockout, not a fund loss — L2 is never under-funded.
    function test_stakeBelowMinimum_cannotStartTransfer() public {
        (, IndexerActor actor) = _fresh(MIN - 1); // whole stake < MIN
        // Any first _amount >= MIN underflows the sub; any _amount < MIN fails the
        // "sent" guard. Either way there is NO amount that succeeds.
        (bool okHigh, ) = actor.transfer(BEN1, MIN); // >= MIN but underflows sub
        (bool okLow, string memory rLow) = actor.transfer(BEN1, MIN - 1); // < MIN
        require(!okHigh && !okLow, "sub-minimum indexer must not transfer");
        require(_eq(rLow, "!minimumIndexerStake sent"), "low path reason");
        require(gw.totalTokens() == 0, "nothing bridged");
    }

}
