// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.7.6;
pragma abicoder v2;

// ---------------------------------------------------------------------------
// HYPOTHESIS #6: L1Staking.transferLockedStakeToL2 -- the indexer-stake twin of
// transferLockedDelegationToL2.
//
//   address l2Beneficiary = l1GraphTokenLockTransferTool.l2WalletAddress(msg.sender);
//   require(l2Beneficiary != address(0), "LOCK NOT TRANSFERRED");
//   uint256 balance = address(this).balance;                       // snapshot
//   uint256 ethAmount = _maxSubmissionCost.add(_maxGas.mul(_gasPriceBid));
//   l1GraphTokenLockTransferTool.pullETH(msg.sender, ethAmount);   // EXTERNAL CALL
//   require(address(this).balance == balance.add(ethAmount), "ETH TRANSFER FAILED");
//   _transferStakeToL2(msg.sender, l2Beneficiary, _amount, ...);   // EFFECTS
//
// The ETH half is byte-identical to the delegation path. The STAKE half is
// fundamentally different and is what this suite targets:
//
//   * the delegation path is IDEMPOTENT   (delegation.shares zeroed, replay
//     blocked by `require(delegation.shares != 0)`);
//   * the stake path is DECREMENTAL and INTENTIONALLY RE-CALLABLE
//     (`tokensStaked = tokensStaked.sub(_amount)`), so "replay" is a feature.
//     Its safety therefore rests on completely different guarantees.
//
//   1. reentrancy through pullETH                  -> test_S1_*, test_S2_*
//   2. partial / repeated migration, double spend  -> test_S3_*, test_S4_*
//   3. tokensStaked/Allocated/Locked consistency   -> test_S5_*, test_S6_*
//   4. malicious tool or gateway                   -> test_S8_*, test_S9_*, test_S12_*
//   5. msg.sender identity vs cross-indexer attack -> test_S2_*, test_S11_*
//   6. forced ETH vs the balance-delta check       -> test_S7_*
//   7. direct comparison with the delegation path  -> test_S9_*, test_S10_*
// ---------------------------------------------------------------------------

import { L1Staking } from "@gp/staking/L1Staking.sol";
import { Controller } from "@gp/governance/Controller.sol";
import { IL2StakingTypes } from "@graphprotocol/interfaces/contracts/contracts/l2/staking/IL2StakingTypes.sol";

interface Vm {
    function store(address account, bytes32 slot, bytes32 value) external;
    function load(address account, bytes32 slot) external view returns (bytes32);
    function prank(address sender) external;
    function deal(address who, uint256 newBalance) external;
}

contract RealL1Staking is L1Staking {}

contract MockGRT {
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return true;
    }
}

contract RecordingGateway {
    uint256 public totalTokens;
    uint256 public totalValue;
    uint256 public calls;
    bytes public lastData;

    function outboundTransfer(
        address,
        address,
        uint256 amount,
        uint256,
        uint256,
        bytes calldata data
    ) external payable returns (bytes memory) {
        totalTokens += amount;
        totalValue += msg.value;
        calls += 1;
        lastData = data;
        return "";
    }

    // Decodes the L2 message the way L2Staking would.
    function lastStakeBeneficiary() external view returns (address) {
        (, bytes memory extraData) = abi.decode(lastData, (uint256, bytes));
        (, bytes memory inner) = abi.decode(extraData, (uint8, bytes));
        IL2StakingTypes.ReceiveIndexerStakeData memory d = abi.decode(
            inner,
            (IL2StakingTypes.ReceiveIndexerStakeData)
        );
        return d.indexer;
    }
}

/// Fully adversarial L1GraphTokenLockTransferTool.
contract HostileTransferTool {
    enum Mode {
        HONEST,
        SEND_NOTHING,
        SEND_LESS,
        SEND_MORE,
        REENTER
    }

    Mode public mode = Mode.HONEST;
    address public staking;
    address public l2WalletOverride;
    uint256 public depth;
    uint256 public reentryAmount;

    bool public reentryOk;
    bytes public reentryRet;

    uint256 public maxGas;
    uint256 public gasPriceBid;
    uint256 public maxSubmissionCost;

    mapping(address => address) public wallets;

    receive() external payable {}

    function setStaking(address _s) external {
        staking = _s;
    }
    function setMode(Mode _m) external {
        mode = _m;
    }
    function setWallet(address l1, address l2) external {
        wallets[l1] = l2;
    }
    function setL2WalletOverride(address _o) external {
        l2WalletOverride = _o;
    }
    function setReentry(uint256 _amount, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSub) external {
        reentryAmount = _amount;
        maxGas = _maxGas;
        gasPriceBid = _gasPriceBid;
        maxSubmissionCost = _maxSub;
    }

    function l2WalletAddress(address l1Wallet) external view returns (address) {
        if (l2WalletOverride != address(0)) return l2WalletOverride;
        return wallets[l1Wallet];
    }

    function pullETH(address, uint256 amount) external {
        if (mode == Mode.REENTER && depth == 0) {
            depth = 1;
            (bool ok, bytes memory ret) = staking.call(
                abi.encodeWithSignature(
                    "transferLockedStakeToL2(uint256,uint256,uint256,uint256)",
                    reentryAmount,
                    maxGas,
                    gasPriceBid,
                    maxSubmissionCost
                )
            );
            reentryOk = ok;
            reentryRet = ret;
            depth = 0;
        }

        uint256 toSend;
        if (mode == Mode.SEND_NOTHING) {
            return;
        } else if (mode == Mode.SEND_LESS) {
            toSend = amount - 1;
        } else if (mode == Mode.SEND_MORE) {
            toSend = amount + 1;
        } else {
            toSend = amount;
        }
        (bool s, ) = payable(msg.sender).call{ value: toSend }("");
        require(s, "tool: eth send failed");
    }
}

interface IStakeProbe {
    function stakeOf(address indexer) external view returns (uint256);
}

/// A gateway that reenters L1Staking while holding the tokens+ETH.
contract ReentrantGateway {
    address public staking;
    address public probe;
    address public watched;
    bool public armed;
    bool public reentryOk;
    bytes public reentryRet;
    uint256 public calls;
    uint256 public totalTokens;
    uint256 public totalValue;
    /// Victim's tokensStaked as observed FROM INSIDE the bridge call.
    uint256 public observedStakeDuringCall;

    function setStaking(address _s) external {
        staking = _s;
    }
    function setProbe(address _p, address _watched) external {
        probe = _p;
        watched = _watched;
    }
    function arm() external {
        armed = true;
    }

    function outboundTransfer(
        address,
        address,
        uint256 amount,
        uint256,
        uint256,
        bytes calldata
    ) external payable returns (bytes memory) {
        calls += 1;
        totalTokens += amount;
        totalValue += msg.value;
        if (armed) {
            armed = false;
            observedStakeDuringCall = IStakeProbe(probe).stakeOf(watched);
            (bool ok, bytes memory ret) = staking.call(
                abi.encodeWithSignature(
                    "transferLockedStakeToL2(uint256,uint256,uint256,uint256)",
                    uint256(1),
                    uint256(0),
                    uint256(0),
                    uint256(0)
                )
            );
            reentryOk = ok;
            reentryRet = ret;
        }
        return "";
    }
}

contract L1StakingLockedStakeTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    event Measured(string what, uint256 value);

    uint256 constant SLOT_CONTROLLER = 0;
    uint256 constant SLOT_MIN_INDEXER_STAKE = 12;
    uint256 constant SLOT_STAKES = 14;
    uint256 constant SLOT_DELEGATION_RATIO = 19; // uint32 at offset 0
    uint256 constant SLOT_DELEGATION_POOLS = 20;
    uint256 constant SLOT_INDEXER_TRANSFERRED = 76;
    uint256 constant SLOT_LOCK_TRANSFER_TOOL = 77;

    address constant LOCKED_INDEXER = address(0x1DECE); // an L1 token-lock wallet
    address constant L2_BEN = address(0x1D5E7);
    address constant THIEF_L2 = address(0x7471EF);
    address constant TOOL_L2 = address(0x700712);
    address constant OUTSIDER = address(0x0475D);

    uint256 constant MIN_STAKE = 100_000 ether;
    uint256 constant DELEGATION_RATIO = 16;
    uint256 constant INITIAL_STAKE = 1_000_000 ether;
    uint256 constant TOOL_STAKE = 400_000 ether;

    uint256 constant MAX_GAS = 1_000_000;
    uint256 constant GAS_PRICE = 1 gwei;
    uint256 constant MAX_SUB = 0.01 ether;
    uint256 constant ETH_AMOUNT = MAX_SUB + MAX_GAS * GAS_PRICE;

    Controller controller;
    MockGRT grt;
    RecordingGateway gw;
    RealL1Staking staking;
    HostileTransferTool tool;

    function setUp() public {
        controller = new Controller();
        controller.setPaused(false);
        grt = new MockGRT();
        gw = new RecordingGateway();
        controller.setContractProxy(keccak256("GraphToken"), address(grt));
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(gw));

        staking = new RealL1Staking();
        tool = new HostileTransferTool();
        tool.setStaking(address(staking));
        tool.setWallet(LOCKED_INDEXER, L2_BEN);
        tool.setWallet(address(tool), TOOL_L2);
        tool.setReentry(MIN_STAKE, MAX_GAS, GAS_PRICE, MAX_SUB);
        vm.deal(address(tool), 100 ether);

        vm.store(address(staking), bytes32(SLOT_CONTROLLER), bytes32(uint256(address(controller))));
        vm.store(address(staking), bytes32(SLOT_MIN_INDEXER_STAKE), bytes32(MIN_STAKE));
        vm.store(address(staking), bytes32(SLOT_DELEGATION_RATIO), bytes32(DELEGATION_RATIO));
        vm.store(address(staking), bytes32(SLOT_LOCK_TRANSFER_TOOL), bytes32(uint256(address(tool))));

        _setStake(LOCKED_INDEXER, INITIAL_STAKE, 0, 0);
    }

    // ---------------- storage helpers ----------------
    function _stakeBase(address indexer) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(indexer, SLOT_STAKES)));
    }
    function _tokensStaked(address i) internal view returns (uint256) {
        return uint256(vm.load(address(staking), bytes32(_stakeBase(i))));
    }
    function _tokensAllocated(address i) internal view returns (uint256) {
        return uint256(vm.load(address(staking), bytes32(_stakeBase(i) + 1)));
    }
    function _tokensLocked(address i) internal view returns (uint256) {
        return uint256(vm.load(address(staking), bytes32(_stakeBase(i) + 2)));
    }
    function _setStake(address i, uint256 staked, uint256 allocated, uint256 locked) internal {
        vm.store(address(staking), bytes32(_stakeBase(i)), bytes32(staked));
        vm.store(address(staking), bytes32(_stakeBase(i) + 1), bytes32(allocated));
        vm.store(address(staking), bytes32(_stakeBase(i) + 2), bytes32(locked));
    }
    function _setPoolTokens(address indexer, uint256 t) internal {
        vm.store(
            address(staking),
            bytes32(uint256(keccak256(abi.encode(indexer, SLOT_DELEGATION_POOLS))) + 2),
            bytes32(t)
        );
    }
    /// Lets a reentrant contract observe live stake state mid-call.
    function stakeOf(address indexer) external view returns (uint256) {
        return uint256(vm.load(address(staking), bytes32(_stakeBase(indexer))));
    }

    function _transferredTo(address indexer) internal view returns (address) {
        return
            address(
                uint160(
                    uint256(
                        vm.load(address(staking), keccak256(abi.encode(indexer, SLOT_INDEXER_TRANSFERRED)))
                    )
                )
            );
    }

    // ---------------- call helpers ----------------
    function _callLocked(address caller, uint256 amount) internal returns (bool ok, bytes memory ret) {
        vm.prank(caller);
        (ok, ret) = address(staking).call(
            abi.encodeWithSignature(
                "transferLockedStakeToL2(uint256,uint256,uint256,uint256)",
                amount,
                MAX_GAS,
                GAS_PRICE,
                MAX_SUB
            )
        );
    }

    function _reasonHash(bytes memory ret) internal pure returns (bytes32) {
        if (ret.length < 68) return bytes32(0);
        bytes memory sliced = new bytes(ret.length - 4);
        for (uint256 i = 4; i < ret.length; i++) {
            sliced[i - 4] = ret[i];
        }
        return keccak256(bytes(abi.decode(sliced, (string))));
    }
    function _requireRevert(bytes memory ret, string memory expected) internal pure {
        require(_reasonHash(ret) == keccak256(bytes(expected)), "wrong revert reason");
    }

    // ===================================================================
    // CONTROL: the honest flow works and every balance moves exactly once.
    // ===================================================================
    function test_S0_control_honestFlowWorks() public {
        uint256 toolEthBefore = address(tool).balance;
        uint256 amount = 300_000 ether;

        (bool ok, ) = _callLocked(LOCKED_INDEXER, amount);
        require(ok, "honest flow must succeed");

        require(gw.calls() == 1, "one bridge call");
        require(gw.totalTokens() == amount, "wrong token amount");
        require(gw.totalValue() == ETH_AMOUNT, "gateway must receive the pulled ETH");
        require(gw.lastStakeBeneficiary() == L2_BEN, "wrong L2 beneficiary");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE - amount, "stake not reduced exactly");
        require(_transferredTo(LOCKED_INDEXER) == L2_BEN, "beneficiary must be pinned");
        require(address(staking).balance == 0, "no ETH retained");
        require(address(tool).balance == toolEthBefore - ETH_AMOUNT, "tool paid exactly once");
    }

    // ===================================================================
    // Q1/Q5: reentrancy through pullETH when the tool has NO stake of its own.
    // The tool swallows the revert so the outer call completes and we can see
    // precisely what the reentrant attempt achieved.
    //
    // Note the structural point: transferLockedStakeToL2 takes NO indexer
    // parameter at all. The indexer IS msg.sender. There is literally no
    // argument through which to name a victim.
    // ===================================================================
    function test_S1_reentrancyCannotTouchVictimStake() public {
        tool.setMode(HostileTransferTool.Mode.REENTER);

        (bool ok, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok, "outer call should still succeed");

        require(!tool.reentryOk(), "reentrant call must fail");
        _requireRevert(tool.reentryRet(), "tokensStaked == 0");

        require(gw.calls() == 1, "only one bridge call");
        require(gw.totalTokens() == 300_000 ether, "double transfer");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE - 300_000 ether, "stake accounting");
        require(address(staking).balance == 0, "no ETH retained");
    }

    // ===================================================================
    // Q1/Q5: reentrancy where the tool DOES have its own stake. The inner call
    // succeeds -- and moves the TOOL's stake, never the victim's. This is the
    // executable proof that identity is bound to msg.sender.
    // ===================================================================
    function test_S2_reentrancyOnlyMovesTheReenterersOwnStake() public {
        _setStake(address(tool), TOOL_STAKE, 0, 0);
        tool.setMode(HostileTransferTool.Mode.REENTER);
        tool.setReentry(MIN_STAKE, MAX_GAS, GAS_PRICE, MAX_SUB);

        uint256 victimAmount = 300_000 ether;
        (bool ok, ) = _callLocked(LOCKED_INDEXER, victimAmount);
        require(ok, "outer call must succeed");
        require(tool.reentryOk(), "inner (tool's own) transfer should succeed");

        // Two independent migrations, each against its own stake.
        require(gw.calls() == 2, "two bridge calls");
        require(gw.totalTokens() == victimAmount + MIN_STAKE, "token accounting broken");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE - victimAmount, "victim over-debited");
        require(_tokensStaked(address(tool)) == TOOL_STAKE - MIN_STAKE, "tool stake accounting");

        // Each indexer got its OWN L2 beneficiary; no cross-contamination.
        require(_transferredTo(LOCKED_INDEXER) == L2_BEN, "victim beneficiary");
        require(_transferredTo(address(tool)) == TOOL_L2, "tool beneficiary");

        require(gw.totalValue() == 2 * ETH_AMOUNT, "ETH forwarded must match pulls");
        require(address(staking).balance == 0, "no ETH stuck");
    }

    // ===================================================================
    // Q2: repeated partial migration. Unlike the delegation path there is NO
    // idempotency guard -- re-calling is intended. Safety comes from
    // SafeMath.sub plus the minimum-stake invariant. Sum of all transfers can
    // never exceed the initial stake.
    // ===================================================================
    function test_S3_repeatedPartialMigrationsCannotOverdraw() public {
        uint256 remaining = INITIAL_STAKE;
        uint256 sent = 0;

        uint256[4] memory amounts = [uint256(300_000 ether), 250_000 ether, 200_000 ether, 250_000 ether];
        for (uint256 i = 0; i < 4; i++) {
            (bool ok, ) = _callLocked(LOCKED_INDEXER, amounts[i]);
            require(ok, "partial transfer must succeed");
            remaining -= amounts[i];
            sent += amounts[i];
            require(_tokensStaked(LOCKED_INDEXER) == remaining, "running stake accounting broken");
            require(gw.totalTokens() == sent, "running token accounting broken");
        }

        // Exact conservation: everything that left equals the initial stake.
        require(remaining == 0, "scenario should fully drain the stake");
        require(gw.totalTokens() == INITIAL_STAKE, "sum of transfers != initial stake");
        require(_tokensStaked(LOCKED_INDEXER) == 0, "stake must be zero");

        // One more wei is impossible.
        (bool ok2, bytes memory ret2) = _callLocked(LOCKED_INDEXER, 1);
        require(!ok2, "transfer from an empty stake must revert");
        _requireRevert(ret2, "tokensStaked == 0");

        emit Measured("total migrated", gw.totalTokens());
    }

    // ===================================================================
    // Q2: over-transfer in a single call is blocked by SafeMath, and a
    // remainder below the minimum is blocked by the invariant. Neither leaves
    // partial state behind.
    // ===================================================================
    function test_S4_overdrawAndSubMinimumRemainderRevert() public {
        (bool ok1, ) = _callLocked(LOCKED_INDEXER, INITIAL_STAKE + 1);
        require(!ok1, "SafeMath must block over-transfer");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE, "no state change");

        // Leaves 1 wei -- non-zero but below the minimum.
        (bool ok2, bytes memory ret2) = _callLocked(LOCKED_INDEXER, INITIAL_STAKE - 1);
        require(!ok2, "sub-minimum remainder must revert");
        _requireRevert(ret2, "!minimumIndexerStake remaining");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE, "no state change");
        require(gw.calls() == 0, "no bridge call");
    }

    // ===================================================================
    // Q3: tokensAllocated and tokensLocked are never touched by the transfer,
    // and tokensLocked != 0 blocks the whole path (the comment in the source
    // says the accounting would otherwise get complicated -- this proves the
    // guard is actually enforced on the locked-wallet path too).
    // ===================================================================
    function test_S5_indexerSubStateStaysConsistent() public {
        _setStake(LOCKED_INDEXER, INITIAL_STAKE, 200_000 ether, 0);

        (bool ok, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok, "transfer must succeed");
        require(_tokensAllocated(LOCKED_INDEXER) == 200_000 ether, "allocations must be untouched");
        require(_tokensLocked(LOCKED_INDEXER) == 0, "locked must stay zero");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE - 300_000 ether, "stake reduced exactly");

        // Now with tokens thawing for withdrawal: the path must close.
        _setStake(LOCKED_INDEXER, INITIAL_STAKE, 0, 50_000 ether);
        (bool ok2, bytes memory ret2) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(!ok2, "tokensLocked != 0 must block the transfer");
        _requireRevert(ret2, "tokensLocked != 0");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE, "no state change");
    }

    // ===================================================================
    // Q3: the allocation-capacity invariant is enforced on the locked path.
    // Stake 1,000,000 / allocated 500,000 / no delegation => at most 500,000
    // may leave, and a full exit with open allocations is refused outright.
    // ===================================================================
    function test_S6_allocationCapacityIsEnforced() public {
        _setStake(LOCKED_INDEXER, INITIAL_STAKE, 500_000 ether, 0);
        _setPoolTokens(LOCKED_INDEXER, 0);

        // 600,000 out would leave 400,000 staked to back 500,000 allocated.
        (bool ok1, bytes memory ret1) = _callLocked(LOCKED_INDEXER, 600_000 ether);
        require(!ok1, "over-allocation must revert");
        _requireRevert(ret1, "! allocation capacity");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE, "no state change");

        // Exactly at the boundary it is allowed.
        (bool ok2, ) = _callLocked(LOCKED_INDEXER, 500_000 ether);
        require(ok2, "boundary transfer must succeed");
        require(_tokensStaked(LOCKED_INDEXER) == 500_000 ether, "stake accounting");

        // A full exit while allocations are still open is refused.
        (bool ok3, bytes memory ret3) = _callLocked(LOCKED_INDEXER, 500_000 ether);
        require(!ok3, "full exit with open allocations must revert");
        _requireRevert(ret3, "allocated");
        require(_tokensStaked(LOCKED_INDEXER) == 500_000 ether, "no state change");
    }

    // ===================================================================
    // Q6: forced ETH. The check is a same-transaction DELTA, so a pre-existing
    // balance is neither spendable nor disruptive.
    // ===================================================================
    function test_S7_forcedEthDoesNotAffectTheDeltaCheck() public {
        uint256 forced = 50 ether; // e.g. arrived via selfdestruct
        vm.deal(address(staking), forced);

        // Cannot be spent in place of a real pull.
        tool.setMode(HostileTransferTool.Mode.SEND_NOTHING);
        (bool ok1, bytes memory ret1) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(!ok1, "must not spend the contract's own ETH");
        _requireRevert(ret1, "ETH TRANSFER FAILED");
        require(address(staking).balance == forced, "forced ETH untouched");

        // And does not disrupt the honest flow either.
        tool.setMode(HostileTransferTool.Mode.HONEST);
        (bool ok2, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok2, "honest flow must still work");
        require(address(staking).balance == forced, "pre-existing ETH must not move");
        require(gw.totalValue() == ETH_AMOUNT, "gateway got exactly the pulled ETH");
    }

    // ===================================================================
    // Q4: a lying tool cannot fake the ETH transfer, in either direction.
    // ===================================================================
    function test_S8_ethCheckIsStrictInBothDirections() public {
        tool.setMode(HostileTransferTool.Mode.SEND_NOTHING);
        (bool ok1, bytes memory ret1) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(!ok1, "no ETH must revert");
        _requireRevert(ret1, "ETH TRANSFER FAILED");

        tool.setMode(HostileTransferTool.Mode.SEND_LESS);
        (bool ok2, bytes memory ret2) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(!ok2, "under-payment must revert");
        _requireRevert(ret2, "ETH TRANSFER FAILED");

        tool.setMode(HostileTransferTool.Mode.SEND_MORE);
        (bool ok3, bytes memory ret3) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(!ok3, "over-payment must revert");
        _requireRevert(ret3, "ETH TRANSFER FAILED");

        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE, "no state change");
        require(address(staking).balance == 0, "no ETH retained");
    }

    // ===================================================================
    // Q4/Q7: THE KEY DIFFERENCE FROM THE DELEGATION PATH.
    //
    // _transferStakeToL2 PINS the L2 beneficiary on the first transfer:
    //     if (indexerTransferredToL2[_indexer] != address(0))
    //         require(indexerTransferredToL2[_indexer] == _l2Beneficiary, ...)
    //
    // So a tool that turns malicious LATER cannot redirect an indexer that has
    // already started migrating. _transferDelegationToL2 has no such pin -- it
    // trusts l2WalletAddress on every single call (proven in
    // L1StakingLockedDelegation.t.sol:test_R9).
    // ===================================================================
    function test_S9_beneficiaryIsPinnedAfterTheFirstTransfer() public {
        (bool ok1, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok1, "first transfer");
        require(_transferredTo(LOCKED_INDEXER) == L2_BEN, "beneficiary pinned");

        // The tool is compromised after the fact.
        tool.setL2WalletOverride(THIEF_L2);

        (bool ok2, bytes memory ret2) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(!ok2, "redirection must be impossible once pinned");
        _requireRevert(ret2, "l2Beneficiary != previous");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE - 300_000 ether, "no state change");
        require(gw.calls() == 1, "no extra bridge call");
    }

    // ===================================================================
    // Q4/Q7: the flip side -- if the tool is ALREADY malicious before the
    // indexer's first transfer, it can pin the thief's address, and every
    // later transfer is then forced to that same address. Same governance
    // trust assumption as the delegation path, but the window is narrower.
    // ===================================================================
    function test_S10_maliciousToolCanPinAThiefOnTheFirstTransfer() public {
        tool.setL2WalletOverride(THIEF_L2);

        (bool ok, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok, "L1Staking cannot tell the difference");
        require(gw.lastStakeBeneficiary() == THIEF_L2, "expected redirection on first transfer");
        require(_transferredTo(LOCKED_INDEXER) == THIEF_L2, "thief pinned");

        emit Measured("redirected stake", gw.totalTokens());
    }

    // ===================================================================
    // Q5: an outsider with no stake cannot migrate anyone. There is no indexer
    // parameter to abuse, so the attempt dies on `tokensStaked == 0` even when
    // the tool cooperates fully by handing out a valid L2 wallet.
    // ===================================================================
    function test_S11_outsiderCannotMigrateSomeoneElsesStake() public {
        tool.setWallet(OUTSIDER, address(0xBADBAD));

        (bool ok, bytes memory ret) = _callLocked(OUTSIDER, 300_000 ether);
        require(!ok, "outsider must not migrate anything");
        _requireRevert(ret, "tokensStaked == 0");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE, "victim untouched");
        require(gw.calls() == 0, "no bridge call");
    }

    // ===================================================================
    // Q4: a malicious GATEWAY reenters while holding both the tokens and the
    // ETH. CEI holds here -- tokensStaked is decremented BEFORE the bridge
    // call -- so the reentrant call sees the already-reduced stake and cannot
    // double-spend. It is still bound to its own msg.sender identity.
    // ===================================================================
    function test_S12_reentrantGatewayCannotDoubleSpend() public {
        ReentrantGateway rgw = new ReentrantGateway();
        rgw.setStaking(address(staking));
        // Let the gateway past "LOCK NOT TRANSFERRED" so its reentrant call
        // fails as LATE as possible -- otherwise the test would pass for a
        // trivial reason and prove nothing about stake accounting.
        tool.setWallet(address(rgw), address(0xBADBAD));
        rgw.setProbe(address(this), LOCKED_INDEXER);
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(rgw));
        // Clear the cached gateway address so Managed re-resolves it.
        vm.store(address(staking), keccak256(abi.encode(keccak256("GraphTokenGateway"), uint256(1))), bytes32(0));
        rgw.arm();

        (bool ok, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok, "outer call completes");

        // CEI PROOF: from inside the bridge call, the victim's stake is ALREADY
        // decremented. There is no window in which the old balance is visible.
        require(
            rgw.observedStakeDuringCall() == INITIAL_STAKE - 300_000 ether,
            "CEI VIOLATION: stale stake visible during the bridge call"
        );

        // The gateway's reentrant call was made and failed: it has no stake.
        require(!rgw.reentryOk(), "gateway reentry must fail");
        _requireRevert(rgw.reentryRet(), "tokensStaked == 0");
        require(rgw.calls() == 1, "exactly one bridge call");
        require(rgw.totalTokens() == 300_000 ether, "no duplicated tokens");
        require(_tokensStaked(LOCKED_INDEXER) == INITIAL_STAKE - 300_000 ether, "stake accounting");
    }

    // ===================================================================
    // FINDING (informational): there is no `_amount != 0` check. Once the
    // beneficiary is pinned, a zero-amount transfer is accepted: it changes no
    // stake, bridges no tokens, but still buys and pays for an L2 retryable
    // ticket. The ETH comes from the caller's own allocation in the transfer
    // tool, so this is self-griefing rather than an attack on others -- but it
    // is a real "burn ETH for nothing" path with no guard.
    // ===================================================================
    function test_S13_zeroAmountTransferBurnsEthForNothing() public {
        (bool ok1, ) = _callLocked(LOCKED_INDEXER, 300_000 ether);
        require(ok1, "first transfer pins the beneficiary");

        uint256 stakeBefore = _tokensStaked(LOCKED_INDEXER);
        uint256 toolEthBefore = address(tool).balance;
        uint256 valueBefore = gw.totalValue();

        (bool ok2, ) = _callLocked(LOCKED_INDEXER, 0);
        require(ok2, "zero-amount transfer is accepted");

        require(_tokensStaked(LOCKED_INDEXER) == stakeBefore, "stake unchanged, as expected");
        require(gw.calls() == 2, "a second, empty ticket was sent");
        require(gw.totalTokens() == 300_000 ether, "no extra tokens bridged");
        // ...but ETH was spent on it.
        require(gw.totalValue() == valueBefore + ETH_AMOUNT, "ETH was spent on an empty ticket");
        require(address(tool).balance == toolEthBefore - ETH_AMOUNT, "caller's ETH was consumed");

        emit Measured("ETH burned on empty ticket (wei)", ETH_AMOUNT);
    }
}
