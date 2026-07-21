// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.7.6;
pragma abicoder v2;

// ---------------------------------------------------------------------------
// HYPOTHESIS #5: L1Staking.transferLockedDelegationToL2 -- the path that calls
// out to the (externally-owned) L1GraphTokenLockTransferTool.
//
//   address l2Beneficiary = l1GraphTokenLockTransferTool.l2WalletAddress(msg.sender);
//   require(l2Beneficiary != address(0), "LOCK NOT TRANSFERRED");
//   uint256 balance = address(this).balance;                       // <- snapshot
//   uint256 ethAmount = _maxSubmissionCost.add(_maxGas.mul(_gasPriceBid));
//   l1GraphTokenLockTransferTool.pullETH(msg.sender, ethAmount);   // <- EXTERNAL CALL
//   require(address(this).balance == balance.add(ethAmount), "ETH TRANSFER FAILED");
//   _transferDelegationToL2(msg.sender, _indexer, l2Beneficiary, ...);  // <- EFFECTS
//
// The external `pullETH` happens BEFORE every state change: textbook CEI
// violation. We attack it with a fully adversarial transfer tool.
//
//   1. reentrancy through pullETH                    -> test_R1_*, test_R2_*, test_R8_*
//   2. manipulating the ETH balance check            -> test_R3_*, test_R4_*, test_R5_*
//   3. state changes before/after the external call  -> test_R1_*, test_R2_*
//   4. double migration / replay                     -> test_R6_*, test_R7_*
//   5. ETH / delegation stolen, locked, misaccounted -> test_R5_*, test_R9_*, test_R10_*
//
// The tool is deliberately hostile in every test. L1Staking itself is the real,
// unmodified contract.
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

// Records tokens, ETH value and the L2 message payload of every bridge call.
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

    // Decodes the L2 delegation message the way L2Staking would.
    function lastDelegationBeneficiary() external view returns (address) {
        (, bytes memory extraData) = abi.decode(lastData, (uint256, bytes));
        (, bytes memory inner) = abi.decode(extraData, (uint8, bytes));
        IL2StakingTypes.ReceiveDelegationData memory d = abi.decode(
            inner,
            (IL2StakingTypes.ReceiveDelegationData)
        );
        return d.delegator;
    }
}

/**
 * Fully adversarial L1GraphTokenLockTransferTool.
 *
 * NOTE: `l2WalletAddress` is intentionally declared NON-view here even though
 * the interface declares it `view`. Solidity emits STATICCALL based on the
 * INTERFACE, so this lets us prove the callee cannot mutate state or reenter
 * from that call site.
 */
contract HostileTransferTool {
    enum Mode {
        HONEST, // send exactly `amount`
        SEND_NOTHING, // send no ETH at all
        SEND_LESS, // send amount - 1
        SEND_MORE, // send amount + 1
        REENTER, // reenter transferLockedDelegationToL2 during pullETH
        REENTER_NO_PAY, // reenter, let the INNER call move ETH, pay nothing here
        REENTER_FROM_VIEW // try to reenter from l2WalletAddress (staticcall)
    }

    Mode public mode = Mode.HONEST;
    address public staking;
    address public reenterIndexer;
    address public l2WalletOverride;
    uint256 public depth;

    // Outcome of the reentrant attempt, so the outer call can still succeed.
    bool public reentryOk;
    bytes public reentryRet;

    uint256 public maxGas;
    uint256 public gasPriceBid;
    uint256 public maxSubmissionCost;

    mapping(address => address) public wallets;

    receive() external payable {}

    function setStaking(address _staking) external {
        staking = _staking;
    }
    function setMode(Mode _mode) external {
        mode = _mode;
    }
    function setWallet(address l1, address l2) external {
        wallets[l1] = l2;
    }
    function setL2WalletOverride(address _o) external {
        l2WalletOverride = _o;
    }
    function setReentry(address _indexer, uint256 _maxGas, uint256 _gasPriceBid, uint256 _maxSub) external {
        reenterIndexer = _indexer;
        maxGas = _maxGas;
        gasPriceBid = _gasPriceBid;
        maxSubmissionCost = _maxSub;
    }

    // Deliberately NOT `view` -- see contract docstring.
    function l2WalletAddress(address l1Wallet) external returns (address) {
        if (mode == Mode.REENTER_FROM_VIEW) {
            // Any state write inside a STATICCALL context reverts the call.
            depth = depth + 1;
            (bool ok, ) = staking.call(_reentryCalldata());
            reentryOk = ok;
        }
        if (l2WalletOverride != address(0)) return l2WalletOverride;
        return wallets[l1Wallet];
    }

    function pullETH(address, uint256 amount) external {
        if ((mode == Mode.REENTER || mode == Mode.REENTER_NO_PAY) && depth == 0) {
            depth = 1;
            (bool ok, bytes memory ret) = staking.call(_reentryCalldata());
            reentryOk = ok;
            reentryRet = ret;
            depth = 0;
            // The outer pull deliberately contributes nothing: we are testing
            // whether ETH that moved during the INNER call can satisfy the
            // OUTER delta check.
            if (mode == Mode.REENTER_NO_PAY) return;
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

    function _reentryCalldata() internal view returns (bytes memory) {
        return
            abi.encodeWithSignature(
                "transferLockedDelegationToL2(address,uint256,uint256,uint256)",
                reenterIndexer,
                maxGas,
                gasPriceBid,
                maxSubmissionCost
            );
    }
}

contract L1StakingLockedDelegationTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    event Measured(string what, uint256 value);

    // Slots from `forge inspect L1Staking storageLayout`.
    uint256 constant SLOT_CONTROLLER = 0;
    uint256 constant SLOT_DELEGATION_POOLS = 20;
    uint256 constant SLOT_INDEXER_TRANSFERRED = 76;
    uint256 constant SLOT_LOCK_TRANSFER_TOOL = 77;

    address constant INDEXER = address(0x1DECE);
    address constant L2_INDEXER = address(0x1D5E7);
    address constant VICTIM = address(0x71C71); // an L1 token-lock wallet
    address constant VICTIM_L2 = address(0x71C712);
    address constant THIEF_L2 = address(0x7471EF);

    uint256 constant MAX_GAS = 1_000_000;
    uint256 constant GAS_PRICE = 1 gwei;
    uint256 constant MAX_SUB = 0.01 ether;
    uint256 constant ETH_AMOUNT = MAX_SUB + MAX_GAS * GAS_PRICE;

    uint256 constant POOL_TOKENS = 1_000_000 ether;
    uint256 constant POOL_SHARES = 900_000 ether; // rate != 1:1
    uint256 constant VICTIM_SHARES = 90_000 ether;
    uint256 constant TOOL_SHARES = 45_000 ether;

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
        tool.setWallet(VICTIM, VICTIM_L2);
        tool.setReentry(INDEXER, MAX_GAS, GAS_PRICE, MAX_SUB);
        vm.deal(address(tool), 100 ether);

        vm.store(address(staking), bytes32(SLOT_CONTROLLER), bytes32(uint256(address(controller))));
        vm.store(address(staking), bytes32(SLOT_LOCK_TRANSFER_TOOL), bytes32(uint256(address(tool))));
        vm.store(address(staking), _indexerTransferredSlot(INDEXER), bytes32(uint256(L2_INDEXER)));

        _setPool(POOL_TOKENS, POOL_SHARES);
        _setDelegatorShares(VICTIM, VICTIM_SHARES);
    }

    // ---------------- storage helpers ----------------
    function _poolBase(address indexer) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(indexer, SLOT_DELEGATION_POOLS)));
    }
    function _poolTokensSlot(address indexer) internal pure returns (bytes32) {
        return bytes32(_poolBase(indexer) + 2);
    }
    function _poolSharesSlot(address indexer) internal pure returns (bytes32) {
        return bytes32(_poolBase(indexer) + 3);
    }
    function _delegationSharesSlot(address indexer, address d) internal pure returns (bytes32) {
        return keccak256(abi.encode(d, _poolBase(indexer) + 4));
    }
    function _indexerTransferredSlot(address indexer) internal pure returns (bytes32) {
        return keccak256(abi.encode(indexer, SLOT_INDEXER_TRANSFERRED));
    }
    function _setPool(uint256 t, uint256 s) internal {
        vm.store(address(staking), _poolTokensSlot(INDEXER), bytes32(t));
        vm.store(address(staking), _poolSharesSlot(INDEXER), bytes32(s));
    }
    function _setDelegatorShares(address d, uint256 s) internal {
        vm.store(address(staking), _delegationSharesSlot(INDEXER, d), bytes32(s));
    }
    function _poolTokens() internal view returns (uint256) {
        return uint256(vm.load(address(staking), _poolTokensSlot(INDEXER)));
    }
    function _poolShares() internal view returns (uint256) {
        return uint256(vm.load(address(staking), _poolSharesSlot(INDEXER)));
    }
    function _sharesOf(address d) internal view returns (uint256) {
        return uint256(vm.load(address(staking), _delegationSharesSlot(INDEXER, d)));
    }

    // ---------------- call helpers ----------------
    function _lockedCalldata(address indexer) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature(
                "transferLockedDelegationToL2(address,uint256,uint256,uint256)",
                indexer,
                MAX_GAS,
                GAS_PRICE,
                MAX_SUB
            );
    }

    function _callLocked(address caller) internal returns (bool ok, bytes memory ret) {
        vm.prank(caller);
        (ok, ret) = address(staking).call(_lockedCalldata(INDEXER));
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
    // CONTROL: the honest flow works, and ETH accounting is neutral.
    // Establishes that every "revert" test below is a real defence and not
    // just a broken setup.
    // ===================================================================
    function test_R0_control_honestFlowWorks() public {
        uint256 toolEthBefore = address(tool).balance;

        (bool ok, ) = _callLocked(VICTIM);
        require(ok, "honest flow must succeed");

        require(gw.calls() == 1, "exactly one bridge call");
        require(gw.totalValue() == ETH_AMOUNT, "gateway must receive the pulled ETH");
        require(gw.totalTokens() == (VICTIM_SHARES * POOL_TOKENS) / POOL_SHARES, "wrong payout");
        require(gw.lastDelegationBeneficiary() == VICTIM_L2, "wrong L2 beneficiary");
        require(_sharesOf(VICTIM) == 0, "victim shares must be zeroed");

        // ETH accounting: everything pulled was forwarded, nothing retained.
        require(address(staking).balance == 0, "staking must retain no ETH");
        require(address(tool).balance == toolEthBefore - ETH_AMOUNT, "tool must pay exactly once");
    }

    // ===================================================================
    // Q1/Q3: REENTRANCY through pullETH, tool has NO delegation of its own.
    // The tool swallows the revert so the outer call still completes, letting
    // us inspect exactly what the reentrant attempt achieved: nothing.
    //
    // Root cause of the safety: _transferDelegationToL2's `_delegator` is the
    // OUTER msg.sender. During reentrancy msg.sender is the TOOL, so the tool
    // can only ever move its OWN delegation -- never the victim's.
    // ===================================================================
    function test_R1_reentrancyCannotTouchVictimDelegation() public {
        tool.setMode(HostileTransferTool.Mode.REENTER);
        // Give the tool a valid L2 wallet so it clears "LOCK NOT TRANSFERRED"
        // and fails as late as possible.
        tool.setWallet(address(tool), address(0xDEAD));

        (bool ok, ) = _callLocked(VICTIM);
        require(ok, "outer call should still succeed");

        // The reentrant call failed, and failed for the RIGHT reason: the tool
        // has no delegation of its own.
        require(!tool.reentryOk(), "reentrant call must fail");
        _requireRevert(tool.reentryRet(), "delegation == 0");

        // Exactly one migration happened, of exactly the victim's shares.
        require(gw.calls() == 1, "only one bridge call");
        require(gw.totalTokens() == (VICTIM_SHARES * POOL_TOKENS) / POOL_SHARES, "double payout");
        require(gw.totalValue() == ETH_AMOUNT, "only one ETH forward");
        require(_sharesOf(VICTIM) == 0, "victim migrated once");
        require(_poolShares() == POOL_SHARES - VICTIM_SHARES, "share accounting broken");
        require(address(staking).balance == 0, "no ETH retained");
    }

    // ===================================================================
    // Q1/Q3: REENTRANCY where the tool DOES hold a delegation. The inner call
    // now succeeds -- and that is fine: it migrates the tool's own stake.
    // This is the strongest test of the nested ETH balance check, because two
    // snapshots and two `pullETH`s are in flight simultaneously.
    // ===================================================================
    function test_R2_nestedMigrationsComposeSafely() public {
        _setDelegatorShares(address(tool), TOOL_SHARES);
        tool.setMode(HostileTransferTool.Mode.REENTER);
        tool.setWallet(address(tool), address(0xDEAD));

        uint256 toolEthBefore = address(tool).balance;

        (bool ok, ) = _callLocked(VICTIM);
        require(ok, "outer call must succeed");
        require(tool.reentryOk(), "inner (tool's own) migration should succeed");

        // Inner ran first, against the untouched pool; outer ran second,
        // against the pool the inner left behind.
        uint256 innerPaid = (TOOL_SHARES * POOL_TOKENS) / POOL_SHARES;
        uint256 outerPaid = ((POOL_TOKENS - innerPaid) * VICTIM_SHARES) / (POOL_SHARES - TOOL_SHARES);

        require(gw.calls() == 2, "two bridge calls expected");
        require(gw.totalTokens() == innerPaid + outerPaid, "payout accounting broken");
        require(_sharesOf(VICTIM) == 0 && _sharesOf(address(tool)) == 0, "both migrated");
        require(_poolShares() == POOL_SHARES - VICTIM_SHARES - TOOL_SHARES, "shares broken");
        require(_poolTokens() == POOL_TOKENS - innerPaid - outerPaid, "tokens broken");

        // NOTHING was double-spent: the victim's payout is computed on the
        // already-reduced pool, so the two migrations cannot overlap.
        require(gw.totalTokens() <= POOL_TOKENS, "paid out more than the pool held");

        // ETH: two nested snapshots, two pulls, two forwards -- all exact.
        require(gw.totalValue() == 2 * ETH_AMOUNT, "ETH forwarded must match pulls");
        require(address(tool).balance == toolEthBefore - 2 * ETH_AMOUNT, "tool paid for both");
        require(address(staking).balance == 0, "no ETH stuck in staking");

        emit Measured("inner payout", innerPaid);
        emit Measured("outer payout", outerPaid);
    }

    // ===================================================================
    // Q2: the tool lies -- it reports success but sends no ETH.
    // ===================================================================
    function test_R3_toolCannotFakeTheEthTransfer() public {
        tool.setMode(HostileTransferTool.Mode.SEND_NOTHING);

        (bool ok, bytes memory ret) = _callLocked(VICTIM);
        require(!ok, "must revert when no ETH arrives");
        _requireRevert(ret, "ETH TRANSFER FAILED");

        require(_sharesOf(VICTIM) == VICTIM_SHARES, "no state may change");
        require(gw.calls() == 0, "no bridge call");
    }

    // ===================================================================
    // Q2: the check is a STRICT EQUALITY -- neither under- nor over-payment
    // is accepted. Over-payment mattering is the non-obvious half: it means a
    // faulty tool cannot silently leave surplus ETH in the contract, where it
    // would be permanently stuck (there is no ETH withdrawal function).
    // ===================================================================
    function test_R4_ethCheckIsStrictInBothDirections() public {
        tool.setMode(HostileTransferTool.Mode.SEND_LESS);
        (bool ok1, bytes memory ret1) = _callLocked(VICTIM);
        require(!ok1, "under-payment must revert");
        _requireRevert(ret1, "ETH TRANSFER FAILED");

        tool.setMode(HostileTransferTool.Mode.SEND_MORE);
        (bool ok2, bytes memory ret2) = _callLocked(VICTIM);
        require(!ok2, "over-payment must revert");
        _requireRevert(ret2, "ETH TRANSFER FAILED");

        require(_sharesOf(VICTIM) == VICTIM_SHARES, "no state may change");
        require(address(staking).balance == 0, "no ETH may be retained");
    }

    // ===================================================================
    // Q2/Q5: can a lock wallet make the contract pay for its L2 ticket out of
    // ETH the contract ALREADY holds (e.g. force-sent via selfdestruct)?
    // No: `balance` is snapshotted in the same transaction, so the check is a
    // DELTA, not an absolute. Pre-existing ETH is invisible to it.
    // ===================================================================
    function test_R5_preExistingEthCannotBeSiphoned() public {
        uint256 forced = 50 ether; // e.g. arrived via selfdestruct
        vm.deal(address(staking), forced);

        tool.setMode(HostileTransferTool.Mode.SEND_NOTHING);
        (bool ok, bytes memory ret) = _callLocked(VICTIM);
        require(!ok, "must not be able to spend the contract's own ETH");
        _requireRevert(ret, "ETH TRANSFER FAILED");
        require(address(staking).balance == forced, "forced ETH must be untouched");

        // And an honest transfer still leaves that pre-existing balance alone.
        tool.setMode(HostileTransferTool.Mode.HONEST);
        (bool ok2, ) = _callLocked(VICTIM);
        require(ok2, "honest flow must still work");
        require(address(staking).balance == forced, "pre-existing ETH must not move");
        require(gw.totalValue() == ETH_AMOUNT, "gateway got exactly the pulled ETH");
    }

    // ===================================================================
    // Q4: replay. A second migration of the same delegation is impossible,
    // and the failed attempt costs the tool nothing (the revert unwinds the
    // ETH pull too).
    // ===================================================================
    function test_R6_noReplayAndFailedRetryCostsNoEth() public {
        (bool ok, ) = _callLocked(VICTIM);
        require(ok, "first migration");

        uint256 toolEthAfterFirst = address(tool).balance;

        (bool ok2, bytes memory ret2) = _callLocked(VICTIM);
        require(!ok2, "replay must revert");
        _requireRevert(ret2, "delegation == 0");

        // The ETH pulled during the failed attempt was rolled back.
        require(address(tool).balance == toolEthAfterFirst, "failed replay must not cost ETH");
        require(gw.calls() == 1, "still exactly one bridge call");
        require(address(staking).balance == 0, "no ETH stuck");
    }

    // ===================================================================
    // Q4: the ETH pull happens BEFORE the `delegation.shares != 0` and
    // `tokensLocked == 0` checks. Prove that this ordering is harmless: a
    // wallet with no delegation at all still cannot drain the tool, because
    // the whole transaction reverts.
    // ===================================================================
    function test_R7_pullBeforeChecksIsRolledBack() public {
        address emptyWallet = address(0xE0E0);
        tool.setWallet(emptyWallet, address(0xE0E2));
        uint256 toolEthBefore = address(tool).balance;

        (bool ok, bytes memory ret) = _callLocked(emptyWallet);
        require(!ok, "must revert");
        _requireRevert(ret, "delegation == 0");
        require(address(tool).balance == toolEthBefore, "tool must not lose ETH");
        require(address(staking).balance == 0, "no ETH stuck");
    }

    // ===================================================================
    // Q1: the OTHER external call, `l2WalletAddress`, is declared `view` in
    // IL1GraphTokenLockTransferTool, so solc emits STATICCALL. Prove that call
    // site cannot be used to reenter at all.
    //
    // Control for this test is test_R0: the very same non-view mock function
    // succeeds there, so the failure below is caused by the STATE WRITE inside
    // a STATICCALL context, not by the mock's mutability declaration.
    // ===================================================================
    function test_R8_viewCallSiteCannotReenter() public {
        tool.setMode(HostileTransferTool.Mode.REENTER_FROM_VIEW);

        (bool ok, ) = _callLocked(VICTIM);
        // The tool's l2WalletAddress writes state -> forbidden inside a
        // STATICCALL -> the whole call reverts before anything happens.
        require(!ok, "staticcall context must reject a state-changing tool");
        require(_sharesOf(VICTIM) == VICTIM_SHARES, "no state may change");
        require(gw.calls() == 0, "no bridge call");
        require(address(staking).balance == 0, "no ETH moved");
    }

    // ===================================================================
    // Q5: the LIMIT of L1Staking's defences. A malicious/compromised transfer
    // tool CAN redirect a victim's delegation to an attacker-controlled L2
    // address, because L1Staking accepts `l2WalletAddress`'s answer verbatim.
    // This is a governance trust assumption (setL1GraphTokenLockTransferTool
    // is onlyGovernor), NOT something a third party can trigger -- but it is
    // the real blast radius if that key is compromised, so we prove it.
    // ===================================================================
    function test_R9_maliciousToolCanRedirectL2Beneficiary() public {
        tool.setL2WalletOverride(THIEF_L2);

        (bool ok, ) = _callLocked(VICTIM);
        require(ok, "call succeeds -- L1Staking cannot tell");

        require(gw.lastDelegationBeneficiary() == THIEF_L2, "expected redirection to be possible");
        require(_sharesOf(VICTIM) == 0, "victim's delegation is gone on L1");

        emit Measured("redirected tokens", gw.totalTokens());
    }

    // ===================================================================
    // Q5: ethAmount arithmetic is SafeMath -- a tool/caller cannot wrap it to
    // a small number and get a cheap ticket, or wrap it to pass the balance
    // check with less ETH.
    // ===================================================================
    function test_R10_ethAmountOverflowReverts() public {
        vm.prank(VICTIM);
        (bool ok, ) = address(staking).call(
            abi.encodeWithSignature(
                "transferLockedDelegationToL2(address,uint256,uint256,uint256)",
                INDEXER,
                uint256(2**255),
                uint256(2**255),
                uint256(1)
            )
        );
        require(!ok, "SafeMath must reject the overflow");
        require(_sharesOf(VICTIM) == VICTIM_SHARES, "no state may change");
    }

    // ===================================================================
    // Q2 (the subtle one): can ETH that moved during a NESTED call satisfy the
    // OUTER balance check? The outer snapshot is taken before pullETH, and the
    // inner call is ETH-neutral (it pulls E and forwards E), so the outer delta
    // is still zero and the check must fail. The tool holds a delegation, so
    // the inner migration genuinely succeeds -- this is not a vacuous revert.
    // ===================================================================
    function test_R12_nestedEthCannotSatisfyOuterCheck() public {
        _setDelegatorShares(address(tool), TOOL_SHARES);
        tool.setMode(HostileTransferTool.Mode.REENTER_NO_PAY);
        tool.setWallet(address(tool), address(0xDEAD));

        (bool ok, bytes memory ret) = _callLocked(VICTIM);
        require(!ok, "outer check must not be satisfiable by nested ETH");
        _requireRevert(ret, "ETH TRANSFER FAILED");

        // Everything unwound, including the inner migration that had succeeded.
        require(_sharesOf(VICTIM) == VICTIM_SHARES, "victim untouched");
        require(_sharesOf(address(tool)) == TOOL_SHARES, "inner migration rolled back");
        require(gw.calls() == 0, "no bridge call survives");
        require(address(staking).balance == 0, "no ETH stuck");
    }

    // ===================================================================
    // Q5: `receive()` is gated on the transfer tool, so nobody else can even
    // push ETH into the contract through the normal path.
    // ===================================================================
    function test_R11_receiveIsGatedToTheTransferTool() public {
        vm.deal(address(this), 1 ether);
        (bool ok, bytes memory ret) = address(staking).call{ value: 1 ether }("");
        require(!ok, "arbitrary ETH deposits must be rejected");
        _requireRevert(ret, "Only transfer tool can send ETH");
        require(address(staking).balance == 0, "no ETH accepted");
    }
}
