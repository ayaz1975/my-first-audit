// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.7.6;
pragma abicoder v2;

// ---------------------------------------------------------------------------
// Disproof PoC for HYPOTHESIS #12: reentrancy / CEI violation in L1Staking.
//
// We deploy the REAL, UNMODIFIED L1Staking contract (compiled from
// graphprotocol/contracts) and drive its real code path
//   transferStakeToL2 -> _transferStakeToL2 -> _sendTokensAndMessageToL2Staking
// The ONLY external call that yields control there is `gateway.outboundTransfer`.
// To stress the hypothesis maximally we register an ADVERSARIAL gateway that
// tries to reenter and move the same stake twice. The test asserts the double
// spend is impossible.
//
// forge-std (Solidity 0.8) is incompatible with L1Staking's ^0.7.6 pragma, so
// the Vm cheatcode interface is declared by hand. State that in production is
// set by the (proxy-only) initializer is injected via vm.store; this does NOT
// alter any L1Staking logic — the audited functions run exactly as written.
// ---------------------------------------------------------------------------

import { L1Staking } from "@gp/staking/L1Staking.sol";
import { Controller } from "@gp/governance/Controller.sol";

interface Vm {
    function store(address account, bytes32 slot, bytes32 value) external;
    function load(address account, bytes32 slot) external view returns (bytes32);
    function prank(address sender) external;
    function label(address account, string calldata newLabel) external;
    function deal(address account, uint256 newBalance) external;
}

/// Concrete, deployable instance of the real L1Staking (no logic added).
contract RealL1Staking is L1Staking {}

/// Minimal benign GRT: L1Staking only ever calls `approve` on the token.
contract MockGRT {
    mapping(address => mapping(address => uint256)) public allowance;
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }
}

/// Records bridge calls but does nothing adversarial (control case).
contract BenignGateway {
    uint256 public callCount;
    uint256 public totalTokens;
    function outboundTransfer(
        address,
        address,
        uint256 amount,
        uint256,
        uint256,
        bytes calldata
    ) external payable returns (bytes memory) {
        callCount += 1;
        totalTokens += amount;
        return "";
    }
}

/// Adversarial gateway: on every bridge call it invokes the indexer's hook,
/// giving the indexer a chance to reenter L1Staking and double-spend.
contract MaliciousGateway {
    uint256 public callCount;
    uint256 public totalTokens;
    ReentrantIndexer public hook;

    function setHook(ReentrantIndexer _hook) external {
        hook = _hook;
    }

    function outboundTransfer(
        address,
        address,
        uint256 amount,
        uint256,
        uint256,
        bytes calldata
    ) external payable returns (bytes memory) {
        callCount += 1;
        totalTokens += amount;
        if (address(hook) != address(0)) {
            hook.onBridgeCallback();
        }
        return "";
    }
}

/// A malicious indexer (contract) that owns stake and attempts, via the
/// gateway callback, to transfer the SAME stake a second time.
contract ReentrantIndexer {
    RealL1Staking public staking;
    address public l2Beneficiary;
    uint256 public amount;

    bool public reenterAttempted;
    bool public reenterReverted;
    bool public reenterSucceeded;
    string public reenterReason;

    function configure(RealL1Staking _staking, address _l2Beneficiary, uint256 _amount) external {
        staking = _staking;
        l2Beneficiary = _l2Beneficiary;
        amount = _amount;
    }

    /// Starts the legitimate transfer. All gas params are 0, so msg.value == 0.
    function attack() external {
        staking.transferStakeToL2(l2Beneficiary, amount, 0, 0, 0);
    }

    /// Invoked by the malicious gateway mid-transfer. Reentry keeps msg.sender
    /// == this indexer, so it targets this indexer's own stake.
    function onBridgeCallback() external {
        if (reenterAttempted) {
            return; // guard against infinite recursion if reentry ever succeeded
        }
        reenterAttempted = true;
        try staking.transferStakeToL2(l2Beneficiary, amount, 0, 0, 0) {
            reenterSucceeded = true;
        } catch Error(string memory reason) {
            reenterReverted = true;
            reenterReason = reason;
        } catch {
            reenterReverted = true;
            reenterReason = "<non-string revert>";
        }
    }
}

contract L1StakingReentrancyTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // Storage slots from `forge inspect ... storageLayout` for L1Staking:
    uint256 constant SLOT_CONTROLLER = 0;
    uint256 constant SLOT_MIN_STAKE = 12;
    uint256 constant SLOT_STAKES_MAP = 14; // mapping(address => Indexer)

    uint256 constant AMOUNT = 1_000_000 ether;
    uint256 constant MIN_STAKE = 100_000 ether;
    address constant L2BEN = address(0xB0B);

    Controller controller;
    MockGRT grt;

    function setUp() public {
        controller = new Controller(); // constructor pauses the protocol...
        controller.setPaused(false); // ...governor (this contract) unpauses it
        grt = new MockGRT();
        controller.setContractProxy(keccak256("GraphToken"), address(grt));
    }

    // Deploy a fresh real L1Staking and inject the minimal state its transfer
    // path reads. Returns the deployed instance.
    function _deployStaking() internal returns (RealL1Staking staking) {
        staking = new RealL1Staking();
        vm.store(address(staking), bytes32(SLOT_CONTROLLER), bytes32(uint256(address(controller))));
        vm.store(address(staking), bytes32(SLOT_MIN_STAKE), bytes32(MIN_STAKE));
    }

    function _setStake(address staking, address indexer, uint256 tokensStaked) internal {
        bytes32 base = keccak256(abi.encode(indexer, uint256(SLOT_STAKES_MAP)));
        vm.store(staking, base, bytes32(tokensStaked)); // Indexer.tokensStaked (offset 0)
        // tokensAllocated (base+1) and tokensLocked (base+2) remain 0.
    }

    function _readTokensStaked(address staking, address indexer) internal view returns (uint256) {
        bytes32 base = keccak256(abi.encode(indexer, uint256(SLOT_STAKES_MAP)));
        return uint256(vm.load(staking, base));
    }

    // -------------------------------------------------------------------
    // CONTROL: with an honest gateway the real transfer moves the stake
    // exactly once. Proves the harness genuinely exercises the code path.
    // -------------------------------------------------------------------
    function test_control_normalTransferMovesStakeOnce() public {
        RealL1Staking staking = _deployStaking();
        BenignGateway gw = new BenignGateway();
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(gw));

        address indexer = address(0xA11CE);
        _setStake(address(staking), indexer, AMOUNT);

        vm.prank(indexer);
        staking.transferStakeToL2(L2BEN, AMOUNT, 0, 0, 0);

        require(gw.callCount() == 1, "control: gateway should be called once");
        require(gw.totalTokens() == AMOUNT, "control: exactly the stake bridged");
        require(_readTokensStaked(address(staking), indexer) == 0, "control: stake fully moved");
    }

    // -------------------------------------------------------------------
    // ATTACK: an adversarial gateway reenters mid-transfer to move the same
    // stake twice. HYPOTHESIS #12 predicts a double spend. We assert it fails.
    // -------------------------------------------------------------------
    function test_attack_reentrantGatewayCannotDoubleSpend() public {
        RealL1Staking staking = _deployStaking();
        MaliciousGateway gw = new MaliciousGateway();
        controller.setContractProxy(keccak256("GraphTokenGateway"), address(gw));

        ReentrantIndexer indexer = new ReentrantIndexer();
        indexer.configure(staking, L2BEN, AMOUNT);
        gw.setHook(indexer);

        _setStake(address(staking), address(indexer), AMOUNT);

        // Launch the attack (starts a legitimate transfer that the gateway
        // tries to abuse via reentry).
        indexer.attack();

        // --- Invariant checks: the double spend must NOT have happened ---
        require(indexer.reenterAttempted(), "attack: reentry hook must have run");
        require(!indexer.reenterSucceeded(), "VULNERABLE: reentrant double-transfer succeeded");
        require(indexer.reenterReverted(), "attack: reentry must revert");
        // Reentry reverts for the RIGHT reason: the outer call already zeroed
        // tokensStaked before making the external gateway call (checks-effects-
        // interactions), so the top-of-function guard rejects the second entry.
        require(
            keccak256(bytes(indexer.reenterReason())) == keccak256("tokensStaked == 0"),
            "attack: reentry reverted for unexpected reason"
        );

        // The reentrant call reverts before reaching the bridge, so the
        // adversarial gateway is only ever asked to bridge the stake ONCE.
        require(gw.callCount() == 1, "VULNERABLE: stake bridged more than once");
        require(gw.totalTokens() == AMOUNT, "VULNERABLE: more than the stake bridged");

        // Stake was decremented exactly once (CEI: state updated before call).
        require(_readTokensStaked(address(staking), address(indexer)) == 0, "attack: stake moved once");
    }
}
