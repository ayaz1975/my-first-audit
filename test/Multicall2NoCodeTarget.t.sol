// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Multicall2} from "../src/Multicall2.sol";

contract Multicall2NoCodeTargetTest is Test {
    Multicall2 public multicall;

    function setUp() public {
        multicall = new Multicall2();
    }

    /// @notice С requireSuccess=true и target без кода низкоуровневый call
    ///         возвращает success=true и пустой returnData — вызов "успешен",
    ///         хотя никакой код не исполнялся.
    function test_TryAggregate_NoCodeTarget_ReportsSuccess() public {
        address noCodeTarget = address(0xdead);

        // Убеждаемся, что по адресу действительно нет кода.
        assertEq(noCodeTarget.code.length, 0, "target must have no code");

        Multicall2.Call[] memory calls = new Multicall2.Call[](1);
        calls[0] = Multicall2.Call({
            target: noCodeTarget,
            callData: abi.encodeWithSignature("doesNotExist()")
        });

        // requireSuccess=true: если бы call реально провалился, транзакция
        // бы откатилась на require внутри tryAggregate.
        Multicall2.Result[] memory results = multicall.tryAggregate(true, calls);

        assertEq(results.length, 1, "one result expected");
        assertTrue(results[0].success, "call to codeless address reported success");
        assertEq(results[0].returnData.length, 0, "returnData must be empty");
    }
}
