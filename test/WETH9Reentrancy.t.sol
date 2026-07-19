// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// WETH9.sol скомпилирован под pragma ^0.4.18, поэтому его нельзя импортировать
// напрямую в этот файл (pragma ^0.8). Вместо этого мы деплоим оригинальный
// контракт как есть через vm.deployCode(...) и общаемся с ним через интерфейс.
// Так src/WETH9.sol остаётся нетронутым.
interface IWETH9 {
    function deposit() external payable;
    function withdraw(uint256 wad) external;
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

// Контракт-атакующий. Кладёт свой депозит, затем вызывает withdraw и во время
// возврата ETH (в receive) пытается повторно войти в withdraw, чтобы вытащить
// больше, чем ему причитается.
contract ReentrantAttacker {
    IWETH9 public weth;
    uint256 public depositAmount;
    uint256 public reentryAttempts;
    bool public reentrySucceeded;

    constructor(IWETH9 _weth) {
        weth = _weth;
    }

    function fund() external payable {
        depositAmount = msg.value;
        weth.deposit{value: msg.value}();
    }

    function attack() external {
        // Запускаем легитимный вывод своего депозита. WETH9 внутри вызовет
        // msg.sender.transfer(wad), что передаст управление в receive() ниже.
        weth.withdraw(depositAmount);
    }

    // Сюда WETH9 присылает ETH во время withdraw. Пытаемся повторно снять те же
    // средства до того, как учёт «устаканится». Используем низкоуровневый call и
    // игнорируем результат, чтобы не сорвать внешний вывод искусственно —
    // хотим увидеть именно естественное поведение WETH9.
    receive() external payable {
        if (reentryAttempts == 0) {
            reentryAttempts++;
            (bool ok, ) = address(weth).call(
                abi.encodeWithSignature("withdraw(uint256)", depositAmount)
            );
            reentrySucceeded = ok;
        }
    }
}

contract WETH9ReentrancyTest is Test {
    IWETH9 internal weth;
    ReentrantAttacker internal attacker;

    address internal victim = makeAddr("victim");

    uint256 internal constant VICTIM_DEPOSIT = 10 ether;
    uint256 internal constant ATTACKER_DEPOSIT = 1 ether;

    function setUp() public {
        // Деплоим настоящий WETH9 (компилируется своим solc 0.4.x).
        weth = IWETH9(deployCode("WETH9.sol:WETH9"));

        // Честный пользователь кладёт 10 ETH — это «чужие» деньги в общем сейфе,
        // которые атакующий теоретически мог бы попытаться украсть.
        vm.deal(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        weth.deposit{value: VICTIM_DEPOSIT}();

        // Атакующий кладёт только 1 ETH.
        attacker = new ReentrantAttacker(weth);
        vm.deal(address(this), ATTACKER_DEPOSIT);
        attacker.fund{value: ATTACKER_DEPOSIT}();
    }

    function test_ReentrancyCannotStealMoreThanBalance() public {
        // Исходное состояние: в контракте лежит 11 ETH, у атакующего 1 WETH.
        assertEq(address(weth).balance, VICTIM_DEPOSIT + ATTACKER_DEPOSIT, "seed balance");
        assertEq(weth.balanceOf(address(attacker)), ATTACKER_DEPOSIT, "attacker WETH");
        assertEq(address(attacker).balance, 0, "attacker starts with 0 ETH");

        // Пытаемся атаковать. Атака может либо пройти (вернув ровно депозит),
        // либо целиком откатиться — оба исхода безопасны, поэтому не даём
        // возможному revert'у сорвать тест.
        try attacker.attack() {} catch {}

        // ГЛАВНАЯ ПРОВЕРКА: сколько бы попыток реэнтранси ни было, атакующий не
        // может получить нативного ETH больше, чем он изначально внёс (1 ETH).
        assertLe(
            address(attacker).balance,
            ATTACKER_DEPOSIT,
            "attacker drained more ETH than it deposited"
        );

        // Средства честного пользователя остались в сейфе нетронутыми.
        assertGe(
            address(weth).balance,
            VICTIM_DEPOSIT,
            "victim funds were stolen"
        );
        assertEq(weth.balanceOf(victim), VICTIM_DEPOSIT, "victim WETH balance changed");

        // Инвариант WETH: суммарный учёт не превышает реальный ETH на контракте.
        assertGe(
            address(weth).balance,
            weth.balanceOf(victim) + weth.balanceOf(address(attacker)),
            "accounting exceeds real ETH (double-spend)"
        );
    }
}
